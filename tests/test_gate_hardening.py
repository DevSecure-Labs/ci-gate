"""CI gate hardening (security review 21 Oct 2026): the gate fails closed instead of passing on a bad
API reply, an unknown band, a broken scan file or a malformed allowlist; untrusted text can't inject
workflow commands; the API key never follows a redirect or goes over plain http."""

import datetime as dt
import http.server
import importlib.util
import io
import json
import threading
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location("ci_gate", Path(__file__).resolve().parents[1] / "gate.py")
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

TODAY = dt.date(2026, 10, 21)


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def replying(*bodies):
    """opener returning each body in turn (bytes, or a dict as JSON); an exception instance is raised."""
    queue = list(bodies)

    def opener(req, timeout=60):
        b = queue.pop(0)
        if isinstance(b, BaseException):
            raise b
        return FakeResp(b if isinstance(b, bytes) else json.dumps(b).encode())
    return opener


def item(cve, band, kev=False):
    return {"cve_id": cve, "priority_band": band, "rps_score": 50.0, "reason": "r", "evidence": {"kev": {"listed": kev}}}


def run(tmp_path, args, opener, key="k"):
    out = tmp_path / "out.txt"
    env = {"DEVSECURE_API_KEY": key, "GITHUB_OUTPUT": str(out)}
    rc = gate.main(args, env=env, opener=opener, sleep=lambda s: None, today=TODAY)
    return rc, out.read_text() if out.exists() else ""


# --- 1. the API reply must account for every CVE sent ---------------------------------------

@pytest.mark.parametrize("reply", [{"results": []}, {"status": "success"}, [], {"data": "x"}])
def test_unexpected_reply_shape_fails_closed(tmp_path, reply):
    rc, _ = run(tmp_path, ["--cves", "CVE-2021-44228"], replying(*[reply] * 5))
    assert rc == 2


def test_incomplete_reply_fails_closed(tmp_path):
    reply = {"ranked": [item("CVE-2021-44228", "low_priority")], "not_found": []}
    with pytest.raises(RuntimeError, match="1 of 2 CVEs missing"):
        gate.prioritize("https://x", "k", ["CVE-2021-44228", "CVE-2024-3400"], opener=replying(reply), sleep=lambda s: None)


def test_non_json_and_read_errors_are_retried_then_fail(tmp_path):
    ok = {"ranked": [item("CVE-2021-44228", "low_priority")], "not_found": []}
    ranked, _ = gate.prioritize("https://x", "k", ["CVE-2021-44228"], sleep=lambda s: None,
                                opener=replying(b"<html>cdn error</html>", TimeoutError("read timed out"),
                                                ConnectionResetError(), ok))
    assert len(ranked) == 1
    rc, _ = run(tmp_path, ["--cves", "CVE-2021-44228", "--on-api-error", "warn"], replying(*[b"not json"] * 5))
    assert rc == 0  # warn mode still honoured for transport errors
    rc, _ = run(tmp_path, ["--cves", "CVE-2021-44228"], replying(*[b"not json"] * 5))
    assert rc == 2


def test_auth_errors_fail_even_in_warn_mode(tmp_path):
    import urllib.error

    def opener(req, timeout=60):
        raise urllib.error.HTTPError(req.full_url, 401, "no", {}, io.BytesIO(b"{}"))
    rc, _ = run(tmp_path, ["--cves", "CVE-2021-44228", "--on-api-error", "warn"], opener)
    assert rc == 2


# --- 2. a CVE in CISA KEV with no band still blocks ------------------------------------------

@pytest.mark.parametrize("band", [None, "", "unknown"])
def test_kev_listed_cve_without_a_band_blocks(tmp_path, band):
    reply = {"ranked": [item("CVE-2021-44228", band, kev=True)], "not_found": []}
    rc, out = run(tmp_path, ["--cves", "CVE-2021-44228"], replying(reply))
    assert rc == 1 and "blocked=1" in out


def test_not_found_cves_are_still_counted_once_as_not_found(tmp_path):
    reply = {"ranked": [item("CVE-2099-99999", "unknown")], "not_found": ["CVE-2099-99999"]}
    rc, out = run(tmp_path, ["--cves", "CVE-2099-99999"], replying(reply))
    assert rc == 0 and "checked=0" in out


# --- 3. a missing, empty or unrecognised scan file fails --------------------------------------

@pytest.mark.parametrize("content", ["", "   \n", "{}", '{"error": "scanner crashed"}', "[]"])
def test_broken_scan_file_fails(tmp_path, content):
    scan = tmp_path / "scan.json"
    scan.write_text(content)
    rc, _ = run(tmp_path, ["--scan-file", str(scan)], replying())
    assert rc == 2


def test_missing_scan_file_fails(tmp_path):
    assert run(tmp_path, ["--scan-file", str(tmp_path / "nope.json")], replying())[0] == 2


@pytest.mark.parametrize("report", [{"SchemaVersion": 2, "ArtifactName": "app"}, {"Results": []}, {"matches": []},
                                    {"bomFormat": "CycloneDX", "components": []}, {"runs": [{"results": []}]}])
def test_clean_reports_pass_and_write_outputs(tmp_path, report):
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps(report))
    rc, out = run(tmp_path, ["--scan-file", str(scan)], replying())
    assert rc == 0 and "blocked=0" in out and "checked=0" in out


def test_text_without_cves_warns_but_passes(tmp_path, capsys):
    scan = tmp_path / "scan.txt"
    scan.write_text("Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)\n")
    rc, _ = run(tmp_path, ["--scan-file", str(scan)], replying())
    assert rc == 0 and "::warning" in capsys.readouterr().out


# --- 4. allowlist comments and expiry dates ---------------------------------------------------

def test_allowlist_ignores_commented_entries_and_expires_bad_dates():
    text = "\n".join([
        "# CVE-2021-44228 removed, do not accept",
        "CVE-2024-3400  # until 31/12/2099 wrong date format",
        "CVE-2023-4966  # until 2026-02-30 impossible date",
        "CVE-2022-26134 # expires 2020-01-01",
        "CVE-2019-11510 # expires: 2099-01-01 fine",
        "CVE-2020-1472  # until 2026-12-31 fine",
        "CVE-2018-13379 # no expiry",
    ])
    allowed, expired = gate.parse_allowlist(text, TODAY)
    assert allowed == {"CVE-2019-11510", "CVE-2020-1472", "CVE-2018-13379"}
    assert expired == {"CVE-2024-3400", "CVE-2023-4966", "CVE-2022-26134"}


# --- 5. untrusted text can't inject workflow commands ----------------------------------------

def test_package_names_cannot_start_a_workflow_command(tmp_path, capsys):
    scan = tmp_path / "trivy.json"
    scan.write_text(json.dumps({"Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-2021-44228", "PkgName": "x\n::error::spoofed|", "InstalledVersion": "1\r\n::add-mask::k"}]}]}))
    reply = {"ranked": [{**item("CVE-2021-44228", "critical_priority"), "reason": "a\n::warning::fake"}], "not_found": []}
    rc, _ = run(tmp_path, ["--scan-file", str(scan)], replying(reply))
    lines = capsys.readouterr().out.splitlines()
    assert rc == 1
    assert [ln for ln in lines if ln.startswith("::")] == [ln for ln in lines if ln.startswith("::error title=DevSecure%3A")]
    assert not any("spoofed" in ln and not ln.startswith("|") for ln in lines)


def test_command_escaping():
    assert gate._cmd("a%b\r\nc") == "a%25b%0D%0Ac"
    assert gate._prop("DevSecure: a,b") == "DevSecure%3A a%2Cb"
    assert gate._cell("a|b\nc\x1b") == "a\\|b c "


# --- 6. the key never follows a redirect or goes over plain http ------------------------------

def test_plain_http_api_is_refused_except_localhost(tmp_path):
    assert run(tmp_path, ["--cves", "CVE-2021-44228", "--api", "http://api.example.com"], replying())[0] == 2
    assert run(tmp_path, ["--cves", "CVE-2021-44228", "--api", "ftp://x"], replying())[0] == 2
    reply = {"ranked": [item("CVE-2021-44228", "low_priority")], "not_found": []}
    assert run(tmp_path, ["--cves", "CVE-2021-44228", "--api", "http://127.0.0.1:9"], replying(reply))[0] == 0


def test_redirects_are_not_followed_so_the_key_stays_put():
    seen = []

    class Quiet(http.server.BaseHTTPRequestHandler):
        def reply(self, code, headers=()):
            # Read the request body first: answering early makes Windows abort the connection.
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(code)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    class Elsewhere(Quiet):
        def do_GET(self):
            seen.append(self.headers.get("Authorization"))
            self.reply(200)

        do_POST = do_GET

    other = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Elsewhere)

    class Redirector(Quiet):
        def do_POST(self):
            self.reply(302, [("Location", f"http://127.0.0.1:{other.server_port}/steal")])

    api = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirector)
    for s in (other, api):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        with pytest.raises(RuntimeError, match="HTTP 302"):
            gate.prioritize(f"http://127.0.0.1:{api.server_port}", "secret-key", ["CVE-2021-44228"], retries=0,
                            sleep=lambda s: None)
    finally:
        api.shutdown()
        other.shutdown()
    assert seen == []
