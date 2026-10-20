"""DevSecure CI gate (gate.py): parsing, decision, batching, retries, outputs."""

import datetime as dt
import importlib.util
import io
import json
import urllib.error
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location("ci_gate", Path(__file__).resolve().parents[1] / "gate.py")
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


def item(cve, band, kev=False, score=50.0):
    return {"cve_id": cve, "priority_band": band, "rps_score": score, "reason": "r",
            "evidence": {"kev": {"listed": kev}}}


def test_parses_scanner_formats():
    trivy = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2021-44228", "PkgName": "log4j-core", "InstalledVersion": "2.14.1"},
                                             {"VulnerabilityID": "GHSA-xxxx-yyyy-zzzz", "PkgName": "x"}]}]}
    assert gate.parse_findings(json.dumps(trivy)) == {"CVE-2021-44228": {"log4j-core@2.14.1"}}
    grype = {"matches": [{"vulnerability": {"id": "GHSA-jfh8-c2jp-5v3q"}, "artifact": {"name": "log4j", "version": "2.14"},
                          "relatedVulnerabilities": [{"id": "CVE-2021-44228"}]}]}
    assert gate.parse_findings(json.dumps(grype)) == {"CVE-2021-44228": {"log4j@2.14"}}
    cdx = {"vulnerabilities": [{"id": "CVE-2024-3400"}, {"id": "GHSA-1"}]}
    assert set(gate.parse_findings(json.dumps(cdx))) == {"CVE-2024-3400"}
    sarif = {"runs": [{"results": [{"ruleId": "CVE-2023-4966", "message": {"text": "also cve-2022-26134"}}]}]}
    assert set(gate.parse_findings(json.dumps(sarif))) == {"CVE-2023-4966", "CVE-2022-26134"}
    assert set(gate.parse_findings("found CVE-2019-11510 and CVE-2019-11510\n")) == {"CVE-2019-11510"}


def test_allowlist_with_expiry():
    text = "CVE-2021-44228  # until 2026-12-31 vendor fix scheduled\nCVE-2024-3400 # until 2026-01-01 old\nCVE-2023-4966\nnot a cve"
    allowed, expired = gate.parse_allowlist(text, dt.date(2026, 10, 20))
    assert allowed == {"CVE-2021-44228", "CVE-2023-4966"} and expired == {"CVE-2024-3400"}


def test_decision_thresholds_kev_and_allowlist():
    ranked = [item("CVE-1-0001", "critical_priority"), item("CVE-1-0002", "high_priority"),
              item("CVE-1-0003", "medium_priority", kev=True), item("CVE-1-0004", "low_priority"),
              item("CVE-1-0005", "unknown")]
    blocked, allow, passed = gate.evaluate(ranked, {"CVE-1-0002"}, "high", True)
    assert [i["cve_id"] for i, _ in blocked] == ["CVE-1-0001", "CVE-1-0003"]
    assert [i["cve_id"] for i, _ in allow] == ["CVE-1-0002"]
    assert [i["cve_id"] for i in passed] == ["CVE-1-0004", "CVE-1-0005"]
    assert "CISA KEV" in blocked[1][1]
    blocked, _, _ = gate.evaluate(ranked, set(), "none", False)
    assert blocked == []
    blocked, _, _ = gate.evaluate(ranked, set(), "critical", False)
    assert [i["cve_id"] for i, _ in blocked] == ["CVE-1-0001"]


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def fake_api(responses, seen):
    """opener that pops responses: dict -> 200 body, int -> HTTPError with that code."""
    def opener(req, timeout=60):
        seen.append(json.loads(req.data.decode())["cve_ids"])
        r = responses.pop(0)
        if isinstance(r, int):
            hdrs = {"Retry-After": "0"} if r == 429 else {}
            raise urllib.error.HTTPError(req.full_url, r, "err", hdrs, io.BytesIO(b'{"error":{"message":"nope"}}'))
        # Production shape: ranked / not_found at the top level (as live /api/v1/prioritize returns).
        return FakeResp(json.dumps({**r, "status": "success"}).encode())
    return opener


def test_batches_and_retries_429():
    seen, sleeps = [], []
    cves = [f"CVE-2020-{i:05d}" for i in range(250)]
    responses = [{"ranked": [item(c, "low_priority") for c in cves[:100]], "not_found": []}, 429,
                 {"ranked": [], "not_found": cves[100:200]}, {"ranked": [], "not_found": cves[200:]}]
    ranked, missing = gate.prioritize("https://x", "k", cves, batch=100, opener=fake_api(responses, seen), sleep=sleeps.append)
    assert [len(b) for b in seen] == [100, 100, 100, 50] and len(ranked) == 100 and len(missing) == 150
    assert sleeps == [0.0]


def test_accepts_a_data_wrapper_too():
    def opener(req, timeout=60):
        return FakeResp(json.dumps({"data": {"ranked": [item("CVE-2021-44228", "high_priority")], "not_found": []}}).encode())
    ranked, _ = gate.prioritize("https://x", "k", ["CVE-2021-44228"], opener=opener, sleep=lambda s: None)
    assert len(ranked) == 1


def test_auth_error_is_reported():
    with pytest.raises(RuntimeError, match="HTTP 403"):
        gate.prioritize("https://x", "k", ["CVE-2021-44228"], opener=fake_api([403], []), sleep=lambda s: None)


def run_main(tmp_path, args, responses, key="k"):
    summary, output = tmp_path / "summary.md", tmp_path / "out.txt"
    env = {"DEVSECURE_API_KEY": key, "GITHUB_STEP_SUMMARY": str(summary), "GITHUB_OUTPUT": str(output)}
    rc = gate.main(args, env=env, opener=fake_api(responses, []), sleep=lambda s: None, today=dt.date(2026, 10, 20))
    return rc, summary.read_text(encoding="utf-8") if summary.exists() else "", output.read_text() if output.exists() else ""


def test_main_blocks_with_summary_and_outputs(tmp_path):
    scan = tmp_path / "trivy.json"
    scan.write_text(json.dumps({"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2021-44228", "PkgName": "log4j-core", "InstalledVersion": "2.14.1"}]}]}))
    rc, md, out = run_main(tmp_path, ["--scan-file", str(scan)], [{"ranked": [item("CVE-2021-44228", "critical_priority", kev=True, score=105)], "not_found": []}])
    assert rc == 1 and "**BLOCKED**" in md and "log4j-core@2.14.1" in md and "blocked=1" in out
    assert "https://intelligence.devsecure.io/cve/CVE-2021-44228" in md


def test_main_pass_api_error_and_inputs(tmp_path):
    rc, md, _ = run_main(tmp_path, ["--cves", "CVE-2020-0001 CVE-2099-99999"],
                         [{"ranked": [item("CVE-2020-0001", "low_priority"), item("CVE-2099-99999", "unknown", score=0)],
                           "not_found": ["CVE-2099-99999"]}])
    assert rc == 0 and "**PASSED**" in md and "1 below threshold, 1 not in DevSecure data" in md
    rc, _, _ = run_main(tmp_path, ["--cves", "CVE-2020-0001"], [500, 500, 500, 500, 500])
    assert rc == 2  # fail closed by default
    rc, _, _ = run_main(tmp_path, ["--cves", "CVE-2020-0001", "--on-api-error", "warn"], [500, 500, 500, 500, 500])
    assert rc == 0
    assert run_main(tmp_path, ["--cves", "CVE-2020-0001"], [], key="")[0] == 2
    assert run_main(tmp_path, ["--cves", "no ids here"], [])[0] == 0
