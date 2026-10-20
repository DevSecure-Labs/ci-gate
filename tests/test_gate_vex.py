"""CI gate VEX handling: exact component scoping, conflicts, partial coverage and the audit trail."""

import datetime as dt
import importlib.util
import io
import json
from pathlib import Path

_spec = importlib.util.spec_from_file_location("ci_gate_vex", Path(__file__).resolve().parents[1] / "gate.py")
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
LOG4J_OTHER = "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0"
APP = "pkg:oci/app@sha256%3Aabc"


def trivy(*pkgs):
    """Trivy JSON with CVE-2021-44228 in each (name, purl)."""
    return json.dumps({"Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-2021-44228", "PkgName": n, "InstalledVersion": "x", "PkgIdentifier": {"PURL": p}}
        for n, p in pkgs]}]})


def openvex(*statements):
    return json.dumps({"@context": "https://openvex.dev/ns/v0.2.0", "author": "Example Sec", "timestamp": "2026-10-01T00:00:00Z",
                       "statements": list(statements)})


def st(status, sub=LOG4J, product=APP, **kw):
    s = {"vulnerability": {"name": "CVE-2021-44228"}, "status": status,
         "products": [{"@id": product, "subcomponents": [{"@id": sub}] if sub else []}]}
    if status == "not_affected" and "justification" not in kw and "impact_statement" not in kw:
        kw["justification"] = "vulnerable_code_not_in_execute_path"
    return {**s, **kw}


def decide(scan, *vex_docs, scope="component", product=None):
    comps = {}
    gate.parse_findings(scan, comps)
    stmts = [s for i, d in enumerate(vex_docs) for s in gate.parse_vex(d, document=f"vex{i}.json")]
    return gate.vex_decisions(comps, stmts, scope, product).get("CVE-2021-44228")


def test_purl_key_is_exact_and_normalised():
    assert gate.purl_key("pkg:npm/%40Angular/Core@1.2.3?arch=x#sub") == "pkg:npm/@angular/core@1.2.3"
    assert gate.purl_key("pkg:npm/@angular/core@1.2.3") == "pkg:npm/@angular/core@1.2.3"
    assert gate.purl_key("pkg:pypi/Django_REST.framework@3.0") == "pkg:pypi/django-rest-framework@3.0"
    assert gate.purl_key("PKG:Maven/Org.Apache/Log4j@2.0") == "pkg:maven/Org.Apache/Log4j@2.0"  # maven keeps case
    assert gate.purl_key("pkg:npm/@angular/core") is None  # no version: never matches
    assert gate.purl_key("log4j-core@2.14.1") is None


def test_exact_component_match_suppresses_with_audit():
    d = decide(trivy(("log4j-core", LOG4J)), openvex(st("not_affected")))
    assert d["suppressed"] is True
    assert "vulnerable_code_not_in_execute_path" in d["reason"] and "vex0.json statements[0]" in d["reason"]
    (e,) = d["entries"]
    assert e["component"] == LOG4J and e["decision"] == "suppressed"
    assert e["statement"]["author"] == "Example Sec" and e["statement"]["timestamp"] == "2026-10-01T00:00:00Z"


def test_other_version_or_versionless_purl_does_not_suppress():
    d = decide(trivy(("log4j-core", LOG4J)), openvex(st("not_affected", sub=LOG4J_OTHER)))
    assert d["suppressed"] is False and d["entries"][0]["reason"] == "no VEX statement for this exact component"
    d = decide(trivy(("log4j-core", LOG4J)), openvex(st("not_affected", sub="pkg:maven/org.apache.logging.log4j/log4j-core")))
    assert d["suppressed"] is False and "without an exact purl version" in d["entries"][0]["reason"]


def test_every_affected_component_must_be_covered():
    scan = trivy(("log4j-core", LOG4J), ("log4j-core", LOG4J_OTHER))
    d = decide(scan, openvex(st("not_affected")))
    assert d["suppressed"] is False
    assert {(e["component"], e["decision"]) for e in d["entries"]} == {(LOG4J, "suppressed"), (LOG4J_OTHER, "not_suppressed")}
    d = decide(scan, openvex(st("not_affected"), st("fixed", sub=LOG4J_OTHER)))
    assert d["suppressed"] is True and "2 components" in d["reason"]


def test_affected_or_investigating_statement_wins_across_documents():
    d = decide(trivy(("log4j-core", LOG4J)), openvex(st("not_affected")), openvex(st("under_investigation")))
    assert d["suppressed"] is False and d["reason"] == "VEX says under_investigation for this component"
    assert d["entries"][0]["statement"]["document"] == "vex1.json"


def test_not_affected_without_justification_is_ignored():
    bad = st("not_affected")
    del bad["justification"]
    d = decide(trivy(("log4j-core", LOG4J)), openvex(bad))
    assert d["suppressed"] is False
    assert any(e["decision"] == "ignored" and "justification or impact_statement" in e["reason"] for e in d["entries"])
    ok = st("not_affected", impact_statement="JNDI lookup disabled by configuration")
    assert "justification" not in ok
    assert decide(trivy(("log4j-core", LOG4J)), openvex(ok))["suppressed"] is True


def test_findings_without_purl_need_explicit_cve_scope():
    vex = openvex(st("not_affected"))
    d = decide("build log mentions CVE-2021-44228", vex)
    assert d["suppressed"] is False and "no exact package URL" in d["reason"]
    d = decide("build log mentions CVE-2021-44228", vex, scope="cve")
    assert d["suppressed"] is True and d["entries"][0]["reason"] == "unscoped (--vex-scope cve)"
    assert decide("CVE-2021-44228", vex, openvex(st("affected")), scope="cve")["suppressed"] is False


def test_product_filter():
    vex = openvex(st("not_affected", product="pkg:oci/other@sha256%3Adef"))
    assert decide(trivy(("log4j-core", LOG4J)), vex)["suppressed"] is True  # no product given: not filtered
    d = decide(trivy(("log4j-core", LOG4J)), vex, product=APP)
    assert d["suppressed"] is False and any("another product" in e["reason"] for e in d["entries"])
    assert decide(trivy(("log4j-core", LOG4J)), openvex(st("not_affected")), product=APP)["suppressed"] is True


def test_product_only_statement_is_the_component():
    """OpenVEX without subcomponents: the product itself is the package."""
    s = {"vulnerability": "CVE-2021-44228", "status": "fixed", "products": [LOG4J]}
    assert decide(trivy(("log4j-core", LOG4J)), openvex(s))["suppressed"] is True


def test_cyclonedx_vex_resolves_bom_refs():
    vex = json.dumps({"bomFormat": "CycloneDX", "metadata": {"authors": [{"name": "App Team"}]},
                      "components": [{"bom-ref": "log4j", "purl": LOG4J}],
                      "vulnerabilities": [{"id": "CVE-2021-44228", "affects": [{"ref": "urn:cdx:1234/1#log4j"}],
                                           "analysis": {"state": "not_affected", "justification": "code_not_reachable",
                                                        "lastUpdated": "2026-10-02"}}]})
    d = decide(trivy(("log4j-core", LOG4J)), vex)
    assert d["suppressed"] is True and d["entries"][0]["statement"]["author"] == "App Team"
    exploitable = vex.replace('"not_affected"', '"exploitable"')
    assert decide(trivy(("log4j-core", LOG4J)), vex, exploitable)["suppressed"] is False


def test_csaf_vex_resolves_relationships_and_flags():
    vex = json.dumps({
        "document": {"category": "csaf_vex", "publisher": {"name": "Vendor PSIRT"},
                     "tracking": {"current_release_date": "2026-10-03T00:00:00Z"}},
        "product_tree": {
            "branches": [{"branches": [{"product": {"product_id": "LOG4J", "name": "log4j",
                                                    "product_identification_helper": {"purl": LOG4J}}}]}],
            "full_product_names": [{"product_id": "APP", "name": "app", "product_identification_helper": {"purl": APP}}],
            "relationships": [{"category": "default_component_of", "product_reference": "LOG4J",
                               "relates_to_product_reference": "APP", "full_product_name": {"product_id": "APP:LOG4J"}}]},
        "vulnerabilities": [{"cve": "CVE-2021-44228", "product_status": {"known_not_affected": ["APP:LOG4J"]},
                             "flags": [{"label": "vulnerable_code_not_in_execute_path", "product_ids": ["APP:LOG4J"]}]}]})
    d = decide(trivy(("log4j-core", LOG4J)), vex, product=APP)
    assert d["suppressed"] is True
    e = d["entries"][0]["statement"]
    assert (e["author"], e["justification"]) == ("Vendor PSIRT", "vulnerable_code_not_in_execute_path")
    assert decide(trivy(("log4j-core", LOG4J)), vex, product="pkg:oci/other@sha256%3Adef")["suppressed"] is False


def test_grype_and_cyclonedx_scans_carry_purls():
    comps = {}
    grype = {"matches": [{"vulnerability": {"id": "CVE-2021-44228"}, "artifact": {"name": "log4j-core", "version": "2.14.1", "purl": LOG4J}}]}
    gate.parse_findings(json.dumps(grype), comps)
    assert list(comps["CVE-2021-44228"].values()) == [("log4j-core@2.14.1", LOG4J)]
    comps = {}
    cdx = {"components": [{"bom-ref": "c1", "purl": LOG4J}], "vulnerabilities": [{"id": "CVE-2021-44228", "affects": [{"ref": "c1"}]}]}
    gate.parse_findings(json.dumps(cdx), comps)
    assert list(comps["CVE-2021-44228"].values()) == [(LOG4J, LOG4J)]


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_main_writes_audit_and_explains_unapplied_vex(tmp_path):
    scan, vex, audit = tmp_path / "trivy.json", tmp_path / "app.openvex.json", tmp_path / "audit.json"
    scan.write_text(trivy(("log4j-core", LOG4J)))
    body = {"ranked": [{"cve_id": "CVE-2021-44228", "priority_band": "critical_priority", "rps_score": 105.0,
                        "reason": "r", "evidence": {"kev": {"listed": True}}}], "not_found": [], "status": "success"}

    def run(doc):
        vex.write_text(doc)
        out = tmp_path / "out.txt"
        out.write_text("")
        env = {"DEVSECURE_API_KEY": "k", "GITHUB_OUTPUT": str(out)}
        rc = gate.main(["--scan-file", str(scan), "--vex", str(vex), "--vex-audit", str(audit)], env=env,
                       opener=lambda req, timeout=60: FakeResp(json.dumps(body).encode()), sleep=lambda s: None,
                       today=dt.date(2026, 10, 20))
        return rc, json.loads(audit.read_text()), out.read_text()

    rc, a, out = run(openvex(st("not_affected")))
    assert rc == 0 and "allowlisted=1" in out and f"vex-audit={audit}" in out
    assert a["scope"] == "component" and a["documents"][0]["statements"] == 1 and len(a["documents"][0]["sha256"]) == 64
    assert a["decisions"][0]["decision"] == "suppressed" and a["decisions"][0]["component"] == LOG4J
    rc, a, out = run(openvex(st("not_affected", sub=LOG4J_OTHER)))
    assert rc == 1 and "blocked=1" in out and a["decisions"][0]["decision"] == "not_suppressed"
