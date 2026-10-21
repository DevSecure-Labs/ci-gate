#!/usr/bin/env python3
"""DevSecure CI gate: fail a build when scanner findings meet your priority threshold.

Reads CVE IDs from scanner output (Trivy, Grype, SARIF, CycloneDX, or any text), ranks them with
POST /api/v1/prioritize, and fails when a CVE is at or above the chosen DevSecure Final Priority
(default high_priority) or is in CISA KEV. Writes a ranked, explained summary (GitHub job summary
when available) and inline annotations. Standard library only, so it runs on any CI runner.

Exit codes: 0 pass, 1 blocked, 2 usage or API error (fail closed unless --on-api-error=warn).

    python gate.py --scan-file trivy.json --fail-on high
    python gate.py --cves CVE-2021-44228,CVE-2024-3400 --fail-on critical --allowlist .devsecure-allow
"""

import argparse
import datetime as dt
import hashlib
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
BANDS = ["critical_priority", "high_priority", "medium_priority", "low_priority", "informational"]
LEVEL = {"critical": 0, "high": 1, "medium": 2, "low": 3}
LABEL = {"critical_priority": "Critical", "high_priority": "High", "medium_priority": "Medium",
         "low_priority": "Low", "informational": "Informational", "unknown": "Unknown"}
DEFAULT_API = "https://api.intelligence.devsecure.io"
USER_AGENT = "devsecure-ci-gate/1.1"
SCAN_KEYS = ("Results", "SchemaVersion", "ArtifactName", "matches", "bomFormat", "vulnerabilities", "runs")


def _cmd(s):
    """Data for a GitHub workflow command (::error::...): escaped so scan or VEX text can't start a new one."""
    return str(s).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _prop(s):
    """A workflow command property (title=...)."""
    return _cmd(s).replace(":", "%3A").replace(",", "%2C")


def _cell(s):
    """One markdown table cell on one line: no control characters (a new line could start a workflow
    command when the summary is printed) and no unescaped pipes."""
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(s)).replace("|", "\\|")


# --- reading findings -----------------------------------------------------------------------

_CASE_INSENSITIVE_PURL_TYPES = {"npm", "pypi", "github", "bitbucket", "composer", "deb", "apk", "nuget"}


def purl_key(purl):
    """Exact component identity from a package URL: 'pkg:type/namespace/name@version', with the type
    (and the name, for case-insensitive ecosystems) lower-cased and qualifiers/subpath dropped.
    None when it isn't a purl or has no version: VEX is only ever applied to an exact version."""
    if not isinstance(purl, str) or not purl.strip().lower().startswith("pkg:"):
        return None
    body = purl.strip()[4:].split("#", 1)[0].split("?", 1)[0].lstrip("/")
    typ, _, rest = body.partition("/")
    at = rest.rfind("@")
    if not typ or at <= 0 or rest[at - 1] == "/":
        return None
    path, version = urllib.parse.unquote(rest[:at]).strip("/"), urllib.parse.unquote(rest[at + 1:])
    typ = typ.lower()
    if typ in _CASE_INSENSITIVE_PURL_TYPES:
        path = path.lower()
    if typ == "pypi":
        path = re.sub(r"[-_.]+", "-", path)
    return f"pkg:{typ}/{path}@{version}" if path and version else None


def _cdx_components(doc):
    """{bom-ref: purl} for every (nested) CycloneDX component, including the metadata component."""
    out, stack = {}, list(doc.get("components") or [])
    meta = (doc.get("metadata") or {}).get("component")
    if isinstance(meta, dict):
        stack.append(meta)
    while stack:
        c = stack.pop()
        if isinstance(c, dict):
            if c.get("bom-ref"):
                out[c["bom-ref"]] = c.get("purl") or ""
            stack += c.get("components") or []
    return out


def _cdx_ref_purl(ref, comps):
    """The purl behind a CycloneDX affects[].ref: a purl, a bom-ref, or urn:cdx:...#bom-ref."""
    if not isinstance(ref, str):
        return None
    if ref.strip().lower().startswith("pkg:"):
        return ref
    local = ref.split("#", 1)[1] if ref.startswith("urn:cdx:") and "#" in ref else ref
    return comps.get(local) or None


def _add(found, cve, pkg=None, components=None, purl=None):
    cve = cve.upper()
    entry = found.setdefault(cve, set())
    if pkg:
        entry.add(pkg)
    if components is not None:
        components.setdefault(cve, {})[purl_key(purl) or f"unidentified:{pkg or '-'}"] = (pkg, purl_key(purl))


def parse_findings(text, components=None):
    """{CVE: {package labels}} from Trivy / Grype / SARIF / CycloneDX JSON, or any text.
    If `components` (a dict) is given it is filled with {CVE: {id: (label, exact purl or None)}},
    one entry per affected package, which is what VEX statements are matched against."""
    found = {}
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None
    if isinstance(doc, dict):
        for res in doc.get("Results") or []:  # Trivy
            for v in res.get("Vulnerabilities") or []:
                vid = v.get("VulnerabilityID") or ""
                if CVE_RE.fullmatch(vid):
                    _add(found, vid, f"{v.get('PkgName')}@{v.get('InstalledVersion')}" if v.get("PkgName") else None,
                         components, (v.get("PkgIdentifier") or {}).get("PURL"))
        for m in doc.get("matches") or []:  # Grype
            vuln, art = m.get("vulnerability") or {}, m.get("artifact") or {}
            pkg = f"{art.get('name')}@{art.get('version')}" if art.get("name") else None
            ids = [vuln.get("id") or ""] + [r.get("id") or "" for r in m.get("relatedVulnerabilities") or []]
            for vid in ids:
                if CVE_RE.fullmatch(vid):
                    _add(found, vid, pkg, components, art.get("purl"))
        bom = _cdx_components(doc)
        for v in doc.get("vulnerabilities") or []:  # CycloneDX
            vid = v.get("id") or ""
            if CVE_RE.fullmatch(vid):
                refs = [a.get("ref") for a in v.get("affects") or [] if isinstance(a, dict)]
                for ref in refs or [None]:
                    purl = _cdx_ref_purl(ref, bom)
                    _add(found, vid, purl, components, purl)
        for run in doc.get("runs") or []:  # SARIF
            for r in run.get("results") or []:
                for vid in CVE_RE.findall(json.dumps([r.get("ruleId"), (r.get("message") or {}).get("text")])):
                    _add(found, vid, None, components)
    if not found:  # unknown format: any CVE ID in the text
        for vid in CVE_RE.findall(text):
            _add(found, vid, None, components)
    return found


def scan_kind(text):
    """'report' for a scanner report we recognise (even with no findings), 'text' for other non-empty
    text, 'empty' for an empty file, 'unrecognised' for JSON that is no scanner report we know."""
    if not text.strip():
        return "empty"
    try:
        doc = json.loads(text)
    except ValueError:
        return "text"
    if isinstance(doc, dict) and any(k in doc for k in SCAN_KEYS):
        return "report"
    return "report" if CVE_RE.search(text) else "unrecognised"


def parse_allowlist(text, today):
    """Allowed CVEs (not expired) and expired entries. Lines: 'CVE-...  # until 2026-12-31 reason'.
    Only the part before '#' names a CVE, so a commented-out entry allowlists nothing. An entry whose
    comment sets an expiry ('until' or 'expires') without a valid YYYY-MM-DD date counts as expired:
    a typo in the date never allowlists a CVE for ever."""
    allowed, expired = set(), set()
    for line in text.splitlines():
        code, _, comment = line.partition("#")
        m = CVE_RE.search(code)
        if not m:
            continue
        cve = m.group(0).upper()
        when = re.search(r"\b(until|expires?)\b", comment, re.IGNORECASE)
        if not when:
            allowed.add(cve)
            continue
        date = re.match(r"\s*:?\s*(\d{4}-\d{2}-\d{2})\b", comment[when.end():])
        try:
            until = dt.date.fromisoformat(date.group(1)) if date else None
        except ValueError:
            until = None
        (expired if until is None or until < today else allowed).add(cve)
    return allowed, expired


# --- VEX ------------------------------------------------------------------------------------
# A VEX statement only suppresses a finding for the exact component (package URL with version) it
# names. A CVE is suppressed only when every affected component in the scan is covered, and any
# affected / under-investigation statement for a component wins over not-affected (fail safe).

VEX_SUPPRESS = {"not_affected", "fixed", "resolved", "resolved_with_pedigree", "false_positive",
                "known_not_affected", "first_fixed"}
VEX_CONFLICT = {"affected", "under_investigation", "exploitable", "in_triage", "known_affected",
                "first_affected", "last_affected"}


def _statement(cve, status, component_ids, product_ids, document, locator, justification=None,
               impact_statement=None, timestamp=None, author=None, invalid=None):
    ids = [i for i in component_ids if isinstance(i, str) and i]
    exact = {purl_key(i) for i in ids} - {None}
    return {
        "cve": cve.upper(), "status": status, "kind": "suppress" if status in VEX_SUPPRESS else "conflict",
        "components": exact, "unexact": sorted({i for i in ids if purl_key(i) is None}),
        "products": {purl_key(p) or p for p in product_ids if isinstance(p, str) and p},
        "justification": justification, "impact_statement": impact_statement, "timestamp": timestamp,
        "author": author, "document": document, "locator": locator, "invalid": invalid,
    }


def _ids(node):
    """@id and identifiers.purl of an OpenVEX product/subcomponent (or a bare string)."""
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [node.get("@id"), (node.get("identifiers") or {}).get("purl")]
    return []


def _openvex(doc, document):
    out = []
    for i, st in enumerate(doc.get("statements") or []):
        vuln = st.get("vulnerability")
        names = [vuln.get("name")] + list(vuln.get("aliases") or []) if isinstance(vuln, dict) else [vuln]
        status = (st.get("status") or "").lower()
        if status not in VEX_SUPPRESS | VEX_CONFLICT:
            continue
        products, subs = [], []
        for p in st.get("products") or []:
            products += _ids(p)
            for s in (p.get("subcomponents") if isinstance(p, dict) else None) or []:
                subs += _ids(s)
        for s in st.get("subcomponents") or []:  # OpenVEX 0.0.x put them on the statement
            subs += _ids(s)
        # With subcomponents, the product is the artefact and the subcomponents are the packages.
        components, product_ids = (subs, products) if subs else (products, [])
        invalid = None
        if status == "not_affected" and not (st.get("justification") or st.get("impact_statement")):
            invalid = "OpenVEX not_affected needs a justification or impact_statement"
        for cve in {n.upper() for n in names if isinstance(n, str) and CVE_RE.fullmatch(n)}:
            out.append(_statement(cve, status, components, product_ids, document, f"statements[{i}]",
                                  st.get("justification"), st.get("impact_statement"),
                                  st.get("timestamp") or doc.get("timestamp"), doc.get("author"), invalid))
    return out


def _cyclonedx(doc, document):
    out, bom = [], _cdx_components(doc)
    authors = ((doc.get("metadata") or {}).get("authors") or [{}])
    author = authors[0].get("name") if isinstance(authors[0], dict) else None
    for i, v in enumerate(doc.get("vulnerabilities") or []):
        vid, analysis = v.get("id") or "", v.get("analysis") or {}
        state = (analysis.get("state") or "").lower()
        if not (isinstance(vid, str) and CVE_RE.fullmatch(vid)) or state not in VEX_SUPPRESS | VEX_CONFLICT:
            continue
        refs = [a.get("ref") for a in v.get("affects") or [] if isinstance(a, dict)]
        components = [_cdx_ref_purl(r, bom) or r for r in refs]
        out.append(_statement(vid, state, components, [], document, f"vulnerabilities[{i}]",
                              analysis.get("justification"), analysis.get("detail"),
                              analysis.get("lastUpdated") or analysis.get("firstIssued"), author))
    return out


def _csaf(doc, document):
    tree, purls, rel = doc.get("product_tree") or {}, {}, {}

    def take(fpn):
        if isinstance(fpn, dict) and fpn.get("product_id"):
            helper = fpn.get("product_identification_helper") or {}
            purls[fpn["product_id"]] = [p for p in [helper.get("purl")] + list(helper.get("purls") or []) if p]

    stack = list(tree.get("branches") or [])
    while stack:
        b = stack.pop()
        take(b.get("product"))
        stack += b.get("branches") or []
    for f in tree.get("full_product_names") or []:
        take(f)
    for r in tree.get("relationships") or []:
        f = r.get("full_product_name") or {}
        if f.get("product_id"):
            rel[f["product_id"]] = (r.get("product_reference"), r.get("relates_to_product_reference"))
    meta = doc.get("document") or {}
    author = (meta.get("publisher") or {}).get("name")
    timestamp = (meta.get("tracking") or {}).get("current_release_date")
    out = []
    for i, v in enumerate(doc.get("vulnerabilities") or []):
        cve = v.get("cve") or ""
        if not (isinstance(cve, str) and CVE_RE.fullmatch(cve)):
            continue
        flags = {pid: f.get("label") for f in v.get("flags") or [] for pid in f.get("product_ids") or []}
        impacts = {pid: t.get("details") for t in v.get("threats") or [] if t.get("category") == "impact"
                   for pid in t.get("product_ids") or []}
        for status, pids in (v.get("product_status") or {}).items():
            if status not in VEX_SUPPRESS | VEX_CONFLICT:
                continue
            for pid in pids or []:
                component, product = rel.get(pid, (pid, None))
                out.append(_statement(cve, status, purls.get(component, []), purls.get(product, []), document,
                                      f"vulnerabilities[{i}].product_status.{status}[{pid}]",
                                      flags.get(pid), impacts.get(pid), timestamp, author))
    return out


def parse_vex(text, document="vex"):
    """VEX statements (OpenVEX, CycloneDX VEX or CSAF VEX) about CVEs, each scoped to exact components."""
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    if not isinstance(doc, dict):
        return []
    if "statements" in doc:
        return _openvex(doc, document)
    if "product_tree" in doc or "document" in doc:
        return _csaf(doc, document)
    return _cyclonedx(doc, document)


def _audit_entry(cve, component, decision, reason, st=None):
    ref = None
    if st:
        ref = {k: st[k] for k in ("document", "locator", "status", "justification", "impact_statement",
                                  "timestamp", "author")}
    return {"cve": cve, "component": component, "decision": decision, "reason": reason, "statement": ref}


def vex_decisions(components, statements, scope="component", product=None):
    """{CVE: {"suppressed", "reason", "entries"}} for each scanned CVE that a VEX statement mentions.

    scope "component" (default): suppressed only if every affected component of the CVE has an exact
    (purl + version) not-affected/fixed statement and none says affected or under investigation.
    scope "cve": the old unscoped behaviour, an explicit opt-in; still loses to any conflicting statement.
    product: if given, statements scoped to a different product (OpenVEX product / CSAF relationship) are ignored."""
    want = (purl_key(product) or product) if product else None
    by_cve = {}
    for st in statements:
        by_cve.setdefault(st["cve"], []).append(st)
    out = {}
    for cve, sts in by_cve.items():
        if cve not in components:
            continue
        entries, usable = [], []
        for st in sts:
            if st["invalid"]:
                entries.append(_audit_entry(cve, None, "ignored", st["invalid"], st))
            elif want and st["products"] and want not in st["products"]:
                entries.append(_audit_entry(cve, None, "ignored", f"statement is for another product, not {product}", st))
            else:
                usable.append(st)
        conflicts = [s for s in usable if s["kind"] == "conflict"]
        covering = [s for s in usable if s["kind"] == "suppress"]
        if scope == "cve":
            ok = bool(covering) and not conflicts
            st = covering[0] if ok else (conflicts[0] if conflicts else None)
            reason = ("unscoped (--vex-scope cve)" if ok else
                      f"VEX says {conflicts[0]['status']}" if conflicts else "no not-affected/fixed statement")
            entries.append(_audit_entry(cve, "*", "suppressed" if ok else "not_suppressed", reason, st))
        else:
            comps = components[cve].values()
            ok = bool(comps)
            for label, key in comps:
                name = key or label or "-"
                if key is None:
                    ok = False
                    entries.append(_audit_entry(cve, name, "not_suppressed",
                                                "the scan gives no exact package URL (purl with version) for this finding"))
                    continue
                against = [s for s in conflicts if key in s["components"]]
                cover = [s for s in covering if key in s["components"]]
                if against:
                    ok = False
                    entries.append(_audit_entry(cve, key, "not_suppressed",
                                                f"VEX says {against[0]['status']} for this component", against[0]))
                elif cover:
                    entries.append(_audit_entry(cve, key, "suppressed", "exact component match", cover[0]))
                else:
                    ok = False
                    loose = sorted({u for s in usable for u in s["unexact"]})
                    why = "no VEX statement for this exact component"
                    if loose:
                        why += f" (VEX names components without an exact purl version: {', '.join(loose[:3])})"
                    entries.append(_audit_entry(cve, key, "not_suppressed", why))
        if ok:
            first = next(e["statement"] for e in entries if e["decision"] == "suppressed")
            reason = f"VEX {first['status']}" + (f": {first['justification']}" if first.get("justification") else "")
            n = sum(1 for e in entries if e["decision"] == "suppressed")
            reason += f" ({n} component{'s' if n != 1 else ''}; {first['document']} {first['locator']})"
        else:
            reason = next((e["reason"] for e in entries if e["decision"] == "not_suppressed"), "no usable VEX statement")
        out[cve] = {"suppressed": ok, "reason": reason, "entries": entries}
    return out


# --- API ------------------------------------------------------------------------------------

class AuthError(RuntimeError):
    """401/403: the key is missing, revoked or not allowed. Always fails, even with --on-api-error=warn."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: urllib would resend the Authorization header to the new host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _reply_data(reply, sent):
    """ranked / not_found from a /prioritize reply, checked: every CVE sent must come back in one of them."""
    if not isinstance(reply, dict):
        raise RuntimeError("unexpected response from /api/v1/prioritize (not a JSON object)")
    # /prioritize returns ranked / not_found at the top level (a "data" wrapper is accepted too).
    data = reply if "ranked" in reply or "not_found" in reply else reply.get("data")
    if not isinstance(data, dict) or not ("ranked" in data or "not_found" in data):
        raise RuntimeError("unexpected response from /api/v1/prioritize (no ranked or not_found)")
    ranked, missing = data.get("ranked") or [], data.get("not_found") or []
    got = {str(x.get("cve_id", "")).upper() for x in ranked if isinstance(x, dict)} | {str(x).upper() for x in missing}
    absent = [c for c in sent if c.upper() not in got]
    if absent:
        raise RuntimeError(f"incomplete response from /api/v1/prioritize: {len(absent)} of {len(sent)} CVEs "
                           f"missing (first: {absent[0]})")
    return [x for x in ranked if isinstance(x, dict)], missing


def prioritize(api, key, cves, batch=100, retries=4, opener=_OPENER.open, sleep=time.sleep):
    """All ranked items and not-found IDs, in batches; retries 429 (Retry-After), 5xx and network errors.
    Fails (RuntimeError) on anything else, including a reply that doesn't account for every CVE sent."""
    ranked, missing = [], []
    for i in range(0, len(cves), batch):
        sent = cves[i:i + batch]
        payload = json.dumps({"cve_ids": sent}).encode()
        for attempt in range(retries + 1):
            req = urllib.request.Request(f"{api.rstrip('/')}/api/v1/prioritize", data=payload, method="POST", headers={
                "Authorization": f"Bearer {key}", "Content-Type": "application/json", "User-Agent": USER_AGENT})
            try:
                with opener(req, timeout=60) as r:
                    reply = json.loads(r.read().decode())
            except urllib.error.HTTPError as e:
                if (e.code == 429 or e.code >= 500) and attempt < retries:
                    wait = e.headers.get("Retry-After") if e.headers else None
                    sleep(min(float(wait), 60.0) if wait and wait.replace(".", "", 1).isdigit() else 2 ** attempt)
                    continue
                detail = ""
                try:
                    detail = (json.loads(e.read().decode()).get("error") or {}).get("message") or ""
                except Exception:  # noqa: BLE001 - best-effort error detail
                    pass
                err = AuthError if e.code in (401, 403) else RuntimeError
                if 300 <= e.code < 400:
                    detail = (detail + " (redirects are not followed, so the API key is never sent elsewhere)").strip()
                raise err(f"HTTP {e.code} from /api/v1/prioritize {detail}".strip()) from e
            except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as e:
                # URLError, timeouts and resets while reading, a truncated or non-JSON body.
                if attempt < retries:
                    sleep(2 ** attempt)
                    continue
                raise RuntimeError(f"cannot get a response from {api}: {getattr(e, 'reason', None) or e}") from e
            got_ranked, got_missing = _reply_data(reply, sent)
            ranked += got_ranked
            missing += got_missing
            break
    return ranked, missing


# --- decision -------------------------------------------------------------------------------

def blocks(item, fail_on, fail_on_kev):
    """Why this ranked item blocks the build, or None."""
    band = item.get("priority_band") or "unknown"
    kev = bool(((item.get("evidence") or {}).get("kev") or {}).get("listed"))
    if fail_on_kev and kev:
        return "in CISA KEV (known exploited)"
    if fail_on != "none" and band in BANDS and BANDS.index(band) <= LEVEL[fail_on]:
        return f"Final Priority {LABEL[band]} (threshold: {fail_on})"
    return None


def evaluate(ranked, allowed, fail_on, fail_on_kev, vex=None):
    """(blocked, allowlisted, passed). vex is vex_decisions() output: CVEs it suppresses are listed with
    the allowlisted ones (VEX status and what would have blocked them); a blocking CVE that VEX
    mentions but doesn't cover says why."""
    vex = vex or {}
    blocked, allowlisted, passed = [], [], []
    for item in ranked:
        why = blocks(item, fail_on, fail_on_kev)
        cve = item.get("cve_id", "").upper()
        decision = vex.get(cve)
        if why and decision and decision["suppressed"]:
            allowlisted.append((item, f"{decision['reason']} (would block: {why})"))
        elif why and cve in allowed:
            allowlisted.append((item, why))
        elif why:
            blocked.append((item, f"{why}; VEX not applied: {decision['reason']}" if decision else why))
        else:
            passed.append(item)
    return blocked, allowlisted, passed


def summary_markdown(blocked, allowlisted, passed, missing, expired, findings, fail_on, fail_on_kev):
    def row(item, why=""):
        # Package labels, VEX justifications and API text are untrusted: one line each, pipes escaped.
        cve = _cell(item.get("cve_id", ""))
        pk = _cell(", ".join(sorted(findings.get(cve.upper(), set()))[:3]) or "-")
        kev = "yes" if ((item.get("evidence") or {}).get("kev") or {}).get("listed") else "no"
        score = item.get("rps_score")
        score = round(score, 1) if isinstance(score, (int, float)) else ""
        band = LABEL.get(item.get("priority_band") or "unknown", "Unknown")
        return (f"| [{cve}](https://intelligence.devsecure.io/cve/{cve}) | {band} | "
                f"{score} | {kev} | {pk} | {_cell(why or (item.get('reason') or '')[:90])} |")

    head = "| CVE | Final Priority | RPS | CISA KEV | Package | Why |\n|---|---|---|---|---|---|"
    out = ["## DevSecure CI gate", "",
           f"**{'BLOCKED' if blocked else 'PASSED'}**: {len(blocked)} blocking, {len(allowlisted)} allowlisted, "
           f"{len(passed)} below threshold, {len(missing)} not in DevSecure data. "
           f"Threshold: Final Priority {fail_on}{' or CISA KEV' if fail_on_kev else ''}.", ""]
    if blocked:
        out += ["### Blocking", head] + [row(i, w) for i, w in blocked] + [""]
    if allowlisted:
        out += ["### Allowlisted or not affected (VEX)", head] + [row(i, w) for i, w in allowlisted] + [""]
    if expired:
        out += [f"Expired allowlist entries (now enforced): {', '.join(sorted(expired))}", ""]
    if passed:
        out += ["<details><summary>Below threshold</summary>", "", head] + [row(i) for i in passed[:200]] + ["", "</details>", ""]
    if missing:
        out += [f"Not in DevSecure data: {_cell(', '.join(sorted(str(m) for m in missing)[:50]))}", ""]
    out.append("Final Priority is DevSecure's RPS band after the CISA KEV floor and EPSS gate. "
               "[How priority works](https://intelligence.devsecure.io/methodology#rps)")
    return "\n".join(out)


def _api_ok(api):
    """The key goes with every request: https only (plain http just for a local test server)."""
    u = urllib.parse.urlsplit(api)
    return u.scheme == "https" and bool(u.hostname) or (u.scheme == "http" and u.hostname in ("localhost", "127.0.0.1", "::1"))


def _write_outputs(env, blocked, checked, allowlisted, vex_audit=None):
    if env.get("GITHUB_OUTPUT"):
        with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write(f"blocked={blocked}\nchecked={checked}\nallowlisted={allowlisted}\n")
            if vex_audit:
                f.write(f"vex-audit={vex_audit}\n")


def main(argv=None, env=None, opener=_OPENER.open, sleep=time.sleep, today=None):
    env = os.environ if env is None else env
    ap = argparse.ArgumentParser(description="DevSecure CI gate")
    ap.add_argument("--cves", default="", help="comma/space separated CVE IDs")
    ap.add_argument("--scan-file", action="append", default=[], help="scanner output (Trivy, Grype, SARIF, CycloneDX, text)")
    ap.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low", "none"])
    ap.add_argument("--fail-on-kev", default="true", choices=["true", "false"])
    ap.add_argument("--allowlist", default="")
    ap.add_argument("--vex", action="append", default=[], help="VEX document (OpenVEX, CycloneDX VEX, CSAF VEX); repeatable")
    ap.add_argument("--vex-scope", default="component", choices=["component", "cve"],
                    help="component (default): exact purl+version match per affected package; cve: unscoped opt-in")
    ap.add_argument("--vex-product", default="", help="only use VEX statements for this product (purl), e.g. your image")
    ap.add_argument("--vex-audit", default="devsecure-vex-audit.json", help="where to write the VEX audit (JSON)")
    ap.add_argument("--api", default=env.get("DEVSECURE_API_BASE", DEFAULT_API))
    ap.add_argument("--batch", type=int, default=100)
    ap.add_argument("--on-api-error", default="fail", choices=["fail", "warn"])
    a = ap.parse_args(argv)
    key = env.get("DEVSECURE_API_KEY", "")
    if not key:
        print("::error::DEVSECURE_API_KEY is not set (create a key at https://intelligence.devsecure.io/dashboard)")
        return 2
    if not _api_ok(a.api):
        print(f"::error::The API base must be an https:// URL, got {_cmd(a.api)} (the API key is sent with every request)")
        return 2

    findings, components = {}, {}
    for vid in CVE_RE.findall(a.cves):
        _add(findings, vid, None, components)
    for path in a.scan_file:
        # A missing, empty or unreadable report usually means the scanner failed: fail, don't pass.
        if not os.path.isfile(path):
            print(f"::error title=DevSecure CI gate::scan file {_cmd(path)} not found (did the scanner run?)")
            return 2
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
        kind = scan_kind(text)
        if kind in ("empty", "unrecognised"):
            what = "is empty" if kind == "empty" else "is JSON but not a Trivy, Grype, SARIF or CycloneDX report"
            print(f"::error title=DevSecure CI gate::scan file {_cmd(path)} {what} (did the scanner fail?)")
            return 2
        found = parse_findings(text, components)
        if kind == "text" and not found:
            print(f"::warning title=DevSecure CI gate::no CVE IDs in {_cmd(path)}; check it is the scanner's output")
        for cve, pkgs in found.items():
            findings.setdefault(cve, set()).update(pkgs)
    today = today or dt.date.today()
    allowed, expired = set(), set()
    if a.allowlist and os.path.exists(a.allowlist):
        with open(a.allowlist, encoding="utf-8") as f:
            allowed, expired = parse_allowlist(f.read(), today)
    statements, documents = [], []
    for path in a.vex:
        if not os.path.exists(path):
            print(f"::warning title=DevSecure VEX::{_cmd(path)} not found; ignored")
            continue
        with open(path, "rb") as f:
            raw = f.read()
        found = parse_vex(raw.decode("utf-8", errors="replace"), document=path)
        statements += found
        documents.append({"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "statements": len(found)})
    vex = vex_decisions(components, statements, a.vex_scope, a.vex_product or None) if a.vex else {}
    if a.vex and not a.vex_product and any(st.get("products") for st in statements):
        print("::warning title=DevSecure VEX::some VEX statements are scoped to a product; set vex-product to your "
              "image or application so statements about other products are not applied")
    cves = sorted(findings)
    if not cves:
        print("DevSecure CI gate: no CVE IDs found; nothing to check.")
        _write_outputs(env, 0, 0, 0)
        return 0
    try:
        ranked, missing = prioritize(a.api, key, cves, batch=max(1, a.batch), opener=opener, sleep=sleep)
    except AuthError as e:
        # A revoked or wrong key must not quietly switch the gate off, even in warn mode.
        print(f"::error::DevSecure CI gate could not rank findings: {_cmd(e)} (check DEVSECURE_API_KEY)")
        return 2
    except RuntimeError as e:
        print(f"::{'error' if a.on_api_error == 'fail' else 'warning'}::DevSecure CI gate could not rank findings: {_cmd(e)}")
        return 2 if a.on_api_error == "fail" else 0

    fail_on_kev = a.fail_on_kev == "true"
    # /prioritize also lists not-found CVEs as "unknown" items; count them once, as not found. A CVE that
    # is found but has no band stays in: the CISA KEV check still applies to it.
    missing_set = {str(m).upper() for m in missing}
    ranked = [i for i in ranked if str(i.get("cve_id", "")).upper() not in missing_set]
    blocked, allowlisted, passed = evaluate(ranked, allowed, a.fail_on, fail_on_kev, vex)
    md = summary_markdown(blocked, allowlisted, passed, missing, expired, findings, a.fail_on, fail_on_kev)
    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(md + "\n")
    for item, why in blocked:
        cve = item.get("cve_id")
        print(f"::error title={_prop(f'DevSecure: {cve}')}::{_cmd(why)}. "
              f"https://intelligence.devsecure.io/cve/{_cmd(cve)}")
    for cve in sorted(expired):
        print(f"::warning title=DevSecure allowlist::{cve} allowlist entry expired; it is enforced again")
    print(md)
    if a.vex:
        audit = {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                 "scope": a.vex_scope, "product": a.vex_product or None, "documents": documents,
                 "decisions": [e for cve in sorted(vex) for e in vex[cve]["entries"]]}
        with open(a.vex_audit, "w", encoding="utf-8") as f:
            json.dump(audit, f, indent=2)
        n = sum(1 for d in vex.values() if d["suppressed"])
        print(f"VEX: {n} CVE(s) suppressed, {len(vex) - n} mentioned but not suppressed; audit: {a.vex_audit}")
    _write_outputs(env, len(blocked), len(ranked), len(allowlisted), a.vex_audit if a.vex else None)
    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
