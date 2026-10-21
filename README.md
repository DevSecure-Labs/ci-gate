# DevSecure Intelligence CI gate

Fail a build when your scanner finds CVEs that DevSecure ranks at or above your threshold, or that CISA lists as known exploited. Each blocking CVE gets a reason, and the job summary shows a ranked table.

Your scanner finds the CVEs. DevSecure decides which ones matter now: RPS, Final Priority (after the CISA KEV floor and the EPSS gate), KEV and exploit evidence.

## GitHub Actions

```yaml
- name: Scan image
  run: trivy image --format json --output trivy.json my-image:latest

- name: DevSecure gate
  uses: DevSecure-Labs/ci-gate@v1   # or pin a full commit SHA
  with:
    api-key: ${{ secrets.DEVSECURE_API_KEY }}
    scan-file: trivy.json
    fail-on: high          # critical | high | medium | low | none
    fail-on-kev: "true"
```

- **Supported inputs:** Trivy JSON, Grype JSON (including related GHSA→CVE IDs), SARIF, CycloneDX vulnerabilities, or any text containing CVE IDs.
- **Allowlist:** `.devsecure-allowlist`, one CVE per line, optionally `# until 2026-12-31 reason`. Text after `#` is a comment, so `# CVE-…` allowlists nothing. Expired entries, and entries whose `until`/`expires` date isn't a valid `YYYY-MM-DD`, are enforced again and flagged.
- **VEX:** pass `vex:` (or `--vex`, repeatable) with an OpenVEX, CycloneDX VEX or CSAF VEX document. The rules are deliberately strict:
  - **Exact components only.** A `not_affected` / `fixed` / `resolved` / `false_positive` statement covers only the package URL **with version** it names (OpenVEX subcomponent or product, CycloneDX `affects[].ref`, CSAF product or relationship component). The scan must report that purl: Trivy `PkgIdentifier.PURL`, Grype `artifact.purl`, or CycloneDX components. A purl without a version never matches.
  - **Every affected package.** A CVE stops blocking only when every package the scan reports it in is covered.
  - **Fail safe.** An `affected` / `under_investigation` / `exploitable` / `in_triage` statement for the same component, in any document, wins. OpenVEX `not_affected` without a `justification` or `impact_statement` is ignored, as the spec requires.
  - **Product scope.** `vex-product: pkg:oci/app@sha256:...` ignores statements written for other products.
  - **Audit.** Every decision goes to `devsecure-vex-audit.json` (`vex-audit` output): document path and SHA-256, statement locator, status, justification, author, timestamp, component, and why it was or wasn't applied. Upload it with `actions/upload-artifact` to keep it with the build. Blocking CVEs that VEX mentions but doesn't cover say why in the summary.
  - **Unscoped opt-in.** `vex-scope: cve` applies CVE-level statements to scans without package URLs (text, SARIF). It's recorded as unscoped in the audit.
- **Fail closed:** the step fails (exit 2) if the API can't be reached or its reply doesn't account for every CVE sent (unless you set `on-api-error: warn`), if the key is rejected (401/403, even with `warn`), or if a scan file is missing, empty or JSON we don't recognise (the scanner probably failed). A CVE in CISA KEV blocks even when it has no priority band. The API base must be `https://`, and redirects are never followed, so the key is only ever sent to that host.
- **Outputs:** `blocked`, `checked`, `allowlisted`, `vex-audit` (when `vex` is set).

## Any CI (CLI)

The gate is a single file using the Python 3 standard library:

```bash
export DEVSECURE_API_KEY=...   # from your CI secret store
python3 gate.py --scan-file grype.json --fail-on critical --allowlist .devsecure-allowlist
```

Exit codes: `0` pass, `1` blocked, `2` usage or API error.

## Pinning

`@v1` follows the latest compatible v1 release. For a fixed, reviewable dependency, pin the full commit SHA of a release tag instead, e.g. `uses: DevSecure-Labs/ci-gate@<40-character SHA>  # v1.0.0`.

## Notes

- **Plan:** `POST /api/v1/prioritize` needs a plan with prioritize access. The gate batches requests to your plan's per-request limit (default 100).
- **Data:** CVE IDs are the only data sent; package names stay in your CI log.
- **Not found:** CVEs that aren't in DevSecure data are listed but never block.

## Licence and scope

This Action and `gate.py` are open source under the [MIT licence](LICENSE). They are a client only: CVE IDs go to the DevSecure Intelligence API with your API key, and the ranking comes back. The DevSecure Intelligence service (RPS scoring, data and API) is not part of this repository and is used under the [Terms of Service](https://intelligence.devsecure.io/terms).

Security issues: see [SECURITY.md](SECURITY.md).
