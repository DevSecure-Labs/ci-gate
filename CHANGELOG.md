# Changelog

## v1.0.0

First public release.

- Ranks the CVEs in scanner output (Trivy, Grype, SARIF, CycloneDX or any text) with DevSecure Final Priority and fails the build at your threshold or on CISA KEV.
- Allowlist with expiry dates.
- VEX (OpenVEX, CycloneDX VEX, CSAF VEX): exact component scope, every affected package, fail-safe conflicts, optional product scope, JSON audit of every decision.
- Fails closed when the API can't be reached, unless `on-api-error: warn`.
