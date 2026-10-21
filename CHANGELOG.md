# Changelog

## v1.1.0

Hardening from a security review; the gate now fails closed in more cases.

- **API reply checked:** a reply that doesn't account for every CVE sent (or isn't the expected shape) is an API error (exit 2, or a warning with `on-api-error: warn`). A rejected key (401/403) always fails, even with `warn`. Network errors while reading the reply, and non-JSON replies, are retried.
- **CISA KEV without a band:** a CVE in CISA KEV now blocks even when the API returns no priority band for it.
- **Scan files:** a missing or empty scan file, or JSON that isn't a Trivy, Grype, SARIF or CycloneDX report, fails (exit 2). Plain text with no CVE IDs passes with a warning. Outputs are written when there is nothing to check.
- **Allowlist:** text after `#` is a comment (a commented-out CVE allowlists nothing). An `until`/`expires` date that isn't a valid `YYYY-MM-DD` counts as expired. `expires YYYY-MM-DD` is accepted as well as `until`.
- **API key:** the API base must be `https://` (plain `http://` only for localhost), and redirects are never followed, so the key is only sent to that host.
- **Annotations and summary:** package names, VEX justifications and API text are escaped, so they can't add workflow commands or break the summary table.
- **VEX:** a warning when product-scoped statements are used without `vex-product`.

## v1.0.2

- Test workflow only: pins the Python matrix to Ubuntu 24.04 (the new `ubuntu-latest` has no Python 3.9), stops one failing version from cancelling the others, and adds Python 3.13 and 3.14. No change to the Action or `gate.py`.

## v1.0.1

- Removes Python bytecode cache files that were published by mistake in v1.0.0 and adds a `.gitignore`. No change to the Action or `gate.py`.

## v1.0.0

First public release.

- Ranks the CVEs in scanner output (Trivy, Grype, SARIF, CycloneDX or any text) with DevSecure Final Priority and fails the build at your threshold or on CISA KEV.
- Allowlist with expiry dates.
- VEX (OpenVEX, CycloneDX VEX, CSAF VEX): exact component scope, every affected package, fail-safe conflicts, optional product scope, JSON audit of every decision.
- Fails closed when the API can't be reached, unless `on-api-error: warn`.
