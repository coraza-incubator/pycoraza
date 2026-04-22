# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately** via one of:

- GitHub Security Advisories: https://github.com/jptosso/pycoraza/security/advisories/new
- Email: jptosso@gmail.com

Do **not** open a public issue for security vulnerabilities.

## What's in scope

- Any bypass — an attack that should be blocked by the shipped CRS
  profiles reaches the application handler.
- Any way to disable or corrupt the WAF without the operator's
  consent (e.g., malformed input that causes the middleware to
  `except` + `continue`).
- Memory-safety issues in the cffi/libcoraza boundary reachable from
  HTTP input.
- Signal-handling interactions that cause the WAF or the host
  process to crash under attacker-controlled input.

## What's out of scope

- Vulnerabilities in the underlying OWASP Coraza Go engine — report
  those upstream: https://github.com/corazawaf/coraza/security
- Vulnerabilities in libcoraza — report upstream:
  https://github.com/corazawaf/libcoraza/security
- Vulnerabilities in CRS rules themselves — report upstream:
  https://github.com/coreruleset/coreruleset/security
- CRS false positives. File a regular issue with `go-ftw`-style
  reproducer.

## Threat model

See [`docs/threat-model.md`](./docs/threat-model.md) for the full
threat model, including:

- Fail-closed guarantees and when they apply.
- Go-runtime signal handling and its interaction with Python's
  `faulthandler`.
- Callback thread safety across the cffi/Go-goroutine boundary.
- Encoding edge cases (ReDoS in SecLang regex, Unicode
  case-insensitive, UTF-8).

## Disclosure timeline

We aim to:
- Acknowledge receipt within 72 hours.
- Provide a first assessment within 7 days.
- Ship a fix or mitigation within 30 days for high/critical issues.

The embargo is lifted on release; coordinated disclosure is
negotiable for high-impact issues.
