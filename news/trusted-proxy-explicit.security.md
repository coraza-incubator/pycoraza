**Breaking change.** `pycoraza.trusted_proxy()` now requires an
explicit `trusted_cidrs=` argument. The previous default that trusted
every RFC1918 / loopback range silently turned any internal-but-not-
XFF-sanitizing hop into a header-spoofing bypass — an attacker who
could land any packet on an internal IP could dictate the "client IP"
the WAF saw. Calling `trusted_proxy()` without `trusted_cidrs=` now
raises `ValueError`. Restore the legacy behavior by passing
`trusted_cidrs=DEFAULT_PRIVATE_CIDRS` (exported from
`pycoraza.client_ip`); `docs/client-ip.md` is updated with the
rationale and migration.
