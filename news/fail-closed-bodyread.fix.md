Flask middleware now wraps `wsgi.input.read()` in the WAF error path. A
slow / broken client that drops mid-body used to escape uncaught and
leak the open transaction; the failure now routes through
`_handle_waf_error` (so `on_waf_error` policy applies) and the
transaction is closed deterministically.
