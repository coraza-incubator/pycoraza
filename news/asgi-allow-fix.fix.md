Starlette / FastAPI middleware: `on_waf_error="allow"` is now actually
fail-open. Previous releases raised `CorazaError("cannot
allow-fall-through after middleware consumed receive")` because the
receive channel had been drained for body buffering. We now replay the
buffered body through `_replay_receive` and forward the original
request to the downstream app on a WAF error.
