`inspect_response=True` now ENFORCES phase-3/4 disruptions on all three
adapters (Flask, Starlette/FastAPI, Django). Earlier releases ran the
response-side rules but let the upstream response through on a
disruption — the WAF was effectively monitor-only on phase 3/4. The
ASGI adapter buffers `http.response.start` and the response body so
the block can replace the headers; if that buffering is impossible
(SSE / chunked downloads) opt back into the legacy monitor-only path
with `inspect_streaming=True`. `docs/threat-model.md` is updated.
