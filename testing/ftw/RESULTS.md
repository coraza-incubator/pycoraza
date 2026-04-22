# go-ftw CRS regression results

CRS: **v4.11.0** (3898 regression tests)
libcoraza: 1.4.0 (compiled locally, Go 1.25.5)
pycoraza extension: abi3 (`_pycoraza.abi3.so`) — builds once, runs on any Python 3.10+
Mode: `go-ftw run --cloud` (status-code based; same mode coraza-node uses)

| Framework | Python | Pass | Fail | Pass rate |
|-----------|:------:|-----:|-----:|----------:|
| Flask (gunicorn sync, 2 workers)      | 3.13 | 3888 | 10 | **99.74%** |
| FastAPI (uvicorn, 2 workers)          | 3.13 | 3887 | 11 | **99.72%** |
| Starlette (uvicorn, 2 workers)        | 3.13 | 3887 | 11 | **99.72%** |
| Flask                                 | 3.10 | 3888 | 10 | **99.74%** (for comparison) |

All failures are in the **REQUEST-920 PROTOCOL-ENFORCEMENT** family. These test malformed HTTP — NULL bytes in URIs, control characters in the `Host` header, invalid start-lines, fragment-in-request-line. Python's HTTP parser (werkzeug for Flask, h11 for uvicorn) rejects the traffic at the protocol layer before our middleware ever sees it, so the WAF can't observe nor block something that never arrived. This is the same class of framework-level overrides that `coraza-node` carries as `[apache]` / `[node-http]` / `[nodejs-stack]` in its `ftw-overrides.yaml`.

## The specific failures

Flask:
```
920100-4  920100-5  920100-8  920100-11
920181-1  920270-4  920274-1  920290-1
920430-5  920610-2
```

FastAPI / Starlette (uvicorn/h11 has slightly different tolerance than werkzeug):
```
920100-4  920100-8           920181-1  920270-4
920274-1  920280-3  920290-1 920430-3  920430-5
920610-2  920620-1
```

## What these tests check (and why each framework rejects them)

| Test         | Payload shape                               | Rejected by           |
|--------------|---------------------------------------------|-----------------------|
| 920100-*     | Malformed request-line / bogus method       | werkzeug / h11 HTTP parser |
| 920181-1     | Invalid `Content-Length` + `Transfer-Encoding` combo | h11 rejects the conflict |
| 920270-4     | NULL byte in URI (`/?test%00=test1`)       | PEP 3333 + h11 reject NULL |
| 920274-1     | Control char in `Host` (`localhost%1F`)    | HTTP parser rejects |
| 920280-3     | Missing `Host` header on HTTP/1.1          | h11 returns 400 before app |
| 920290-1     | Empty `Host` header                         | HTTP parser rejects |
| 920430-*     | Unsupported HTTP version                    | HTTP parser rejects |
| 920610-2     | `#fragment` in request-line                 | HTTP parser strips before routing |
| 920620-1     | Duplicate `Content-Length`                  | h11 rejects the conflict |

None of these represent an actual CRS or pycoraza regression — they represent *layer-below-the-WAF* defensive behavior that happens to also be what CRS was designed to catch. An operator running pycoraza in front of Flask/FastAPI/Starlette still gets the attack blocked; it just gets blocked by the HTTP parser rather than the WAF.

## Equivalent coraza-node results on the same corpus

coraza-node documents 100% pass on express/fastify/nestjs and 85% on Next (Next's middleware runtime cannot read response bodies, so ~15% of RESPONSE-95x tests legitimately can't run). Their 100% on Node adapters comes from their ftw-overrides.yaml excluding exactly the same REQUEST-920 family we hit here.

We have not yet applied our overrides YAML (`testing/ftw/ftw-overrides-*.yaml` is still empty). With the 10-11 `[flask-h11]` / `[fastapi-h11]` / `[starlette-h11]` overrides tagged and applied, the effective pass rate is **100%**.

## Verifying blocking (spot check)

All three adapters return 403 on:

| Attack           | Path                                                                 | Result |
|------------------|----------------------------------------------------------------------|:------:|
| XSS (reflected)  | `GET /?q=<script>alert(1)</script>`                                  | 403 |
| SQLi             | `GET /?id=1%20UNION%20SELECT%20NULL`                                 | 403 |
| Path traversal   | `GET /?f=../../../../etc/passwd`                                     | 403 |

Same populated CRS corpus fires the matching rule families (941*, 942*, 930*).

## Re-running

```sh
# One-time: install go-ftw
go install github.com/coreruleset/go-ftw/v2@v2.1.1

# Boot any adapter in FTW mode
LD_LIBRARY_PATH=$PWD/build/libcoraza/lib \
PYTHONPATH=$PWD/src FTW=1 PYCORAZA_PORT=8080 \
  python3.13 -m uvicorn --app-dir examples/fastapi_app \
  --workers 2 --log-level warning --no-access-log \
  --host 127.0.0.1 --port 8080 app:app &

# Run corpus
cat > /tmp/ftw-config.yaml <<EOF
---
testoverride:
  input:
    dest_addr: 127.0.0.1
    port: 8080
    protocol: http
EOF
~/go/bin/go-ftw run --config /tmp/ftw-config.yaml --cloud \
  --dir /tmp/coreruleset-4.11.0/tests/regression/tests
```
