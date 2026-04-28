Preserve multi-value HTTP headers when forwarding to the WAF. The
Flask/WSGI adapter now iterates request headers via Werkzeug's
``EnvironHeaders`` (canonical names, ``Content-Type`` /
``Content-Length`` included) and the Starlette/ASGI adapter preserves
repeated headers — including multiple ``Set-Cookie`` response lines
and proxy-split ``X-Forwarded-For`` request lines — as distinct
``(name, value)`` tuples instead of collapsing them.
