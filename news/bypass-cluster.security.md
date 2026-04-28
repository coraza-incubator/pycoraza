Close three request-side bypass classes shared by every adapter: (1)
re-split RFC 7230 list-valued request headers (``X-Forwarded-For``,
``Forwarded``, ``Cookie``, ``Accept`` family, ``Via``, ``Warning``,
``X-Forwarded-Proto/Host``) when WSGI/Django collapse repeats into a
single comma-joined env value, so rules keyed on exact values no
longer miss merged-string attacks; (2) decode ASGI ``raw_path`` /
``query_string`` as UTF-8 with ``surrogateescape`` instead of latin-1
+ ``errors="replace"`` so non-ASCII paths (e.g. ``%E4%B8%AD``)
round-trip cleanly to the WAF without ``U+FFFD`` corruption; (3)
strip RFC 3986 path parameters (``;...``) from the path before the
static-asset skip predicate runs in Flask, Django and Starlette,
closing the ``/admin;.png`` -> static-skip -> framework-still-routes-
to-``/admin`` bypass.
