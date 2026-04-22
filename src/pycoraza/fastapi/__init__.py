"""FastAPI middleware — thin re-export of `pycoraza.starlette`.

FastAPI is built on Starlette; its `add_middleware(cls, **kwargs)`
instantiates `cls` with the given kwargs, so the same ASGI middleware
works for both. We expose it under `pycoraza.fastapi` for
discoverability: users who come looking for "pycoraza + fastapi"
should find it without knowing about Starlette internals.
"""

from ..starlette import CorazaMiddleware, OnBlockAsync

__all__ = ["CorazaMiddleware", "OnBlockAsync"]
