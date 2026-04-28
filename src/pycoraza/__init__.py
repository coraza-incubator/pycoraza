"""pycoraza — OWASP Coraza WAF for Python (Flask, FastAPI, Starlette).

Mirrors the public surface of `@coraza/core` from coraza-node:

    >>> from pycoraza import create_waf, WAFConfig, ProcessMode
    >>> from pycoraza.coreruleset import recommended
    >>> waf = create_waf(WAFConfig(rules=recommended(), mode=ProcessMode.BLOCK))
    >>> tx = waf.new_transaction()
    >>> tx.process_connection("127.0.0.1", 54321)
    >>> ...
    >>> tx.close()

Framework integrations live under `pycoraza.flask`, `pycoraza.fastapi`,
and `pycoraza.starlette` — install the appropriate extra.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from .abi import Abi, CorazaError
from .client_ip import DEFAULT_PRIVATE_CIDRS, trusted_proxy
from .logger import Logger, console_logger, silent_logger
from .pool import WAFPool, create_waf_pool
from .skip import SkipArg, SkipPredicate, build_skip_predicate
from .transaction import Transaction
from .types import (
    PROBE_METHODS,
    PROBE_PATHS,
    Interruption,
    MatchedRule,
    OnWAFError,
    OnWAFErrorArg,
    ProcessMode,
    RequestInfo,
    ResponseInfo,
    SkipOptions,
    WAFConfig,
    WAFErrorPolicy,
)
from .waf import WAF, create_waf

try:
    __version__ = _pkg_version("pycoraza")
except PackageNotFoundError:  # editable / source-tree dev install
    __version__ = "0.0.0+dev"

__all__ = [
    "DEFAULT_PRIVATE_CIDRS",
    "PROBE_METHODS",
    "PROBE_PATHS",
    "WAF",
    "Abi",
    "CorazaError",
    "Interruption",
    "Logger",
    "MatchedRule",
    "OnWAFError",
    "OnWAFErrorArg",
    "ProcessMode",
    "RequestInfo",
    "ResponseInfo",
    "SkipArg",
    "SkipOptions",
    "SkipPredicate",
    "Transaction",
    "WAFConfig",
    "WAFErrorPolicy",
    "WAFPool",
    "__version__",
    "build_skip_predicate",
    "console_logger",
    "create_waf",
    "create_waf_pool",
    "silent_logger",
    "trusted_proxy",
]
