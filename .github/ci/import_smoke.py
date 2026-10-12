"""CI import-smoke: import the zalo plugin package with host modules stubbed.

The zalo adapter imports Hermes gateway internals (gateway.platforms.base,
gateway.session, gateway.config, hermes_constants) that only exist in the
Hermes runtime, not on PyPI. CI stubs them so `import zalo` exercises real
module-level code (class definitions, constants, __init__ re-exports) without
the host app.
"""
import sys
import types
from pathlib import Path

# Anchor the repo root so `import zalo` works no matter which directory or
# script-path invocation CI uses (sys.path[0] would otherwise be .github/ci).
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))


def _placeholder(name):
    # Class whose metaclass answers ANY attribute access with another
    # placeholder — covers MessageType.TEXT-style enum members used as
    # default arg values at import time, and arbitrary base classes.
    class _Meta(type):
        def __getattr__(cls, attr):
            return _placeholder(f"{cls.__name__}.{attr}")

    return _Meta(name, (object,), {})


def _stub(dotted):
    parts = dotted.split(".")
    for i in range(1, len(parts) + 1):
        mod_name = ".".join(parts[:i])
        if mod_name not in sys.modules:
            mod = types.ModuleType(mod_name)
            mod.__getattr__ = _placeholder  # PEP 562
            sys.modules[mod_name] = mod


for _d in (
    "gateway",
    "gateway.platforms",
    "gateway.platforms.base",
    "gateway.session",
    "gateway.config",
    "hermes_constants",
):
    _stub(_d)

# hermes_constants.get_hermes_home() is called at module import time and its
# result is path-joined — give it a concrete return value.
sys.modules["hermes_constants"].get_hermes_home = lambda: Path("/tmp/hermes-ci")

import zalo  # noqa: E402

assert callable(zalo.register), "zalo.register must be a callable entry point"
assert isinstance(zalo.__version__, str) and zalo.__version__, "version must be set"
print(f"import-smoke OK: zalo v{zalo.__version__}")
