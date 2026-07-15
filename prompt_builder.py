import sys as _sys
from importlib import import_module as _import_module
from pathlib import Path as _Path

_legacy_name = __name__
_src = str(_Path(__file__).resolve().parent / 'src')
if _src not in _sys.path:
    _sys.path.insert(0, _src)
_mod = _import_module('source_diff_engine.llm.prompt_builder')
globals().update(_mod.__dict__)
_sys.modules[_legacy_name] = _mod
