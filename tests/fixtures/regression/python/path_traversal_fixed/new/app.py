from pathlib import Path
from flask import request

BASE = Path("/srv/files").resolve()


def download():
    name = request.args.get("path", "")
    target = (BASE / name).resolve()
    if not str(target).startswith(str(BASE)):
        raise ValueError("invalid path")
    return open(target, "rb").read()
