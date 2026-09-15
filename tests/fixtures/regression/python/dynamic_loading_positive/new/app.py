import importlib
from flask import Flask, request

app = Flask(__name__)


@app.get("/plugin")
def plugin():
    module_name = request.args.get("module", "")
    module = importlib.import_module(module_name)
    return {"loaded": module.__name__}
