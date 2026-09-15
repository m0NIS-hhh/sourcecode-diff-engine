import os
from flask import Flask, request

app = Flask(__name__)


@app.get("/run")
def run_command():
    cmd = request.args.get("cmd")
    return os.system(cmd)
