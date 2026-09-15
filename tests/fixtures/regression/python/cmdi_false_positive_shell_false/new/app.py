import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.get("/lookup")
def lookup():
    host = request.args.get("host", "localhost")
    completed = subprocess.run(["ping", "-c", "1", host], shell=False, check=False)
    return str(completed.returncode)
