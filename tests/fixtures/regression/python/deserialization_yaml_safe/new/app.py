import yaml
from flask import Flask, request

app = Flask(__name__)


@app.post("/config")
def import_config():
    payload = request.get_data(as_text=True)
    return yaml.safe_load(payload)
