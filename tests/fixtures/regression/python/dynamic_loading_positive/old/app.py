from flask import Flask

app = Flask(__name__)


@app.get("/plugin")
def plugin():
    return {"ok": True}
