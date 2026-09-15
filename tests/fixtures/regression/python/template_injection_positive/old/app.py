from flask import Flask

app = Flask(__name__)


@app.get("/preview")
def preview():
    return "preview disabled"
