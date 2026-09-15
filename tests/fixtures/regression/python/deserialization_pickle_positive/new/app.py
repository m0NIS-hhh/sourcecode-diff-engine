import pickle
from flask import Flask, request

app = Flask(__name__)


@app.post("/import")
def import_job():
    payload = request.get_data()
    job = pickle.loads(payload)
    return str(job)
