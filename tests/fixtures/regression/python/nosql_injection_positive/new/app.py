from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient()["demo"]


@app.get("/users")
def users():
    query = request.args.get("query", "")
    return db.users.find_one({"name": query})
