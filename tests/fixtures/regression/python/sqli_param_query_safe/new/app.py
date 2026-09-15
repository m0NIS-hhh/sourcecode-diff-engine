from flask import Flask, request

app = Flask(__name__)


@app.get("/user")
def load_user(cursor):
    user_id = request.args.get("id")
    cursor.execute("select * from users where id = ?", (user_id,))
    return cursor.fetchone()
