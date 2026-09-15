from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.get("/preview")
def preview():
    template = request.args.get("template", "")
    return render_template_string(template)
