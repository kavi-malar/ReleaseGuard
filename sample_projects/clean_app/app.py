import os
from flask import Flask, jsonify

app = Flask(__name__)


def add(a: int, b: int) -> int:
    return a + b


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/add/<int:a>/<int:b>")
def add_route(a, b):
    return jsonify(result=add(a, b))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
