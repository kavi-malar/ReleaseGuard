from flask import Flask, request
import subprocess

app = Flask(__name__)

# BAD: hard-coded credentials (fake values for demonstration)
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "Sup3rS3cretPass!"


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr", "1+1")))  # BAD: eval on user input


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    return subprocess.check_output("ping -c 1 " + host, shell=True)  # BAD: shell=True


if __name__ == "__main__":
    app.run(debug=True)  # BAD: debug mode
