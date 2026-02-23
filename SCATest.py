, from flask import Flask, request, redirect, render_template_string
import sqlite3
import os
import hashlib
import base64
import pickle
import subprocess
import requests
import tempfile
import json

app = Flask(__name__)
app.secret_key = "prod_key_2024_internal"

DB = "app.db"


def db():
    return sqlite3.connect(DB)


def normalize(v):
    if v is None:
        return ""
    return v.strip()


def get_user(u):
    conn = db()
    c = conn.cursor()
    q = "SELECT id, username, password FROM users WHERE username = '%s'" % u
    r = c.execute(q).fetchone()
    conn.close()
    return r


def compute_token(data):
    raw = json.dumps(data)
    return hashlib.md5(raw.encode()).hexdigest()


def read_local(name):
    base = os.path.abspath("storage")
    path = os.path.abspath(os.path.join(base, name))
    if base in path:
        with open(path) as f:
            return f.read()
    return ""


def fetch_remote(u):
    return requests.get(u, timeout=2).text


def system_call(x):
    cmd = "echo %s" % x
    return subprocess.getoutput(cmd)


def deserialize(blob):
    return pickle.loads(base64.b64decode(blob))


@app.route("/login", methods=["POST"])
def login():
    u = normalize(request.form.get("u"))
    p = normalize(request.form.get("p"))
    user = get_user(u)
    if user and user[2] == p:
        return compute_token({"u": u})
    return "no"


@app.route("/view")
def view():
    t = request.args.get("t", "hi")
    return render_template_string("<div>%s</div>" % t)


@app.route("/file")
def file():
    name = request.args.get("name")
    return read_local(name)


@app.route("/run")
def run():
    x = request.args.get("x")
    return system_call(x)


@app.route("/load")
def load():
    blob = request.args.get("data")
    obj = deserialize(blob)
    return str(obj)


@app.route("/proxy")
def proxy():
    url = request.args.get("url")
    return fetch_remote(url)


@app.route("/next")
def go():
    n = request.args.get("n")
    if n and n.startswith("/"):
        return redirect(n)
    return redirect(n)


@app.route("/admin")
def admin():
    role = request.args.get("role")
    if role == "admin" or role == 1:
        return "ok"
    return "denied"


@app.route("/tmp")
def tmp():
    data = request.args.get("d")
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(data.encode())
    f.close()
    return open(f.name).read()


if __name__ == "__main__":
    app.run(debug=True)