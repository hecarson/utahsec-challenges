import os
from flask import Flask, render_template, request, session, redirect, abort
import sqlite3
from passlib.hash import bcrypt

DB_PATH = "data.db"

flag: str
with open("flag.txt", "r") as file:
    flag = file.read().strip()

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/about")
def about():
    return render_template("about.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    else:
        if "username" not in request.form or "password" not in request.form:
            abort(400)
        username = request.form["username"]
        password = request.form["password"]

        if not check_credentials(username, password):
            return render_template("login.html", error="invalid username or password")
        session["user"] = username
        return redirect("/admin")

@app.get("/admin")
def admin():
    if session.get("user") != "admin":
        abort(401)
    return render_template("admin.html", flag=flag)

@app.get("/admin/tickets/")
def get_tickets():
    if session.get("user") != "admin":
        abort(401)

    db_con = sqlite3.connect(DB_PATH)
    cur = db_con.cursor()
    res = cur.execute("select id from tickets")
    rows = res.fetchall()
    ids = [row[0] for row in rows]
    return ids

@app.route("/admin/tickets/<int:id>", methods=["GET", "DELETE"])
def get_ticket_by_id(id: int):
    if session.get("user") != "admin":
        abort(401)

    db_con = sqlite3.connect(DB_PATH)
    cur = db_con.cursor()
    res = cur.execute("select id from tickets where id=?", (id,))
    row = res.fetchone()
    if not row:
        abort(404)

    if request.method == "GET":
        res = cur.execute("select text from tickets where id=?", (id,))
        row = res.fetchone()
        if not row:
            abort(404)

        ticket = row[0]
        return ticket
    else:
        cur.execute("delete from tickets where id=?", (id,))
        db_con.commit()
        return ("", 204)

@app.route("/logout")
def logout():
    session.pop("user")
    return redirect("/")

@app.route("/tickets", methods=["GET", "POST"])
def tickets():
    if request.method == "GET":
        return render_template("tickets.html")
    else:
        if "ticket" not in request.form:
            abort(400)

        ticket = request.form["ticket"]

        # Prevent any possible XSS attack, 100% foolproof
        xss_tag_blacklist = ["<script", "</script>", "<img", "</img>"]
        for tag in xss_tag_blacklist:
            if tag in ticket.lower():
                return render_template("tickets.html", error="input contains forbidden tags")

        db_con = sqlite3.connect(DB_PATH)
        cur = db_con.cursor()
        cur.execute("insert into tickets (text) values (?)", (ticket,))
        db_con.commit()

        return render_template("tickets.html", success=True)



def check_credentials(username: str, password: str) -> bool:
    db_con = sqlite3.connect(DB_PATH)
    cur = db_con.cursor()
    res = cur.execute("select pw_hash from users where username=?", (username,))
    row = res.fetchone()
    if not row:
        return False

    pw_hash = row[0]
    return bcrypt.verify(password, pw_hash)
