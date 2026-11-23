
import os
import sqlite3
from functools import wraps
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash, g
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

DATABASE = os.environ.get(
    "DB_PATH",
    os.path.join(app.instance_path, "students.db")
)

os.makedirs(app.instance_path, exist_ok=True)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        db.commit()


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("All fields are required.", "error")
            return redirect(url_for("signup"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return redirect(url_for("signup"))

        hashed_password = generate_password_hash(password)

        try:
            db = get_db()
            cursor = db.execute(
                "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                (name, email, hashed_password)
            )
            db.commit()

            session.clear()
            session["user_id"] = cursor.lastrowid
            session["user_name"] = name

            flash("Account created successfully!", "success")
            return redirect(url_for("dashboard"))

        except sqlite3.IntegrityError:
            flash("This email is already registered.", "error")

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]

            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/student")
@login_required
def student():
    return render_template("student.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have logged out successfully.", "success")
    return redirect(url_for("login"))


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=True)
