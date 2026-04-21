from flask import render_template, redirect, url_for
from flask_login import login_required, current_user
from app.main import main_bp


@main_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))
    return render_template("landing.html")


@main_bp.route("/home")
@login_required
def home():
    return render_template("home.html", user=current_user)


@main_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)
