from crypt import methods
from flask_app import app
from flask import render_template, request, redirect, session, flash
from flask_app.models.register_model import Account
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

@app.route('/')
def index():
    if "email" in session:
    # can have access to dashboard by URL if still email in session 
        return redirect('/dashboard')
    return render_template("index.html")

@app.route('/create', methods=['POST'])
def create():
    if not Account.validate_form(request.form):
        return redirect('/')
    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    data = {
        'first_name': request.form['first_name'],
        'last_name': request.form['last_name'],
        'email': request.form['email'],
        'password': pw_hash
    }
    Account.save(data)
    session['email'] = request.form['email']
    return redirect('/')

@app.route('/login', methods=['POST'])
def log_in():
    data = {
        'email': request.form['email'],
    }
    user_in_db = Account.get_by_email(data)
    if not user_in_db:
        flash("Invalid Credential", "err_log")
        return redirect('/')
    if not bcrypt.check_password_hash(user_in_db.password, request.form['password']):
            flash("Invalid Credential", "err_log")
            return redirect('/')
    if user_in_db:
        session['email'] = user_in_db.email
        return redirect('/dashboard')

@app.route('/dashboard')
def dashboard():
# this is to not have access to the dash board when session is empty with URL
    if not "email" in session:
        return redirect('/')
    data = {
        'email': session['email'],
    }
    user = Account.get_by_email(data)
    return render_template("user_page.html", user=user)

@app.route("/delete_session")
def delete_session():
    session.clear()
    return redirect("/")