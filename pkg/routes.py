from flask import Flask, render_template, url_for, redirect, request, session, flash
from pkg import app
from pkg.models import db, User

# #custom errors
# @app.errorhandler(404)
# def not_found_error(error):
#     return render_template('page404.html')

@app.route('/')
@app.route('/index/')
def index():
    return render_template('users/index.html')

@app.route('/dashboard/')
def dashboard():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    return render_template('users/dashboard.html', user=user)

@app.route('/start-trading/', methods=['GET', 'POST'])
def auth():
    if request.method == 'POST':
        if 'signup' in request.form:
            alias = request.form.get('alias')
            email = request.form.get('email')
            password = request.form.get('password')
            re_password = request.form.get('re_password')
            if password == re_password:
                existing_email = User.query.filter_by(email=email).first()
                existing_alias = User.query.filter_by(alias=alias).first()
                if existing_email is None and existing_alias is None:
                    user = User(alias=alias, email=email)
                    user.set_password(password)
                    db.session.add(user)
                    db.session.commit()
                    flash('Account created successfully! Please log in.', 'success')
                else:
                    if existing_email:
                        flash('Email already registered.', 'danger')
                    if existing_alias:
                        flash('Alias already in use.', 'danger')
            else:
                flash('Passwords do not match.', 'danger')
        elif 'login' in request.form:
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()
            if user and user.check_password(password):
                session['user_id'] = user.id
                flash('Logged in successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password.', 'danger')
    return render_template('users/auth.html')



@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth'))