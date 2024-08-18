from flask import Flask, render_template, url_for, redirect, request, session, flash
from pkg import app, mail
from pkg.models import db, User
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message

# Secret key for generating the token
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

#custom errors
@app.errorhandler(404)
def not_found_error(error):
    return render_template('page404.html')

@app.route('/')
@app.route('/index/')
def index():
    return render_template('users/index.html')

@app.route('/dashboard/')
def dashboard():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    return render_template('users/dashboard.html', user=user)

@app.route('/connect_wallet', methods=['POST'])
def connect_wallet():
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    if user:
        api_key = request.form.get('api_key')
        api_secret = request.form.get('api_secret')

        if api_key and api_secret:
            user.set_api_credentials(api_key, api_secret)
            db.session.commit()

            # Bro this redirect to the page with start/stop buttons
            return redirect(url_for('wallet_control'))
        else:
            flash("Please provide both API key and secret", "danger")
            return redirect(url_for('dashboard'))

    flash("User not found", "danger")
    return redirect(url_for('dashboard'))

@app.route('/wallet_control/')
def wallet_control():
    return render_template('users/wallet_control.html')

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


@app.route('/forgot-password/', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)

            # Compose the email
            subject = "Password Reset Request"
            body = f"Hi {user.alias},\n\nClick the link below to reset your password:\n{reset_url}\n\nIf you didn't request a password reset, please ignore this email."

            msg = Message(subject, 
                          sender=app.config['MAIL_USERNAME'], 
                          recipients=[email])
            msg.body = body

            try:
                # Send the email using Flask-Mail
                mail.send(msg)
                flash('A password reset link has been sent to your email.', 'info')
            except Exception as e:
                flash(f'Failed to send email. Error: {str(e)}', 'danger')
        else:
            flash('Email not found.', 'danger')
    return render_template('users/forgot_password.html')


@app.route('/reset-password/<token>/', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # Token is valid for 1 hour
    except:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        re_password = request.form.get('re_password')
        
        if password == re_password:
            user = User.query.filter_by(email=email).first()
            user.set_password(password)
            db.session.commit()
            flash('Your password has been reset. Please log in.', 'success')
            return redirect(url_for('auth'))
        else:
            flash('Passwords do not match.', 'danger')
    
    return render_template('users/reset_password.html')



@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth'))