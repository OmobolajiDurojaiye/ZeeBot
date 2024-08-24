from flask import Flask, render_template, url_for, redirect, request, session, flash, jsonify
from pkg import app
from pkg.models import db, User, Symbol
import threading
# import trading_logic
# from trading_logic import live_trading, stop_trading_logic, close_all_positions, set_trading_capital,trading_thread_function
from itsdangerous import URLSafeTimedSerializer
from flask_wtf import FlaskForm
from wtforms import DecimalField, SubmitField
from flask_mail import Mail, Message
from wtforms.validators import DataRequired, NumberRange
from werkzeug.exceptions import BadRequest
import logging
from flask import current_app 


mail = Mail(app)

# Global variable to store the trading thread
trading_thread = None

# Secret key for generating the token
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Flask-WTF form for setting trading capital
class TradingCapitalForm(FlaskForm):
    amount = DecimalField('Enter the amount to trade', validators=[DataRequired(), NumberRange(min=0.01)], places=2)
    submit = SubmitField('Submit')

#custom errors
@app.errorhandler(404)
def not_found_error(error):
    return render_template('page404.html')

def trading_thread_function(app, user_id, selected_symbol, amount, leverage):
    # Push the app context to the new thread
    with app.app_context():
        live_trading(user_id, selected_symbol, amount, leverage)

@app.route('/select-symbol', methods=['POST'])
def select_symbol():
    selected_symbol = request.json.get('symbol')
    
    if selected_symbol:
        # Store selected symbol in session
        session['selected_symbol'] = selected_symbol
        
        trading_logic.symbol = selected_symbol
        
        flash(f'Symbol {selected_symbol} has been selected.', 'success')
        return jsonify({'message': f'Symbol {selected_symbol} selected.'}), 200
    else:
        flash('No symbol selected', 'danger')
        return jsonify({'error': 'No symbol selected'}), 400

@app.route('/select-symbol', methods=['GET'])
def get_symbols():
    symbols = Symbol.query.all()
    symbol_list = [{'name': symbol.name} for symbol in symbols]
    return jsonify(symbol_list)

@app.route('/symbols', methods=['GET', 'POST'])
def symbols():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    symbols = Symbol.query.all()
    
    if request.method == 'POST':
        selected_symbol = request.form.get('symbol')
        
        if selected_symbol:
            session['selected_symbol'] = selected_symbol
            trading_logic.symbol = selected_symbol
            flash(f'Symbol {selected_symbol} selected successfully.', 'success')
        else:
            flash('No symbol selected. Please choose one.', 'danger')

    return render_template('users/dashboard.html', user=user, symbols=symbols)


@app.route('/start_trading', methods=['POST'])
def start_trading():
    global trading_thread

    try:
        user_id = session.get('user_id')
        if not user_id:
            flash('User not authenticated. Please log in.', 'danger')
            return redirect(url_for('auth'))

        # Retrieve form data or session data
        selected_symbol = request.form.get('symbol') or session.get('selected_symbol')
        amount = request.form.get('amount') or session.get('amount')
        leverage = request.form.get('leverage') or session.get('leverage')

        logging.info(f"Received symbol: {selected_symbol}, amount: {amount}, leverage: {leverage}")

        if not selected_symbol:
            flash('No symbol selected. Please choose a symbol.', 'danger')
            return redirect(url_for('dashboard'))

        try:
            amount = float(amount)
            if amount <= 0:
                raise ValueError("Amount must be greater than 0.")
        except ValueError as e:
            flash(str(e), 'danger')
            return redirect(url_for('dashboard'))

        try:
            leverage = int(leverage)
            if leverage <= 0:
                raise ValueError("Leverage must be greater than 0.")
        except ValueError as e:
            flash(str(e), 'danger')
            return redirect(url_for('dashboard'))

        # Store amount and leverage in session
        session['amount'] = amount
        session['leverage'] = leverage

        if trading_thread is None or not trading_thread.is_alive():
            if hasattr(trading_logic, 'set_parameters'):
                trading_logic.set_parameters(symbol=selected_symbol, leverage=leverage)

            # Pass the app instance to the thread function
            trading_thread = threading.Thread(target=trading_thread_function, args=(app, user_id, selected_symbol, amount, leverage))
            trading_thread.start()

            flash(f'Trading started for {selected_symbol} with amount {amount} and leverage {leverage}.', 'success')
        else:
            flash('Trading is already running.', 'warning')

    except Exception as e:
        logging.error(f"Error in start_trading: {str(e)}")
        flash('An unexpected error occurred while trying to start trading.', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/stop-trading', methods=['POST'])
def stop_trading():
    try:
        with current_app.app_context():  # Ensure Flask context is available
            stop_trading_logic()

            data = request.get_json()
            if data:
                user_id = data.get('user_id')
                if user_id:
                    logging.info(f"Stopping trading for user_id={user_id}")
                else:
                    return jsonify({"error": "Missing 'user_id' in request."}), 400

            return jsonify({"message": "Trading stopped successfully."}), 200

    except BadRequest as e:
        logging.error(f"Bad request: {str(e)}")
        return jsonify({"error": str(e)}), 400

    except Exception as e:
        logging.error(f"Error stopping trading: {str(e)}")
        return jsonify({"error": "An error occurred while stopping trading."}), 500


@app.route('/select-leverage', methods=['POST'])
def select_leverage():
    data = request.get_json()
    selected_leverage = data.get('leverage')

    if selected_leverage:
        session['leverage'] = selected_leverage  # Store leverage in session
        
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                user.leverage = int(selected_leverage)
                db.session.commit()
                trading_logic.LEVERAGE = user.leverage
                return jsonify({'success': True, 'message': f'Leverage set to {selected_leverage}'}), 200
            else:
                return jsonify({'success': False, 'message': 'User not found.'}), 404
        else:
            return jsonify({'success': False, 'message': 'User not authenticated.'}), 401
    else:
        return jsonify({'success': False, 'message': 'No leverage selected'}), 400
@app.route('/set_amount', methods=['POST'])
def set_amount():
    with current_app.app_context():  # Ensure Flask context is available
        data = request.get_json()
        amount = data.get('amount')

        if amount is not None:
            session['amount'] = amount  # Store amount in session

            user_id = session.get('user_id')
            if user_id:
                success = set_trading_capital(user_id, float(amount))
                if success:
                    user = User.query.get(user_id)
                    if user:
                        user.trading_capital = float(amount)
                        db.session.commit()
                        return jsonify({'success': True, 'message': 'Amount set successfully!'}), 200
                    else:
                        return jsonify({'success': False, 'message': 'User not found.'}), 404
                else:
                    return jsonify({'success': False, 'message': 'Error setting the amount.'}), 500
            else:
                return jsonify({'success': False, 'message': 'User not authenticated.'}), 401
        else:
            return jsonify({'success': False, 'message': 'Invalid amount provided.'}), 400


@app.route('/')
@app.route('/index/')
def index():
    return render_template('users/index.html')

@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    # Check if the API credentials are already set
    api_credentials_set = bool(user.api_key and user.api_secret)

    return render_template('users/dashboard.html', user=user, api_credentials_set=api_credentials_set)



@app.route('/profile/<alias>', methods=['GET', 'POST'])
def profile(alias):
    user = User.query.filter_by(alias=alias).first_or_404()

    if request.method == 'POST':

        new_email = request.form['email']
        if new_email != user.email:
            # Egbon, so after it detects the user changed email, it will send the link to update
            send_confirmation_email(user, new_email)

            flash('A confirmation link has been sent to your current email address. Please confirm to update your email.', 'info')
            return redirect(url_for('profile'))

        # for future purpose
        # user.trading_capital = request.form['trading_capital']
        # user.leverage = request.form['leverage']
        
        if request.form['api_key'] and request.form['api_secret']:
            user.set_api_credentials(request.form['api_key'], request.form['api_secret'])
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('users/user_profile.html', user=user)

def send_confirmation_email(user, new_email):
    #na the token wey the user go use change email be this, e go do am auto
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    token = serializer.dumps([user.email, new_email], salt='email-update')

    # na the configuration email be this
    msg = Message("Confirm Your Email Change", sender=app.config['MAIL_USERNAME'], recipients=[user.email])
    link = url_for('confirm_email_change', token=token, _external=True)
    msg.body = f"Hi {user.alias},\n\nTo confirm your email change to {new_email}, please click the link below:\n{link}\n\nIf you didn't request this change, please ignore this email."
    mail.send(msg)

@app.route('/confirm_email_change/<token>')
def confirm_email_change(token):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email_data = serializer.loads(token, salt='email-update', max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('dashboard'))

    current_email, new_email = email_data
    user = User.query.filter_by(email=current_email).first_or_404()

    # Update email
    user.email = new_email
    db.session.commit()
    flash('Your email has been updated successfully!', 'success')
    return redirect(url_for('dashboard'))



@app.route('/start-trading/', methods=['GET', 'POST'])
def auth():
    if request.method == 'POST':
        if 'signup' in request.form:
            alias = request.form.get('alias')
            email = request.form.get('email')
            password = request.form.get('password')
            re_password = request.form.get('re_password')
            referral_code = request.form.get('referral_code')

            if password == re_password:
                existing_email = User.query.filter_by(email=email).first()
                existing_alias = User.query.filter_by(alias=alias).first()
                if existing_email is None and existing_alias is None:
                    user = User(alias=alias, email=email)
                    user.set_password(password)
                    user.generate_referral_code()  # Generate a unique referral code

                    if referral_code:
                        user.referred_by = referral_code  # Store the referral code of the referrer
                        User.increment_referral_count(referral_code)  # Increment referral count for referrer

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


@app.route('/connect_wallet', methods=['POST'])
def connect_wallet():
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    if user:
        data = request.get_json()
        api_key = data.get('api_key')
        api_secret = data.get('api_secret')

        # Validate the fields
        if not api_key or not api_secret:
            return jsonify({"success": False, "message": "API key or secret missing."}), 400

        try:
            # Save API credentials to the database
            user.api_key = api_key
            user.api_secret = api_secret
            db.session.commit()

            return jsonify({"success": True, "message": "Connected successfully."})
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": str(e)}), 500
    else:
        return jsonify({"success": False, "message": "User not authenticated."}), 401

@app.route('/change_api_credentials', methods=['POST'])
def change_api_credentials():
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    if user:
        data = request.get_json()
        api_key = data.get('api_key')
        api_secret = data.get('api_secret')

        # Validate the fields
        if not api_key or not api_secret:
            return jsonify({"success": False, "message": "API key or secret missing."}), 400

        try:
            # Update API credentials in the database
            user.api_key = api_key
            user.api_secret = api_secret
            db.session.commit()

            return jsonify({"success": True, "message": "API credentials updated successfully."})
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": str(e)}), 500
    else:
        return jsonify({"success": False, "message": "User not authenticated."}), 401
@app.route('/wallet_control/')
def wallet_control():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    return render_template('users/wallet_control.html', user=user)

@app.route('/forgot-password/', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)

            subject = "Password Reset Request"
            body = f"Hi {user.alias},\n\nClick the link below to reset your password:\n{reset_url}\n\nIf you didn't request a password reset, please ignore this email."

            msg = Message(subject, 
                          sender=app.config['MAIL_USERNAME'], 
                          recipients=[email])
            msg.body = body

            try:
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
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
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
