from flask import Flask, render_template, url_for, redirect, request, session, flash, jsonify
from pkg import app
from pkg.models import db, User, Symbol, Trade, UserAction, get_or_create_symbol, get_or_create_leverage
from datetime import datetime, timedelta
from functools import wraps
# import threading
# import trading_logic
# from trading_logic import live_trading, stop_trading_logic, close_all_positions, set_trading_capital,calculate_amount_out,get_active_position
from itsdangerous import URLSafeTimedSerializer
from flask_wtf import FlaskForm
from wtforms import DecimalField, SubmitField
from flask_mail import Mail, Message
from wtforms.validators import DataRequired, NumberRange
# from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.exceptions import BadRequest
# from pybit.unified_trading import HTTP 
import logging
from flask import current_app 
# from pkg.volume import get_ticker_info, HIGH_TURNOVER_RATIO_MULTIPLIER,LOW_TURNOVER_RATIO_MULTIPLIER
from threading import Lock
from flask_wtf.csrf import CSRFProtect, validate_csrf, CSRFError, generate_csrf

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=2)
# trading_lock = threading.Lock()
mail = Mail(app)

HOST = 'api-demo.bybit.com'

# Initialize a lock for thread synchronization
# trading_lock = Lock()
csrf = CSRFProtect(app)

# Global variable to keep track of trading state
is_trading_active = False
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
def login_required(f):
    @wraps(f)
    def check_login(*args,**kwargs):
        if session.get('user_id') !=None:
          return  f(*args,**kwargs)

        else:
            flash('You must be logged in to access this page', 'danger')
            return redirect('/auth/')
    return check_login

def trading_thread_function(app, user_id, selected_symbol, amount, leverage):
    try:
        with app.app_context():
            live_trading(user_id, selected_symbol, amount, leverage)
            # Notify user when trading starts
            logging.info(f'Trading started for {selected_symbol} with amount {amount} and leverage {leverage}')
            # Notify user via UI here or update the status
    except Exception as e:
        logging.error(f"Trading Error: {str(e)}")
        # Handle trading errors here gracefully (you can log or notify via other means)
        pass


@app.route('/how-to-use/')
def howToUse():
    descriptions = [
        "In the navbar at the top, click Let's Trade Now",
        "Fill in the signup form to create a new account, if a new account has been created",
        "Click the log in button at the top right and fill in the form",
        "This is your dashboard",
        "Enter your API key and API secret, after which you click on the connect wallet button",
        "Once that is done, you'll see a proceed to wallet control button, click it",
        "Click on start and trading starts!",
        "Before that, make sure you have your symbol set",
        "You can find the set symbol at the sidebar of your dashboard",
        "Select your leverage by dragging the blue line to set a fixed leverage ranging from 1-10",
        "You can also find the leverage at the sidebar on your dashboard",
        "Click on your name in the dashboard to update your API key, API secret, and Email if needed"
    ]
    return render_template('users/howtouse.html', descriptions=descriptions)


@app.route('/get_new_csrf_token', methods=['GET'])
def get_new_csrf_token():
    try:
        new_csrf_token = generate_csrf()
        return jsonify({'success': True, 'new_csrf_token': new_csrf_token}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/select-symbol', methods=['POST'])
@login_required
def select_symbol():
    selected_symbol = request.json.get('symbol')

    if selected_symbol:
        session['selected_symbol'] = selected_symbol
        user_id = session.get('user_id')

        try:
            current_turnover, current_volume, last_price = get_ticker_info(user_id, selected_symbol)

            if current_turnover is None or current_volume is None or last_price is None:
                flash(f'Symbol {selected_symbol} selected, but unable to fetch ticker info.', 'warning')
                return jsonify({'message': f'Symbol {selected_symbol} selected, but volume analysis failed.', 'category': 'warning'}), 200

            normalized_turnover_ratio = current_turnover / current_volume
            high_turnover_threshold = normalized_turnover_ratio * HIGH_TURNOVER_RATIO_MULTIPLIER
            low_turnover_threshold = normalized_turnover_ratio * LOW_TURNOVER_RATIO_MULTIPLIER

            if normalized_turnover_ratio >= high_turnover_threshold:
                volume_status = 'high'
                message = f"Volume is high for {selected_symbol}."
                flash(message, 'success')  # Categorized as success
            elif normalized_turnover_ratio <= low_turnover_threshold:
                volume_status = 'low'
                message = f"Volume is low for {selected_symbol}."
                flash(message, 'danger')  # Categorized as danger
            else:
                volume_status = 'moderate'
                message = f"Volume is moderate for {selected_symbol}. You may proceed."
                flash(message, 'info')  # Categorized as info

            return jsonify({'message': f'Symbol {selected_symbol} selected. {message}', 'volume_status': volume_status, 'category': volume_status}), 200

        except Exception as e:
            logging.error(f"Error during symbol selection and volume analysis: {e}")
            flash('An error occurred during volume analysis.', 'danger')
            return jsonify({'error': 'An error occurred during symbol selection and volume analysis.', 'category': 'danger'}), 500
    else:
        flash('No symbol selected', 'danger')
        return jsonify({'error': 'No symbol selected', 'category': 'danger'}), 400


@app.route('/select-symbol', methods=['GET'])
@login_required
def get_symbols():
    symbols = Symbol.query.all()
    symbol_list = [{'name': symbol.name} for symbol in symbols]
    return jsonify(symbol_list)

@app.route('/symbols', methods=['GET', 'POST'])
@login_required
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

@app.route('/check_active_trade', methods=['GET'])
@login_required
def check_active_trade():
    # Check session or database flag for active trade
    is_active = session.get('is_trading_active', False) or is_trading_active
    return jsonify({'is_active': is_active})


@app.route('/start_trading', methods=['POST'])
@login_required
def start_trading():
    global trading_thread
    global is_trading_active

    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'status': 'error', 'message': 'User not authenticated. Please log in.'}), 401  # Unauthorized

        # Retrieve form data or session data
        selected_symbol = request.form.get('symbol') or session.get('selected_symbol')
        amount = request.form.get('amount') or session.get('amount')
        leverage = request.form.get('leverage') or session.get('leverage')

        # Validate input parameters before any further logic
        if not selected_symbol:
            return jsonify({'status': 'error', 'message': 'Please select a symbol before starting trading.'}), 400
        if not amount:
            return jsonify({'status': 'error', 'message': 'Please input a trading amount before starting trading.'}), 400
        if not leverage:
            return jsonify({'status': 'error', 'message': 'Please set leverage before starting trading.'}), 400

        # Debugging logs to check the state of trading
        logging.info(f"is_trading_active: {is_trading_active}, session is_trading_active: {session.get('is_trading_active', False)}")
        logging.info(f"Received symbol: {selected_symbol}, amount: {amount}, leverage: {leverage}")

        # Correctly check if trading is already running
        with trading_lock:
            # Check both global and session state
            if is_trading_active or session.get('is_trading_active', False):
                logging.warning("Attempted to start trading when already active.")
                return jsonify({'status': 'warning', 'message': 'Trading is already running.'}), 409  # Conflict

        # Proceed with setting up trading
        try:
            amount = float(amount)
            if amount <= 0:
                return jsonify({'status': 'error', 'message': 'Amount must be greater than 0.'}), 400
        except ValueError as e:
            return jsonify({'status': 'error', 'message': f'Invalid amount: {str(e)}'}), 400

        try:
            leverage = int(leverage)
            if leverage <= 0:
                return jsonify({'status': 'error', 'message': 'Leverage must be greater than 0.'}), 400
        except ValueError as e:
            return jsonify({'status': 'error', 'message': f'Invalid leverage: {str(e)}'}), 400

        # Store amount and leverage in session
        session['amount'] = amount
        session['leverage'] = leverage

        # Retrieve or create symbol and leverage objects
        symbol = get_or_create_symbol(selected_symbol)
        leverage_obj = get_or_create_leverage(leverage)

        # After checking and starting the trading logic
        if trading_thread is None or not trading_thread.is_alive():
            if hasattr(trading_logic, 'set_parameters'):
                trading_logic.set_parameters(symbol=selected_symbol, leverage=leverage)

            # Pass the app instance to the thread function
            trading_thread = threading.Thread(target=trading_thread_function, args=(app, user_id, selected_symbol, amount, leverage))
            trading_thread.start()

            # Additional logging to confirm thread start
            logging.info("Trading thread started successfully.")

            # Create a new trade entry
            new_trade = Trade(user_id=user_id, symbol_id=symbol.id, leverage_id=leverage_obj.id, amount=amount)
            db.session.add(new_trade)

            # Log user action
            user_action = UserAction(user_id=user_id, action_type='start_trade', symbol_id=symbol.id, leverage_id=leverage_obj.id, amount=amount)
            db.session.add(user_action)

            # Commit the transaction
            db.session.commit()

            # Set trading active flag to True
            is_trading_active = True
            session['is_trading_active'] = True  # Ensure session is also updated
            logging.info(f"Trading started for user {user_id} with symbol {selected_symbol}, amount {amount}, leverage {leverage}. is_trading_active: {is_trading_active}, session is_trading_active: {session['is_trading_active']}")

            return jsonify({'status': 'success', 'message': f'Trading started for {selected_symbol} with amount {amount} and leverage {leverage}.'}), 200  # OK
        else:
            logging.warning("Trading thread already active.")
            return jsonify({'status': 'warning', 'message': 'Trading is already running.'}), 409  # Conflict

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error in start_trading: {str(e)}")
        return jsonify({'status': 'error', 'message': 'An unexpected error occurred while trying to start trading.'}), 500  # Internal Server Error


@app.route('/stop-trading', methods=['POST'])
@login_required
def stop_trading():
    global trading_thread  # Ensure we modify the global variable
    global is_trading_active  # Ensure we modify the global variable

    try:
        # Ensure request content type is application/json
        if request.content_type != 'application/json':
            return jsonify({"status": "error", "message": "Unsupported Media Type"}), 415

        with current_app.app_context():
            data = request.get_json()

            # Validate if user_id is present
            if data and 'user_id' in data:
                user_id = data.get('user_id')
                logging.info(f"Request received to stop trading for user_id={user_id}")

                # Stop trading logic and reset flags
                stop_trading_logic(user_id)  # Call stop trading logic

                # Explicitly reset the is_trading_active flag
                session['is_trading_active'] = False
                is_trading_active = False

                # Reset the trading_thread to None
                trading_thread = None  # Reset the thread status
                logging.info(f"Trading thread reset to None for user_id={user_id}.")

                return jsonify({"status": "success", "message": "Trading stopped successfully."}), 200
            else:
                return jsonify({"status": "error", "message": "Missing user_id in request."}), 400

    except Exception as e:
        logging.error(f"Error stopping trading: {str(e)}")
        return jsonify({"status": "error", "message": "An error occurred while stopping trading."}), 500



@app.route('/select-leverage', methods=['POST'])
@login_required
def select_leverage():
    with current_app.app_context():
        data = request.get_json()

        # Handle dynamic form loading request
        if not data or data.get('action') == 'fetch_content':
            csrf_token = generate_csrf()  # Generate a new CSRF token
            content = f'''
            <div id="flash-messages"></div>
            <form method="POST" action="/select-leverage" class="token-form" id="leverageForm">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <div class="form-group">
                  <label for="rangeInput">Select your leverage (1-10):</label>
                  <input type="range" class="form-control-range" id="rangeInput" name="leverage" min="1" max="10" value="1">
                </div>
                <div class="form-group">
                  <label for="numberDisplay">Selected Leverage:</label>
                  <input type="number" class="form-control" id="numberDisplay" value="1" readonly>
                </div>
                <button type="button" class="btn btn-primary" id="submitLeverage">Set Leverage</button>
            </form>
            '''
            return jsonify({'success': True, 'content': content}), 200

        # Validate CSRF token for form submission
        try:
            csrf_token = request.headers.get('X-CSRFToken')
            validate_csrf(csrf_token)
        except CSRFError as e:
            return jsonify({'success': False, 'message': f'CSRF token error: {str(e)}'}), 400

        # Process leverage setting
        selected_leverage = data.get('leverage')
        if selected_leverage:
            session['leverage'] = selected_leverage
            user_id = session.get('user_id')

            if user_id:
                user = User.query.get(user_id)
                if user:
                    user.leverage = int(selected_leverage)
                    db.session.commit()
                    trading_logic.LEVERAGE = user.leverage

                    # Flash a message and redirect to dashboard after success
                    flash(f'Leverage set to {selected_leverage}.', 'success')
                    return jsonify({
                        'success': True,
                        'message': f'Leverage set to {selected_leverage}',
                        'redirect': url_for('dashboard')  # URL to redirect after successful form submission
                    }), 200
                else:
                    return jsonify({'success': False, 'message': 'User not found.'}), 404
            else:
                return jsonify({'success': False, 'message': 'User not authenticated.'}), 401
        else:
            return jsonify({'success': False, 'message': 'No leverage selected'}), 400
      
@app.route('/set_amount', methods=['POST'])
@login_required
def set_amount():
    with current_app.app_context():
        try:
            csrf_token = request.headers.get('X-CSRFToken')
            validate_csrf(csrf_token)  # Validate the CSRF token manually

            data = request.get_json()  # Attempt to parse JSON data
            if not data:
                return jsonify({'success': False, 'message': 'No data provided'}), 400

            action = data.get('action')  # Retrieve 'action' to distinguish request type

            if action == 'fetch_content':
                # Generate a new CSRF token for the dynamically loaded form
                csrf_token = generate_csrf()
                print(f"CSRF token generated for set_amount: {csrf_token}")  # Debug print

                # Return HTML content as a JSON response
                content = f'''
                <div id="flash-messages"></div>
                <form method="POST" action="/set_amount" class="token-form" id="tradeForm">
                    <input type="hidden" name="csrf_token" value="{csrf_token}">
                    <h2>Amount To Trade</h2>
                    <div class="form-group">
                        <label for="tradeAmountInput">Enter the amount you want to trade:</label>
                        <input type="number" class="form-control" id="tradeAmountInput" value="10000" />
                    </div>
                    <button type="button" class="btn btn-primary" id="submitTradeAmount">Set Amount</button>
                </form>
                <div class="navigation-buttons" id="navigationButtons"></div>
                '''
                return jsonify({'success': True, 'content': content}), 200

            # Process the amount submission
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

                            # Flash a message and return response after success
                            flash(f'Amount set to {amount}.', 'success')
                            return jsonify({'success': True, 'message': 'Amount set successfully!'}), 200
                        else:
                            db.session.rollback()
                            return jsonify({'success': False, 'message': 'User not found.'}), 404
                    else:
                        return jsonify({'success': False, 'message': 'Error setting the amount.'}), 500
                else:
                    return jsonify({'success': False, 'message': 'User not authenticated.'}), 401
            else:
                return jsonify({'success': False, 'message': 'Invalid amount provided.'}), 400

        except CSRFError as e:
            return jsonify({'success': False, 'message': f'CSRF token error: {str(e)}'}), 400

        except Exception as e:
            # Handle JSON parsing error
            return jsonify({'success': False, 'message': f'Failed to decode JSON object: {e}'}), 400

@app.route('/')
@app.route('/index/')
def index():
    # background_image = url_for('static', filename='images/index-background.jpg')
    return render_template('index.html')


@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    # Check if the API credentials are already set
    api_credentials_set = bool(user.api_key and user.api_secret)

    return render_template('users/dashboard.html', user=user, api_credentials_set=api_credentials_set)

def send_confirmation_email(user, new_email):
    #na the token wey the user go use change email be this, e go do am auto
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    token = serializer.dumps([user.email, new_email], salt='email-update')

    # na the configuration email be this
    msg = Message("Confirm Your Email Change", sender=app.config['MAIL_USERNAME'], recipients=[user.email])
    link = url_for('confirm_email_change', token=token, _external=True)
    msg.body = f"Hi {user.alias},\n\nTo confirm your email change to {new_email}, please click the link below:\n{link}\n\nIf you didn't request this change, please ignore this email."
    mail.send(msg)

@app.route('/profile/<alias>', methods=['GET', 'POST'])
def profile(alias):
    try:
        user = User.query.filter_by(alias=alias).first_or_404()

        if request.method == 'POST':
            new_email = request.form['email']
            if new_email != user.email:
                # Send confirmation email if the email has changed
                send_confirmation_email(user, new_email)
                flash('A confirmation link has been sent to your current email address. Please confirm to update your email.', 'info')
                return redirect(url_for('profile', alias=alias))

            # Update API credentials if provided
            if request.form['api_key'] and request.form['api_secret']:
                user.set_api_credentials(request.form['api_key'], request.form['api_secret'])

            # Commit the changes to the database
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('dashboard'))

        return render_template('users/user_profile.html', user=user)

    except Exception as e:
        db.session.rollback()
        flash('An error occurred while updating the profile. Please try again.', 'danger')
        # Optional: log the exception for debugging purposes
        app.logger.error(f"Error updating profile for {alias}: {e}")
        return redirect(url_for('profile', alias=alias))

@app.route('/confirm_email_change/<token>')
def confirm_email_change(token):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email_data = serializer.loads(token, salt='email-update', max_age=3600)
        current_email, new_email = email_data
        user = User.query.filter_by(email=current_email).first_or_404()

        # Update the user's email
        user.email = new_email
        db.session.commit()
        flash('Your email has been updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    except Exception as e:
        db.session.rollback()
        flash('The confirmation link is invalid, has expired, or another error occurred.', 'danger')
        # Optional: log the exception for debugging purposes
        app.logger.error(f"Error confirming email change: {e}")
        return redirect(url_for('dashboard'))

@app.route('/execute_trade', methods=['POST', 'GET'])
def execute_trade():
    # Sample logic for trade execution
    trade_amount = get_trade_amount()  # Example function to get the trade amount   
    # Trade execution logic here...
    flash("Trade executed successfully!", "success")
    return redirect(url_for('wallet_control'))

# @app.route('/get_trade_reports', methods=['GET'])
# def get_trade_reports():
#     user_id = get_current_user_id()  # Example function to get current user ID
#     trade_reports = fetch_trade_reports(user_id)  # Fetch trade reports from the database
    
#     return jsonify(trade_reports)
# def fetch_trade_reports(user_id):
#     """
#     Fetches the trades associated with a specific user.
#     """
#     try:
#         # Get all trades for the user ordered by timestamp
#         trade_reports = Trade.query.filter_by(user_id=user_id).order_by(Trade.timestamp.desc()).all()
#         return trade_reports
#     except Exception as e:
#         print(f"Error fetching trade reports for user {user_id}: {e}")
#         return []

def get_current_user_id():
    """
    Returns the ID of the currently authenticated user using session data.
    """
    user_id = session.get('user_id')
    if user_id:
        return user_id
    return None


def get_trade_amount(trade):
    """
    Returns the amount of a trade.
    """
    return trade.amount



@app.route('/auth/', methods=['GET', 'POST'])
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
                db.session.rollback()
                flash('Invalid email or password.', 'danger')
    return render_template('users/auth.html')


@app.route('/get_position', methods=['GET'])
@login_required
def get_position():
    try:
        user_id = session.get('user_id')
        symbol = session.get('selected_symbol')  # Fetch symbol from session

        # Debug log to check if symbol is in session
        logging.info(f"Fetching position for user_id: {user_id}, symbol: {symbol}")

        if not symbol:
            return jsonify({'success': False, 'message': 'No symbol found in session.'}), 400

        position = get_active_position(user_id, symbol)
        if position:
            return jsonify({
                'success': True,
                'position': {
                    'symbol': position['symbol'],
                    'size': position['size'],
                    'markPrice': position['markPrice'],
                    'unrealizedPnl': position['unrealisedPnl'],
                    'side': position['side']
                }
            }), 200
        else:
            logging.warning(f"No active position found or error occurred for user_id: {user_id}, symbol: {symbol}")
            return jsonify({'success': False, 'message': 'No active position found or error occurred.'}), 404
    except Exception as e:
        logging.error(f"Error in get_position: {e}")
        return jsonify({'success': False, 'message': 'An error occurred while fetching the position.'}), 500

                
@app.route('/connect_wallet', methods=['POST', 'GET'])
@login_required
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
@login_required
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

@app.route('/wallet_control/', methods=['POST', 'GET'])
@login_required
def wallet_control():
    if request.content_type == 'application/json':
        data = request.get_json()

        if not data or data.get('action') == 'fetch_content':
            csrf_token = generate_csrf()  # Generate a new CSRF token
            content = render_template('users/wallet_control.html', user=session.get('user'))

            return jsonify({'success': True, 'content': content}), 200

        # Handle any other JSON post requests for the wallet control page as needed
        return jsonify({'success': False, 'message': 'Invalid request'}), 400

    elif request.content_type == 'application/x-www-form-urlencoded':

        user_id = session.get('user_id')
        user = User.query.get(user_id)

        # Render the wallet control page as HTML for direct form submissions
        return render_template('users/wallet_control.html', user=user)

    else:
        # Unsupported Media Type
        return jsonify({'success': False, 'message': 'Unsupported Media Type'}), 415

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
            db.session.rollback()
            flash('Passwords do not match.', 'danger')
    
    return render_template('users/reset_password.html')



@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth'))


@app.route('/auto_logout', methods=['GET'])
@login_required
def auto_logout():
    user_id = session.get('user_id')

    # Check if the user is trading using a session flag or database query
    is_trading = session.get('is_trading', False)  # Or query from the database

    # Preserve essential trading-related data in session before logging out
    trading_settings = {
        'is_trading': is_trading,
        'symbol': session.get('symbol'),
        'leverage': session.get('leverage'),
        'amount': session.get('amount'),
        'wallet_control': session.get('wallet_control')
    }

    if is_trading:
        # Log the user out of the session but continue trading
        session.clear()  # Clear all session data
        session.update(trading_settings)  # Restore essential trading data
        flash('You have been logged out due to inactivity, but your trading will continue.', 'info')
        # Indicate a logout with continuation of trading
        return jsonify({'success': True, 'message': 'You have been logged out due to inactivity, but your trading will continue.', 'redirect': False})
    else:
        # Normal logout process
        session.clear()  # Clear all session data
        flash('You have been logged out due to inactivity.', 'info')
        # Indicate a logout with redirection
        return jsonify({'success': True, 'message': 'You have been logged out due to inactivity.', 'redirect': True, 'redirect_url': url_for('login')})

@app.route('/get_trade_reports', methods=['GET'])
def get_trade_reports(close_price=None, qty=None, side=None):
    user_id = get_current_user_id()  # Example function to get the current user ID
    trade_reports = fetch_trade_reports(user_id, close_price, qty, side)  # Fetch trade reports from the database
    
    # Convert trade reports to JSON format
    return jsonify(trade_reports)

def trade_to_dict(trade):
    """
    Converts a Trade object into a dictionary.
    """
    return {
        'id': trade.id,
        'user_id': trade.user_id,
        'symbol': trade.symbol.name,  # Access related symbol's name
        'leverage': trade.leverage.value,  # Access related leverage's value
        'amount': trade.amount,
        'timestamp': trade.timestamp.strftime('%Y-%m-%d %H:%M:%S'),  # Format timestamp as a string
    }
def fetch_trade_reports(user_id, close_price, qty, side):
    """
    Fetches the trades associated with a specific user and converts them to a dictionary format.
    """
    try:
        # Fetch only executed trades for the user
        trades = Trade.query.filter_by(user_id=user_id).filter(Trade.status == 'executed').order_by(Trade.timestamp.desc()).all()

        trade_reports = []
        for trade in trades:
            # Ensure trade has valid data
            if not trade.side or trade.side not in ['Buy', 'Sell']:
                logging.error(f"Invalid trade side: {trade.side}")
                continue

            trade_report = {
                'id': trade.id,
                'symbol': trade.symbol.name,
                'leverage': trade.leverage.value,
                'amount_in': trade.amount,
                'amount_out': calculate_amount_out(close_price, qty, trade.side),
                'profit_loss': calculate_profit_loss(trade, close_price, qty, trade.side),
                'reason_for_closure': determine_closure_reason(trade, close_price, qty, trade.side),
                'timestamp': trade.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            }
            trade_reports.append(trade_report)

        return trade_reports
    except Exception as e:
        logging.error(f"Error fetching trade reports for user {user_id}: {e}")
        return []


def calculate_profit_loss(trade,close_price, qty, side):
    """
    Calculates profit or loss for a trade.
    """
    # Placeholder logic for profit/loss calculation
    amount_out = calculate_amount_out(close_price, qty, side)
    profit_loss = amount_out - trade.amount
    return round(profit_loss, 2)
def determine_closure_reason(trade,close_price, qty, side):
    """
    Determines the reason for trade closure.
    """
    # Placeholder logic to determine reason for closure
    if trade.amount >= calculate_amount_out(close_price, qty, side):
        return "Target met"
    else:
        return "Manually closed by user"

def get_user_balance(user_id):
    """
    Fetch the user's balance from the exchange.
    """
    user = User.query.get(user_id)
    if not user or not user.api_key or not user.api_secret:
        logging.error("API credentials not found for user")
        return None

    try:
        client = HTTP(
            testnet=False,  # Set to True if using testnet
            api_key=user.api_key,
            api_secret=user.api_secret,
            recv_window=10000
        )
        
        response = client.get_wallet_balance()
        if response['retCode'] == 0:  # Assuming 0 indicates success
            return response['result']['wallet_balance']
        else:
            logging.error(f"Failed to fetch balance: {response['retMsg']}")
            return None
    except Exception as e:
        logging.error(f"Error fetching balance for user {user_id}: {e}")
        return None
    
def send_daily_reports(close_price, qty, side):
    """
    Sends daily trade reports to all users via email.
    """
    users = User.query.all()  # Fetch all users from the database
    
    for user in users:
        trade_reports = fetch_trade_reports(user.id, close_price, qty, side)
        
        # Skip sending emails if no trades were executed
        if not trade_reports:
            logging.info(f"No trades executed for user {user.alias}. Skipping email report.")
            continue

        # Format the email body with trade report data
        email_body = format_trade_report(trade_reports, user)

        # Send the email to the user
        msg = Message('Your Daily Trade Report',
                      sender='zeecryptobot@gmail.com',
                      recipients=[user.email])
        msg.body = email_body
        
        try:
            mail.send(msg)
            logging.info(f"Successfully sent daily report to {user.email}")
        except Exception as e:
            logging.error(f"Error sending email to {user.email}: {e}")

def format_trade_report(trades, user):
    """
    Formats the trade report into a string to be sent via email.
    """
    if not trades:
        return f"Hi {user.alias},\n\nNo trading activity was recorded for today.\n\nBest regards,\nZeeCryptoBot"

    report = f"Hi {user.alias},\n\nHere is your daily trade report:\n\n"
    report += "Trade ID | Symbol | Leverage | Amount In | Amount Out | Profit/Loss | Closure Reason | Date\n"
    report += "-" * 90 + "\n"

    for trade in trades:
        report += (f"{trade['id']} | {trade['symbol']} | {trade['leverage']} | "
                   f"{trade['amount_in']} | {trade['amount_out']} | {trade['profit_loss']} | "
                   f"{trade['reason_for_closure']} | {trade['timestamp']}\n")
    
    report += "\nThank you for using ZeeCryptoBot. Happy trading!\n\nBest regards,\nZeeCryptoBot Team"
    return report
