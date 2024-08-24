import random
import string
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alias = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(225), nullable=False)
    api_key = db.Column(db.String(225), nullable=True)  
    api_secret = db.Column(db.String(225), nullable=True)  
    trading_capital = db.Column(db.Float, nullable=True) 
    leverage = db.Column(db.Integer, nullable=True)
    referral_code = db.Column(db.String(10), unique=True, nullable=True)  # New column for referral code
    referred_by = db.Column(db.String(10), nullable=True)  # New column to store who referred the user
    referral_count = db.Column(db.Integer, default=0)  # New column to track the number of referrals

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def generate_referral_code(self):
        self.referral_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        
    def set_api_credentials(self, api_key, api_secret):
        self.api_key = generate_password_hash(api_key)
        self.api_secret = generate_password_hash(api_secret)

    def check_api_credentials(self, api_key, api_secret):
        return check_password_hash(self.api_key, api_key) and check_password_hash(self.api_secret, api_secret)

    @staticmethod
    def increment_referral_count(referral_code):
        referrer = User.query.filter_by(referral_code=referral_code).first()
        if referrer:
            referrer.referral_count += 1
            db.session.commit()

class Symbol(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(10), unique=True, nullable=False)

    def __repr__(self):
        return f'<Symbol {self.name}>'

