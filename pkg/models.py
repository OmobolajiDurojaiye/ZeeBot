import random
import string
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    alias = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(225), nullable=False)
    api_key = db.Column(db.String(225), nullable=True)
    api_secret = db.Column(db.String(225), nullable=True)
    referral_code = db.Column(db.String(10), unique=True, nullable=True)
    referred_by = db.Column(db.String(10), nullable=True)
    referral_count = db.Column(db.Integer, default=0)
    
    # Relationships
    trades = db.relationship('Trade', backref='user', lazy=True)
    actions = db.relationship('UserAction', backref='user', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def generate_referral_code(self):
        self.referral_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

    @staticmethod
    def increment_referral_count(referral_code):
        referrer = User.query.filter_by(referral_code=referral_code).first()
        if referrer:
            referrer.referral_count += 1
            db.session.commit()


class Symbol(db.Model):
    __tablename__ = 'symbol'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    
    trades = db.relationship('Trade', backref='symbol', lazy=True)
    actions = db.relationship('UserAction', backref='symbol', lazy=True)

    def __repr__(self):
        return f'<Symbol {self.name}>'


class Leverage(db.Model):
    __tablename__ = 'leverage'
    
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.Integer, nullable=False)

    trades = db.relationship('Trade', backref='leverage', lazy=True)
    actions = db.relationship('UserAction', backref='leverage', lazy=True)

    def __repr__(self):
        return f'<Leverage {self.value}>'


class Trade(db.Model):
    __tablename__ = 'trade'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    symbol_id = db.Column(db.Integer, db.ForeignKey('symbol.id'), nullable=False)
    leverage_id = db.Column(db.Integer, db.ForeignKey('leverage.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<Trade {self.amount} {self.symbol.name}>'


class UserAction(db.Model):
    __tablename__ = 'user_action'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)
    symbol_id = db.Column(db.Integer, db.ForeignKey('symbol.id'), nullable=True)
    leverage_id = db.Column(db.Integer, db.ForeignKey('leverage.id'), nullable=True)
    amount = db.Column(db.Float, nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<UserAction {self.action_type}>'


# Helper function to create or find a symbol
def get_or_create_symbol(symbol_name):
    symbol = Symbol.query.filter_by(name=symbol_name).first()
    if not symbol:
        symbol = Symbol(name=symbol_name)
        db.session.add(symbol)
        db.session.commit()
    return symbol

# Helper function to create or find leverage
def get_or_create_leverage(leverage_value):
    leverage = Leverage.query.filter_by(value=leverage_value).first()
    if not leverage:
        leverage = Leverage(value=leverage_value)
        db.session.add(leverage)
        db.session.commit()
    return leverage
