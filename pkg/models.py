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

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def set_api_credentials(self, api_key, api_secret):
        self.api_key = generate_password_hash(api_key)
        self.api_secret = generate_password_hash(api_secret)

    def check_api_credentials(self, api_key, api_secret):
        return check_password_hash(self.api_key, api_key) and check_password_hash(self.api_secret, api_secret)