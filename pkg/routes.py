from flask import Flask, render_template, url_for, redirect, request, session, flash
from pkg import app

# #custom errors
# @app.errorhandler(404)
# def not_found_error(error):
#     return render_template('page404.html')

@app.route('/')
def index():
    return render_template('users/index.html')

@app.route('/dashboard/')
def dashboard():
    return render_template('users/dashboard.html')

@app.route('/start-trading/')
def auth():
    return render_template('users/auth.html')
