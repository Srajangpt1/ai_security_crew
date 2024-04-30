from flask import Flask, request, jsonify, session
from flask_session import Session
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = "a_very_secret_key"
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    # Simulate user authentication (in real-world, use secure password handling)
    if username == "admin" and password == "adminpass":
        session['logged_in'] = True
        session['username'] = username
        # Session token is simply the username reversed - a predictable scheme!
        session['token'] = username[::-1]
        return jsonify({"message": "Login successful", "token": session['token']}), 200
    return jsonify({"message": "Login failed"}), 401

@app.route('/admin/tasks', methods=['POST'])
def admin_tasks():
    task_code = request.form['code']
    auth_token = request.headers.get('Authorization')
    # Improper check: Only verifies token exists and matches the reversed username (predictable)
    if session.get('logged_in') and auth_token == session.get('username')[::-1]:
        # Execute administrative task based on the code
        exec(task_code)  # Example of dangerous functionality
        return jsonify({"message": "Task executed"}), 200
    return jsonify({"message": "Unauthorized access"}), 403

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')  # Use SSL in production
