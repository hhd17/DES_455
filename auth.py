from flask import Blueprint, make_response, request, redirect, render_template, jsonify, url_for, current_app
import jwt
import datetime
from models import User, History
from extensions import db, bcrypt

auth_bp = Blueprint('auth', __name__)

def generate_token(username, user_id):
    payload = {
        'username': username,
        'user_id': user_id,  # Include user ID in the payload
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
    
    print("Generated Token:", token)  # Debugging line to verify token value
    return token


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error='User already exists')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('auth.login'))

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        username = data['username']
        password = data['password']

        user = User.query.filter_by(username=username).first()
        if not user or not bcrypt.check_password_hash(user.password, password):
            return render_template('login.html', error='Invalid credentials')

        token = generate_token(user.username, user.id) 
        response = redirect(url_for('index'))
        response.set_cookie('token', token)
        response.set_cookie('username', username)
        return response

    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    # Create a response object to send back to the client
    response = make_response(render_template('index.html'))

    # Remove the token by clearing the cookie (set to empty value and expired)
    response.delete_cookie('token')

    return response


from flask import render_template, request, current_app, jsonify
import jwt
from models import User, History

@auth_bp.route('/history', methods=['GET'])
def get_history():
    # Try to retrieve the token from the request headers
    token = request.cookies.get('token').split()[0]
    
    try:
        # Decode the token
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
        username = payload['username']
        
        # Fetch the user from the database
        user = User.query.filter_by(username=username).first()

        # If user not found, return an error
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Fetch the history data for the user
        history = History.query.filter_by(user_id=user.id).all()
        
        # Pass history data to the template
        return render_template('history.html', history=history)

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

