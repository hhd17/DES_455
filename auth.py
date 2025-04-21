from datetime import datetime, timezone, timedelta
import jwt
from flask import Blueprint, make_response, redirect, url_for, render_template, request, current_app, jsonify

from extensions import db, bcrypt
from models import User, History

# Create a Flask Blueprint for authentication routes
auth_bp = Blueprint('auth', __name__)


# Function to generate a JWT token
def generate_token(username, user_id):
    payload = {
        'username': username,
        'user_id': user_id,
        'exp': datetime.now(timezone.utc) + timedelta(hours=1)  # Token expires in 1 hour
    }
    token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
    print('Generated Token:', token)  # Debug line to see token in console
    return token


# Register route (GET = show form, POST = handle form submission)
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error='User already exists')

        # Hash the password and create a new user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('auth.login'))  # Redirect to login after registering

    return render_template('register.html')  # Show registration form


# Login route (GET = form, POST = process login)
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        username = data['username']
        password = data['password']

        # Get user from database and check password
        user = User.query.filter_by(username=username).first()
        if not user or not bcrypt.check_password_hash(user.password, password):
            return render_template('login.html', error='Invalid credentials')

        # Generate token and set it as cookie
        token = generate_token(user.username, user.id)
        response = redirect(url_for('index'))
        response.set_cookie('token', token)
        response.set_cookie('username', username)
        return response

    return render_template('login.html')  # Show login form


# Logout route - clear the cookies
@auth_bp.route('/logout')
def logout():
    response = make_response(render_template('index.html'))  # Return to home page
    response.delete_cookie('token')  # Remove token cookie
    return response


# Route to fetch and display user encryption/decryption history
@auth_bp.route('/history', methods=['GET'])
def get_history():
    # Get JWT token from cookies
    token = request.cookies.get('token').split()[0]

    try:
        # Decode token to get user info
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload['username']

        # Find the user
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Fetch user's encryption/decryption history
        history = History.query.filter_by(user_id=user.id).all()

        # Render history template with user's data
        return render_template('history.html', history=history)

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401