# --- Imports --- #
import os
import re
import uuid
from datetime import datetime, timezone, timedelta

import jwt
from flask import Blueprint, make_response, redirect, url_for, render_template, request, current_app, jsonify
from flask import flash
from flask import send_from_directory
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.utils import secure_filename

from extensions import db, bcrypt
from models import User, History

# --- Constants --- #
# Regex to enforce strong password requirements
PASSWORD_RE = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$'
)

# Directory settings for user avatars
BASE_DIR = os.path.dirname(__file__)
AVATAR_FOLDER = os.path.join(BASE_DIR, 'static', 'img', 'avatars')
os.makedirs(AVATAR_FOLDER, exist_ok=True)

# Allowed image extensions for avatar uploads
ALLOWED_IMG = {'png', 'jpg', 'jpeg'}

# --- Blueprint --- #
# Create a Flask Blueprint for authentication-related routes
auth_bp = Blueprint('auth', __name__)


# --- Helper Functions --- #
# Function to generate JWT tokens for authentication
def generate_token(username, user_id):
    payload = {
        'username': username,
        'user_id': user_id,
        'exp': datetime.now(timezone.utc) + timedelta(hours=1)  # Token expiration time
    }
    token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
    print('Generated Token:', token)  # Debugging purpose
    return token


# --- Routes --- #

# User Registration: show form (GET) or process form (POST)
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username_raw = request.form['username'].strip().lower()
        username = username_raw.lower()
        password = request.form['password']
        confirm = request.form['confirm']

        # Check if username is already taken (case-insensitive)
        if User.query.filter(func.lower(User.username) == username).first():
            return render_template('register.html', error='That username is already taken')

        # Check if passwords match
        if password != confirm:
            return render_template('register.html', error='Passwords do not match')

        # Validate password strength
        if not PASSWORD_RE.fullmatch(password):
            return render_template(
                'register.html',
                error=('Password must be at least 8 characters long and include '
                       'one uppercase letter, one lowercase letter, one digit, '
                       'and one special character.')
            )

        # Final username existence check (redundant safeguard)
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='User already exists')

        # Hash password and create new user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        default_avatar = 'static/img/avatars/default_avatar.png'
        db.session.add(User(username=username_raw,
                            password=hashed_password,
                            avatar=default_avatar))
        db.session.commit()

        return redirect(url_for('auth.login'))

    # Render registration page
    return render_template('register.html')


# User Login: show form (GET) or process login (POST)
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        username = data['username']
        password = data['password']

        # Retrieve user and verify password
        user = User.query.filter(func.lower(User.username) == username.lower()).first()
        if not user or not bcrypt.check_password_hash(user.password, password):
            return render_template('login.html', error='Invalid credentials')

        # Generate token and set it in cookies
        token = generate_token(user.username, user.id)
        response = redirect(url_for('index'))
        response.set_cookie('token', token)
        response.set_cookie('username', username)
        return response

    # Render login page
    return render_template('login.html')


# User Logout: clear authentication cookies
@auth_bp.route('/logout')
def logout():
    response = make_response(render_template('index.html'))
    response.delete_cookie('token')
    return response


# Serve user avatar image file
@auth_bp.route('/avatar/<int:user_id>')
def avatar(user_id):
    user = User.query.get_or_404(user_id)
    filename = os.path.basename(user.avatar)
    folder = os.path.join(current_app.static_folder, 'img', 'avatars')
    return send_from_directory(folder, filename)


# User Profile Page
@auth_bp.route('/profile', methods=['GET'])
def profile():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('auth.login'))

    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
    except jwt.InvalidTokenError:
        flash('Please log in again.', 'error')
        resp = redirect(url_for('auth.login'))
        resp.delete_cookie('token')
        return resp

    user = User.query.get(payload['user_id'])
    if user is None:
        flash('Account no longer exists. Please log in again.', 'error')
        resp = redirect(url_for('auth.login'))
        resp.delete_cookie('token')
        return resp

    return render_template('profile.html', user=user)


# Update Username Route
@auth_bp.route('/profile/update_username', methods=['POST'])
def update_username():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('auth.login'))

    payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
    user = User.query.get(payload['user_id'])

    new_name_raw = request.form['new_username'].strip()
    new_name = new_name_raw.lower()

    # Check if new username is already taken
    if User.query.filter(func.lower(User.username) == new_name).first():
        flash('Username is already in use.', 'error')
        return redirect(url_for('auth.profile'))

    # Update username and reissue token
    user.username = new_name_raw
    db.session.commit()

    flash('Username updated.', 'success')
    new_token = generate_token(user.username, user.id)
    resp = redirect(url_for('auth.profile'))
    resp.set_cookie('token', new_token)
    return resp


# Update Avatar Route
@auth_bp.route('/profile/update_avatar', methods=['POST'])
def update_avatar():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('auth.login'))

    payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
    user = User.query.get(payload['user_id'])

    file = request.files.get('avatar')
    if not file or '.' not in file.filename:
        flash('No image selected.', 'error')
        return redirect(url_for('auth.profile'))

    ext = file.filename.rsplit('.', 1)[1].lower()
    if ext not in ALLOWED_IMG:
        flash('Unsupported image type.', 'error')
        return redirect(url_for('auth.profile'))

    # Save the uploaded file with a unique filename
    fname = secure_filename(f'user_{user.id}_{uuid.uuid4().hex[:8]}.{ext}')
    rel_path = os.path.join('img', 'avatars', fname)  # Path stored in DB
    abs_path = os.path.join(AVATAR_FOLDER, fname)

    file.save(abs_path)
    user.avatar = rel_path
    db.session.commit()

    flash('Avatar updated.', 'success')
    return redirect(url_for('auth.profile'))


# Update Password Route
@auth_bp.route('/profile/update_password', methods=['POST'])
def update_password():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('auth.login'))

    payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
    user = User.query.get(payload['user_id'])

    pwd = request.form['password']
    confirm = request.form['confirm']

    # Validate password confirmation
    if pwd != confirm:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('auth.profile'))

    # Validate password strength
    if not PASSWORD_RE.fullmatch(pwd):
        flash('Password must meet complexity requirements.', 'error')
        return redirect(url_for('auth.profile'))

    # Update password
    user.password = bcrypt.generate_password_hash(pwd).decode('utf-8')
    db.session.commit()

    flash('Password updated successfully.', 'success')
    return redirect(url_for('auth.profile'))


# Delete Account Route
@auth_bp.route('/profile/delete', methods=['POST'])
def delete_account():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('auth.login'))

    payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
    user = User.query.get(payload['user_id'])

    try:
        # Delete user's history records and account
        History.query.filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        flash('Could not delete account, please try again.', 'error')
        return redirect(url_for('auth.profile'))

    # Clear session after account deletion
    resp = redirect(url_for('index'))
    resp.delete_cookie('token')
    flash('Account deleted.', 'success')
    return resp


# Fetch User Encryption/Decryption History
@auth_bp.route('/history', methods=['GET'])
def get_history():
    token = request.cookies.get("token")
    if not token:
        return redirect(url_for("auth.login"))

    try:
        payload = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        user_id = payload["user_id"]

        if not user_id:
            return jsonify({'error': 'User not found'}), 404

        # Fetch and render user's history records
        history = History.query.filter_by(user_id=user_id).all()
        return render_template('history.html', history=history)

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
