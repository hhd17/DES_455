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

PASSWORD_RE = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$'
)

BASE_DIR = os.path.dirname(__file__)
AVATAR_FOLDER = os.path.join(BASE_DIR, 'static', 'img', 'avatars')
os.makedirs(AVATAR_FOLDER, exist_ok=True)
ALLOWED_IMG = {'png', 'jpg', 'jpeg'}

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
        username_raw = request.form['username'].strip().lower()
        username = username_raw.lower()
        password = request.form['password']
        confirm = request.form['confirm']

        # username already taken? (case‑insensitive)
        if User.query.filter(func.lower(User.username) == username).first():
            return render_template('register.html',
                                   error='That username is already taken')

        # confirm password
        if password != confirm:
            return render_template('register.html',
                                   error='Passwords do not match')

        # strong‑password rule
        strong = re.fullmatch(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$',
            password
        )
        if not strong:
            return render_template(
                'register.html',
                error=('Password must be at least 8 characters long and include '
                       'one uppercase letter, one lowercase letter, one digit, '
                       'and one special character.')
            )

        # existing user?
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='User already exists')

        # hash + create
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        default_avatar = 'static/img/avatars/default_avatar.png'
        db.session.add(User(username=username_raw,
                            password=hashed_password,
                            avatar=default_avatar))
        db.session.commit()

        return redirect(url_for('auth.login'))

    return render_template('register.html')


# Login route (GET = form, POST = process login)
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        username = data['username']
        password = data['password']

        # Get user from database and check password
        user = User.query.filter(func.lower(User.username) == username.lower()).first()
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


@auth_bp.route('/avatar/<int:user_id>')
def avatar(user_id):
    user = User.query.get_or_404(user_id)
    filename = os.path.basename(user.avatar)
    folder = os.path.join(current_app.static_folder, 'img', 'avatars')
    return send_from_directory(folder, filename)


@auth_bp.route('/profile', methods=['GET'])
def profile():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('auth.login'))

    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'],
                             algorithms=['HS256'])
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


@auth_bp.route('/profile/update_username', methods=['POST'])
def update_username():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('auth.login'))

    payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
    user = User.query.get(payload['user_id'])

    new_name_raw = request.form['new_username'].strip()
    new_name = new_name_raw.lower()

    # already taken?
    if User.query.filter(func.lower(User.username) == new_name).first():
        flash('Username is already in use.', 'error')
        return redirect(url_for('auth.profile'))

    user.username = new_name_raw
    db.session.commit()

    flash('Username updated.', 'success')

    # re‑issue token with new username
    new_token = generate_token(user.username, user.id)
    resp = redirect(url_for('auth.profile'))
    resp.set_cookie('token', new_token)
    return resp


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

    fname = secure_filename(f'user_{user.id}_{uuid.uuid4().hex[:8]}.{ext}')
    rel_path = os.path.join('img', 'avatars', fname)  # stored in DB
    abs_path = os.path.join(AVATAR_FOLDER, fname)

    file.save(abs_path)
    user.avatar = rel_path
    db.session.commit()
    flash('Avatar updated.', 'success')
    return redirect(url_for('auth.profile'))


@auth_bp.route('/profile/update_password', methods=['POST'])
def update_password():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('auth.login'))

    payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
    user = User.query.get(payload['user_id'])

    pwd = request.form['password']
    confirm = request.form['confirm']

    if pwd != confirm:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('auth.profile'))

    if not PASSWORD_RE.fullmatch(pwd):
        flash('Password must be at least 8 characters long and include '
              'one uppercase, one lowercase, one digit, and one special character.',
              'error')
        return redirect(url_for('auth.profile'))

    user.password = bcrypt.generate_password_hash(pwd).decode('utf-8')
    db.session.commit()
    flash('Password updated successfully.', 'success')
    return redirect(url_for('auth.profile'))


@auth_bp.route('/profile/delete', methods=['POST'])
def delete_account():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('auth.login'))

    payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
    user = User.query.get(payload['user_id'])

    try:
        History.query.filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        flash('Could not delete account, please try again.', 'error')
        return redirect(url_for('auth.profile'))

    resp = redirect(url_for('index'))
    resp.delete_cookie('token')
    flash('Account deleted.', 'success')
    return resp


# Route to fetch and display user encryption/decryption history
@auth_bp.route('/history', methods=['GET'])
def get_history():
    # Get JWT token from cookies
    token = request.cookies.get("token")
    if not token:
        return redirect(url_for("auth.login"))

    try:
        # Decode token to get user info
        payload = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        user_id = payload["user_id"]

        if not user_id:
            return jsonify({'error': 'User not found'}), 404

        # Fetch user's encryption/decryption history
        history = History.query.filter_by(user_id=user_id).all()

        # Render history template with user's data
        return render_template('history.html', history=history)

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
