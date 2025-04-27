# Import necessary modules for server, security, database, file handling, etc.
import ast
import json
import os

import jwt
from flask import Flask, request, jsonify, render_template, current_app, session
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Import internal modules for authentication, encryption, and database extensions
from auth import auth_bp
from des.DES import DES
from des.modes_runner import run_des
from des.utils import ensure_hex, hex_to_text, left_circ_shift
from extensions import db, bcrypt
from models import History

# Initialize Flask app and basic config (DB, secret key)
app = Flask(__name__)
app.config.update(
    SQLALCHEMY_DATABASE_URI='sqlite:///users.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SECRET_KEY='supersecretkey',
)

# Enable CORS (allow frontend running on localhost:5000 to make requests)
CORS(app, resources={r'/*': {'origins': 'http://localhost:5000'}}, supports_credentials=True)

# Initialize database and bcrypt extensions
db.init_app(app)
bcrypt.init_app(app)

# Register authentication blueprint (handles login, register, profile, history)
app.register_blueprint(auth_bp)

# Create database tables if they don't exist
with app.app_context():
    db.create_all()

# Inject user ID into templates if JWT token is valid
@app.context_processor
def inject_current_user():
    token = request.cookies.get("token")
    if not token:
        return dict(current_user_id=None)

    try:
        payload = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        return dict(current_user_id=payload.get("user_id"))
    except jwt.InvalidTokenError:
        return dict(current_user_id=None)

# Root route to render homepage
@app.route('/')
def index():
    return render_template('index.html')

# API route to encrypt a message using DES
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    message = data.get('message', '')
    hex_key = data.get('hex_key', '')
    mode = data.get('mode', 'ECB').upper()

    # Input validation
    if not message or not hex_key:
        return jsonify(error='Message and hex_key are required'), 400
    if len(hex_key) != 16 or any(c not in '0123456789abcdefABCDEF' for c in hex_key):
        return jsonify(error='DES key must be 16 hex chars (64-bit including parity)'), 400

    try:
        # Ensure message is in hex and perform encryption
        hex_message = ensure_hex(message)
        result = run_des('encrypt', mode, hex_message, hex_key)

        # Handle result unpacking
        if len(result) == 3:
            cipher_hex, rounds, keys = result
            extra = None
        else:
            cipher_hex, extra, rounds, keys = result

        # Save encryption history if user is logged in
        token = request.cookies.get('token')
        if token:
            try:
                payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
                user_id = payload["user_id"]
                h = History(
                    operation='encrypt',
                    mode=mode,
                    message_input=message,
                    key_input=hex_key,
                    extra_param=extra,
                    encrypted_message=cipher_hex,
                    decrypted_message=message,
                    user_id=user_id
                )
                db.session.add(h)
                db.session.commit()
            except jwt.InvalidTokenError:
                pass

        # Store first round results and key expansion for detailed viewing
        session['last_mode'] = 'encrypt'
        session['last_round_data'] = rounds[0]
        session['last_hex_key'] = hex_key
        session['last_key'] = keys[0]

        return jsonify(
            encrypted_hex=cipher_hex,
            round_results=rounds,
            key_expansions=keys,
            extra=extra
        )
    except Exception as e:
        return jsonify(error=str(e)), 500

# API route to decrypt a hex-encoded message using DES
@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json(force=True)
    hex_message = data.get('hex_message', '')
    hex_key = data.get('hex_key', '')
    mode = data.get('mode', 'ECB').upper()

    # Input validation
    if not hex_message or not hex_key:
        return jsonify(error='hex_message and hex_key are required'), 400
    if any(c not in '0123456789abcdefABCDEF' for c in hex_message):
        return jsonify(error='hex_message must be valid hex'), 400
    if len(hex_key) != 16 or any(c not in '0123456789abcdefABCDEF' for c in hex_key):
        return jsonify(error='DES key must be 16 hex chars'), 400

    try:
        # Perform decryption, handle optional 'extra' param (for CBC, etc.)
        extra = data.get('extra', None)
        if extra:
            plain_hex, rounds, keys = run_des('decrypt', mode, hex_message, hex_key, extra)
        else:
            plain_hex, rounds, keys = run_des('decrypt', mode, hex_message, hex_key)

        # Try converting hex output to printable text
        text_guess = hex_to_text(plain_hex)
        safe_text = text_guess if all(c.isprintable() or c.isspace() for c in text_guess) else '[Non-text binary data]'

        # Save decryption history if user is logged in
        token = request.cookies.get('token')
        if token:
            try:
                payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
                user_id = payload["user_id"]
                h = History(
                    operation='decrypt',
                    mode=mode,
                    message_input=hex_message,
                    key_input=hex_key,
                    extra_param=extra,
                    encrypted_message=hex_message,
                    decrypted_message=safe_text,
                    user_id=user_id
                )
                db.session.add(h)
                db.session.commit()
            except jwt.InvalidTokenError:
                pass

        # Store first round results and key expansion for detailed viewing
        session['last_mode'] = 'decrypt'
        session['last_round_data'] = rounds[0]
        session['last_hex_key'] = hex_key
        session['last_key'] = keys[0]

        return jsonify(
            decrypted_text=safe_text,
            decrypted_hex=plain_hex,
            round_results=rounds,
            key_expansions=keys
        )
    except Exception as e:
        return jsonify(error=str(e)), 500

# Route to view detailed Round 1 key schedule and data transformations
@app.route('/round1-details')
def round1_details():
    mode = session.get('last_mode')
    round_data = session.get('last_round_data')
    hex_key = session.get('last_hex_key')

    if not (mode and round_data and hex_key):
        return "No round data available. Please encrypt or decrypt first.", 400

    # Rebuild key schedule for round 1
    des_obj = DES(hex_key)
    bin_key = DES.hex_to_bin(hex_key)
    pc1_out = des_obj.PC_1.permutate(bin_key)
    C0, D0 = pc1_out[:28], pc1_out[28:]

    # Perform round 1 left circular shifts
    C1 = left_circ_shift(C0, 1)
    D1 = left_circ_shift(D0, 1)
    pre_pc2 = C1 + D1
    round1_key_binary = des_obj.PC_2.permutate(pre_pc2)
    round1_key_hex = hex(int(round1_key_binary, 2))[2:].zfill(12)

    # Prepare key schedule details
    key_schedule = {
        'original_key_binary': bin_key,
        'pc1_output': pc1_out,
        'C0': C0,
        'D0': D0,
        'C1': C1,
        'D1': D1,
        'pre_pc2': pre_pc2,
        'round1_key_binary': round1_key_binary,
        'round1_key_hex': round1_key_hex,
    }

    # Safely parse round data
    if isinstance(round_data, str):
        try:
            round_data = json.loads(round_data)
        except ValueError:
            try:
                round_data = ast.literal_eval(round_data)
            except Exception:
                round_data = {"value": round_data}

    # Render detailed round 1 info page
    return render_template(
        'round1_details.html',
        mode=mode,
        round_data=round_data,
        round_key=round1_key_hex,
        key_schedule=key_schedule
    )

# Configuration for file uploads
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max 16MB upload size

# API route to encrypt uploaded file contents using DES
@app.route('/encrypt_file', methods=['POST'])
def encrypt_file():
    if 'file' not in request.files:
        return jsonify(error='No file part'), 400

    file = request.files['file']
    hex_key = request.form.get('hex_key', '')
    mode = request.form.get('mode', 'ECB').upper()

    # Validate file and key
    if not file or file.filename == '':
        return jsonify(error='No selected file'), 400
    if not hex_key:
        return jsonify(error='hex_key is required'), 400
    if len(hex_key) != 16 or any(c not in '0123456789abcdefABCDEF' for c in hex_key):
        return jsonify(error='DES key must be 16 hex chars'), 400

    try:
        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Read file bytes and encrypt
        with open(filepath, 'rb') as f:
            file_bytes = f.read()
        hex_message = file_bytes.hex()

        result = run_des('encrypt', mode, hex_message, hex_key)
        if len(result) == 3:
            cipher_hex, rounds, keys = result
        else:
            cipher_hex, extra, rounds, keys = result

        cipher_bytes = bytes.fromhex(cipher_hex)

        # Save encrypted output
        encrypted_filename = f'encrypted_{filename}'
        encrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        with open(encrypted_filepath, 'wb') as f:
            f.write(cipher_bytes)

        return jsonify(
            message='File encrypted successfully',
            encrypted_file=encrypted_filename,
            round_results=rounds,
            key_expansions=keys
        )
    except Exception as e:
        return jsonify(error=str(e)), 500

# API route to decrypt uploaded file contents using DES
@app.route('/decrypt_file', methods=['POST'])
def decrypt_file():
    if 'file' not in request.files:
        return jsonify(error='No file part'), 400

    file = request.files['file']
    hex_key = request.form.get('hex_key', '')
    mode = request.form.get('mode', 'ECB').upper()
    extra = request.form.get('extra', None)

    # Validate file and key
    if not file or file.filename == '':
        return jsonify(error='No selected file'), 400
    if not hex_key:
        return jsonify(error='hex_key is required'), 400
    if len(hex_key) != 16 or any(c not in '0123456789abcdefABCDEF' for c in hex_key):
        return jsonify(error='DES key must be 16 hex chars'), 400

    try:
        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Read file bytes and decrypt
        with open(filepath, 'rb') as f:
            file_bytes = f.read()
        hex_message = file_bytes.hex()

        if extra:
            plain_hex, rounds, keys = run_des('decrypt', mode, hex_message, hex_key, extra)
        else:
            plain_hex, rounds, keys = run_des('decrypt', mode, hex_message, hex_key)

        plain_bytes = bytes.fromhex(plain_hex)

        # Save decrypted output
        decrypted_filename = f'decrypted_{filename}'
        decrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
        with open(decrypted_filepath, 'wb') as f:
            f.write(plain_bytes)

        return jsonify(
            message='File decrypted successfully',
            decrypted_file=decrypted_filename,
            round_results=rounds,
            key_expansions=keys
        )
    except Exception as e:
        return jsonify(error=str(e)), 500

# Start the Flask app on localhost:5000
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
