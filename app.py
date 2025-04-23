import jwt
from flask import Flask, request, jsonify, render_template, current_app
from flask_cors import CORS
from flask import session
from auth import auth_bp
from des.modes_runner import run_des
from des.utils import hex_to_text, ensure_hex
from extensions import db, bcrypt
from models import User, History

# Initialize Flask app and config
app = Flask(__name__)
app.config.update(
    SQLALCHEMY_DATABASE_URI='sqlite:///users.db',  # SQLite database
    SQLALCHEMY_TRACK_MODIFICATIONS=False,  # Disable unnecessary tracking
    SECRET_KEY='supersecretkey'  # Secret key for JWT
)

# Enable CORS for frontend (e.g., localhost:5000)
CORS(app, resources={r'/*': {'origins': 'http://localhost:5000'}}, supports_credentials=True)

# Initialize database and password hashing
db.init_app(app)
bcrypt.init_app(app)

# Register authentication routes
app.register_blueprint(auth_bp)

# Create tables if they don't exist
with app.app_context():
    db.create_all()




@app.route('/')
def index():
    # Render the main HTML page
    return render_template('index.html')


@app.route('/encrypt', methods=['POST'])
def encrypt():
    # Handle encryption request
    data = request.get_json()
    message = data.get('message', '')
    hex_key = data.get('hex_key', '')
    mode = data.get('mode', 'ECB').upper()

    # Validate input
    if not message or not hex_key:
        return jsonify(error='Message and hex_key are required'), 400
    if len(hex_key) != 16 or not all(c in '0123456789abcdefABCDEF' for c in hex_key):
        return jsonify(error='DES key must be 16 hex chars (64‑bit including parity)'), 400

    try:
        # Convert message to hex format
        hex_message = ensure_hex(message)

        # Perform DES encryption
        result = run_des('encrypt', mode, hex_message, hex_key)

        # Destructure based on length
        if len(result) == 3:
            cipher_hex, rounds, keys = result
            extra = None
        else:
            cipher_hex, extra, rounds, keys = result

        # Check if user is logged in using JWT token
        token = request.cookies.get('token')
        if token:
            try:
                # Decode JWT to get user
                payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
                user = User.query.filter_by(username=payload['username']).first()
                if user:
                    # Save encryption history in the database
                    h = History(
                        encrypted_message=cipher_hex,
                        decrypted_message=message,
                        user_id=user.id
                    )
                    db.session.add(h)
                    db.session.commit()
            except jwt.InvalidTokenError:
                pass
        session["last_mode"] = "encrypt"
        session["last_round_data"] = rounds[0]
        session["last_key"] = keys[0]
        # Return the result
        return jsonify(
            encrypted_hex=cipher_hex,
            round_results=rounds,
            key_expansions=keys,
            extra=extra
        )
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route('/decrypt', methods=['POST'])
def decrypt():
    # Handle decryption request
    data = request.get_json(force=True)
    hex_message = data.get('hex_message', '')
    hex_key = data.get('hex_key', '')
    mode = data.get('mode', 'ECB').upper()

    # Validate input
    if not hex_message or not hex_key:
        return jsonify(error='hex_message and hex_key are required'), 400
    if any(c not in '0123456789abcdefABCDEF' for c in hex_message):
        return jsonify(error='hex_message must be valid hex'), 400
    if len(hex_key) != 16 or not all(c in '0123456789abcdefABCDEF' for c in hex_key):
        return jsonify(error='DES key must be 16 hex chars'), 400

    try:
        # Perform DES decryption
        extra = data.get('extra', None)

        if extra:
            plain_hex, rounds, keys = run_des('decrypt', mode, hex_message, hex_key, extra)
        else:
            plain_hex, rounds, keys = run_des('decrypt', mode, hex_message, hex_key)

        # Try to convert hex to readable text
        text_guess = hex_to_text(plain_hex)
        safe_text = text_guess if all(c.isprintable() or c.isspace() for c in text_guess) else '[Non-text binary data]'

        # Check if user is logged in and save to history
        token = request.cookies.get('token')
        if token:
            try:
                payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
                user = User.query.filter_by(username=payload['username']).first()
                if user:
                    h = History(
                        encrypted_message=hex_message,
                        decrypted_message=safe_text,
                        user_id=user.id
                    )
                    db.session.add(h)
                    db.session.commit()
            except jwt.InvalidTokenError:
                pass
        session["last_mode"] = "decrypt"
        session["last_round_data"] = rounds[0]
        session["last_key"] = keys[0]
        # Return decrypted data
        return jsonify(
            decrypted_text=safe_text,
            decrypted_hex=plain_hex,
            round_results=rounds,
            key_expansions=keys
        )
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route("/round1-details")
def round1_details():
    from flask import g, render_template

    # Fallbacks if no encryption/decryption done yet
    mode = session.get("last_mode")
    round_data = session.get("last_round_data")
    round_key = session.get("last_key")

    if not mode or not round_data:
        return "No round data available. Please encrypt or decrypt first."

    return render_template(
        "round1_details.html",
        mode=mode,
        round_data=round_data,
        round_key=round_key
    )
# Run the app on localhost
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
