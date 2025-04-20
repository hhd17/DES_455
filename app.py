from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from auth import auth_bp
from des.modes_runner import run_des
from des.utils import hex_to_text, ensure_hex
from extensions import db, bcrypt

app = Flask(__name__)
app.config.update(
    SQLALCHEMY_DATABASE_URI='sqlite:///users.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SECRET_KEY='supersecretkey'
)
CORS(app, resources={r'/*': {'origins': 'http://localhost:5000'}}, supports_credentials=True)

db.init_app(app)
bcrypt.init_app(app)
app.register_blueprint(auth_bp)

with app.app_context():
    db.create_all()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    message = data.get('message', '')
    hex_key = data.get('hex_key', '')
    mode = data.get('mode', 'ECB').upper()

    if not message or not hex_key:
        return jsonify(error='Message and hex_key are required'), 400
    if len(hex_key) != 16 or not all(c in '0123456789abcdefABCDEF' for c in hex_key):
        return jsonify(error='DES key must be 16 hex chars (64‑bit including parity)'), 400

    try:
        hex_message = ensure_hex(message)
        cipher_hex, rounds, keys = run_des('encrypt', mode, hex_message, hex_key)
        return jsonify(
            encrypted_hex=cipher_hex,
            round_results=rounds,
            key_expansions=keys
        )
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json(force=True)
    hex_message = data.get('hex_message', '')
    hex_key = data.get('hex_key', '')
    mode = data.get('mode', 'ECB').upper()

    if not hex_message or not hex_key:
        return jsonify(error='hex_message and hex_key are required'), 400
    if any(c not in '0123456789abcdefABCDEF' for c in hex_message):
        return jsonify(error='hex_message must be valid hex'), 400
    if len(hex_key) != 16 or not all(c in '0123456789abcdefABCDEF' for c in hex_key):
        return jsonify(error='DES key must be 16 hex chars'), 400

    try:
        plain_hex, rounds, keys = run_des('decrypt', mode, hex_message, hex_key)
        text_guess = hex_to_text(plain_hex)
        safe_text = text_guess if all(c.isprintable() or c.isspace() for c in text_guess) else '[Non-text binary data]'

        return jsonify(
            decrypted_text=safe_text,
            decrypted_hex=plain_hex,
            round_results=rounds,
            key_expansions=keys
        )


    except Exception as e:
        return jsonify(error=str(e)), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
