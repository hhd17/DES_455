from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from auth import auth_bp
from des import DES
from des import modes
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


def ensure_hex(s: str) -> str:
    try:
        int(s, 16)
        return s.lower() if len(s) % 2 == 0 else '0' + s.lower()
    except ValueError:
        return s.encode().hex()


def hex_to_text(hex_str: str) -> str:
    try:
        return bytes.fromhex(hex_str).decode(errors='replace')
    except ValueError:
        return '[Invalid hex]'


def run_des(action: str, mode: str, hex_message: str, hex_key: str):
    des = DES(key=hex_key)
    raw_key_bytes = hex_key.encode()

    def encrypt_block(block: bytes, _k: bytes):
        return bytes.fromhex(des.encrypt(block.hex())[0])

    def decrypt_block(block: bytes, _k: bytes):
        return bytes.fromhex(des.decrypt(block.hex())[0])

    from des.modes import pad, unpad, BLOCK_SIZE

    if mode == 'ECB':
        if action == 'encrypt':
            msg_bytes = bytes.fromhex(hex_message)
            padded = pad(msg_bytes)
            result_hex, rounds, keys = des.encrypt(padded.hex())
            return result_hex, rounds, keys

        else:
            decrypted_hex, rounds, keys = des.decrypt(hex_message)
            decrypted_bytes = bytes.fromhex(decrypted_hex)
            try:
                unpadded = unpad(decrypted_bytes)
            except Exception:
                unpadded = decrypted_bytes
            return unpadded.hex(), rounds, keys

    msg_bytes = bytes.fromhex(hex_message)

    if mode == 'CBC':
        if action == 'encrypt':
            cipher_bytes = modes.encrypt_cbc(msg_bytes, raw_key_bytes, encrypt_block)
            aux_rounds = des.encrypt(msg_bytes[:BLOCK_SIZE].hex())
            return cipher_bytes.hex(), aux_rounds[1], aux_rounds[2]
        else:
            plain_bytes = modes.decrypt_cbc(msg_bytes, raw_key_bytes, decrypt_block)
            aux_rounds = des.decrypt(msg_bytes[BLOCK_SIZE:BLOCK_SIZE * 2].hex())
            return plain_bytes.hex(), aux_rounds[1], aux_rounds[2]

    if mode == 'CFB':
        if action == 'encrypt':
            cipher_bytes = modes.encrypt_cfb(msg_bytes, raw_key_bytes, encrypt_block)
            aux_rounds = des.encrypt(msg_bytes[:BLOCK_SIZE].hex())
            return cipher_bytes.hex(), aux_rounds[1], aux_rounds[2]
        else:
            plain_bytes = modes.decrypt_cfb(msg_bytes, raw_key_bytes, encrypt_block)
            aux_rounds = des.decrypt(msg_bytes[BLOCK_SIZE:BLOCK_SIZE * 2].hex())
            return plain_bytes.hex(), aux_rounds[1], aux_rounds[2]

    if mode == 'OFB':
        if action == 'encrypt':
            cipher_bytes = modes.encrypt_ofb(msg_bytes, raw_key_bytes, encrypt_block)
            aux_rounds = des.encrypt(msg_bytes[:BLOCK_SIZE].hex())
            return cipher_bytes.hex(), aux_rounds[1], aux_rounds[2]
        else:
            plain_bytes = modes.decrypt_ofb(msg_bytes, raw_key_bytes, encrypt_block)
            aux_rounds = des.decrypt(msg_bytes[BLOCK_SIZE:BLOCK_SIZE * 2].hex())
            return plain_bytes.hex(), aux_rounds[1], aux_rounds[2]

    if mode == 'CTR':
        if action == 'encrypt':
            cipher_bytes = modes.encrypt_ctr(msg_bytes, raw_key_bytes, encrypt_block)
            aux_rounds = des.encrypt(msg_bytes[:BLOCK_SIZE].hex())
            return cipher_bytes.hex(), aux_rounds[1], aux_rounds[2]
        else:
            plain_bytes = modes.decrypt_ctr(msg_bytes, raw_key_bytes, encrypt_block)
            aux_rounds = des.decrypt(msg_bytes[BLOCK_SIZE:BLOCK_SIZE * 2].hex())
            return plain_bytes.hex(), aux_rounds[1], aux_rounds[2]

    raise ValueError(f'Unsupported mode {mode}')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/encrypt', methods=['POST'])
def api_encrypt():
    data = request.get_json(force=True)
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
def api_decrypt():
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
