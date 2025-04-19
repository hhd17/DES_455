from flask import Flask, current_app, request, jsonify, render_template
from flask_cors import CORS
import jwt
from extensions import db, bcrypt
from des import DES
from models import History
from auth import auth_bp

app = Flask(__name__)
CORS(app, origins=["http://localhost:5000"])
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'

# Initialize extensions
db.init_app(app)
bcrypt.init_app(app)

# Register auth blueprint
app.register_blueprint(auth_bp)

# Create database tables
with app.app_context():
    db.create_all()

def text_to_hex(text):
    return text.encode().hex()

def hex_to_text(hex_str):
    try:
        return bytes.fromhex(hex_str).decode(errors='replace')  # Replaces invalid bytes with �
    except ValueError:
        return "[Invalid hex to text]"
    


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    message = data['message']         # Plaintext message
    hex_key = data['hex_key']         # Still expecting hex key

    token = request.cookies.get('token')
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
        user_id = payload['user_id']  # Assume user_id is part of the token
    # Convert plaintext to hex
        hex_message = text_to_hex(message)

        # Create DES object using the user-provided key
        des = DES(key=hex_key)
        encrypted, round_results, key_expansions = des.encrypt(hex_message)
        print("enc:",encrypted)

        # Log encryption to history
        new_history = History(
            encrypted_message=encrypted,
            decrypted_message=message,  # Placeholder for decrypted message
            user_id=user_id
        )
        db.session.add(new_history)
        db.session.commit()

        return jsonify({
            'encrypted_hex': encrypted,
            'round_results': round_results,
            'key_expansions': key_expansions
        })

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    hex_message = data['hex_message']  # Encrypted message in hex
    hex_key = data['hex_key']
    token = request.cookies.get('token')
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
        user_id = payload['user_id']  # Assume user_id is part of the token
        # Create DES object using the user-provided key
        des = DES(key=hex_key)
        decrypted_hex, round_results, key_expansions = des.decrypt(hex_message)

        # Convert hex back to plaintext
        decrypted_text = hex_to_text(decrypted_hex)

        # Log decryption to history
        history = History.query.filter_by(user_id=user_id, encrypted_message=hex_message).first()
        if history:
            history.decrypted_message = decrypted_text
        else:
            # Create a new history entry if user hasn't encrypted this before
            history = History(
                encrypted_message=hex_message,
                decrypted_message=decrypted_text,
                user_id=user_id
            )
            db.session.add(history)

        db.session.commit()

        return jsonify({
            'decrypted_text': decrypted_text,
            'decrypted_hex': decrypted_hex,
            'round_results': round_results,
            'key_expansions': key_expansions
        })
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401


if __name__ == '__main__':
    app.run(debug=True)
