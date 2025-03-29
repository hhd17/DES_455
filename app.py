from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from des import DES

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    hex_message = data['hex_message']  # Hexadecimal message
    hex_key = data['hex_key']  # Hexadecimal key

    # Create DES object using the user-provided key
    des = DES(key=hex_key)
    encrypted, round_results, key_expansions = des.encrypt(hex_message)
    
    return jsonify({
        'encrypted': encrypted,
        'round_results': round_results,
        'key_expansions': key_expansions
    })

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    hex_message = data['hex_message']  # Hexadecimal message
    hex_key = data['hex_key']  # Hexadecimal key

    # Create DES object using the user-provided key
    des = DES(key=hex_key)
    decrypted, round_results, key_expansions = des.decrypt(hex_message)
    
    return jsonify({
        'decrypted': decrypted,
        'round_results': round_results,
        'key_expansions': key_expansions
    })

if __name__ == '__main__':
    app.run(debug=True)
