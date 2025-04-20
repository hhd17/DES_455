from flask import Flask, request, render_template
from des import DES
from des import modes
from des.modes import BLOCK_SIZE

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    mode = request.form['mode']
    action = request.form['action']
    message = request.form['message']
    original_message = message
    key = request.form['key']

    result = ""
    round_results = []
    key_expansions = []

    try:
        des = DES(key=key)

        def encrypt_block(block, key):
            return bytes.fromhex(des.encrypt(block.hex())[0])

        def decrypt_block(block, key):
            return bytes.fromhex(des.decrypt(block.hex())[0])

        # Convert non-hex input to hex automatically
        try:
            int(message, 16)
        except ValueError:
            message = message.encode().hex()

        if mode == "ECB":
            if action == "encrypt":
                result, round_results, key_expansions = des.encrypt(message)
            else:
                result, round_results, key_expansions = des.decrypt(message)

        elif mode == "CBC":
            raw_key = key.encode()
            if action == "encrypt":
                plaintext_bytes = bytes.fromhex(message)
                encrypted = modes.encrypt_cbc(plaintext_bytes, raw_key, encrypt_block)
                result = encrypted.hex()
                _, round_results, key_expansions = des.encrypt(plaintext_bytes[:8].hex())
            else:
                ciphertext_bytes = bytes.fromhex(message)
                decrypted = modes.decrypt_cbc(ciphertext_bytes, raw_key, decrypt_block)
                result = decrypted.decode()
                _, round_results, key_expansions = des.decrypt(ciphertext_bytes[BLOCK_SIZE:BLOCK_SIZE*2].hex())

        elif mode == "CFB":
            raw_key = key.encode()
            if action == "encrypt":
                plaintext_bytes = bytes.fromhex(message)
                encrypted = modes.encrypt_cfb(plaintext_bytes, raw_key, encrypt_block)
                result = encrypted.hex()
                _, round_results, key_expansions = des.encrypt(plaintext_bytes[:8].hex())
            else:
                ciphertext_bytes = bytes.fromhex(message)
                decrypted = modes.decrypt_cfb(ciphertext_bytes, raw_key, encrypt_block)
                result = decrypted.decode()
                _, round_results, key_expansions = des.decrypt(ciphertext_bytes[BLOCK_SIZE:BLOCK_SIZE*2].hex())
        elif mode == "OFB":
            raw_key = key.encode()
            if action == "encrypt":
                plaintext_bytes = bytes.fromhex(message)
                encrypted = modes.encrypt_ofb(plaintext_bytes, raw_key, encrypt_block)
                result = encrypted.hex()
                _, round_results, key_expansions = des.encrypt(plaintext_bytes[:8].hex())
            else:
                ciphertext_bytes = bytes.fromhex(message)
                decrypted = modes.decrypt_ofb(ciphertext_bytes, raw_key, encrypt_block)
                result = decrypted.decode()
                _, round_results, key_expansions = des.decrypt(ciphertext_bytes[BLOCK_SIZE:BLOCK_SIZE*2].hex())
        elif mode == "CTR":
            raw_key = key.encode()
            if action == "encrypt":
                plaintext_bytes = bytes.fromhex(message)
                encrypted = modes.encrypt_ctr(plaintext_bytes, raw_key, encrypt_block)
                result = encrypted.hex()
                _, round_results, key_expansions = des.encrypt(plaintext_bytes[:8].hex())
            else:
                ciphertext_bytes = bytes.fromhex(message)
                decrypted = modes.decrypt_ctr(ciphertext_bytes, raw_key, encrypt_block)
                result = decrypted.decode()
                _, round_results, key_expansions = des.decrypt(ciphertext_bytes[BLOCK_SIZE:BLOCK_SIZE*2].hex())
            


        return render_template("index.html",
                       result=result,
                       mode=mode,
                       action=action,
                       message=message,
                       original_message=original_message,
                       key=key,
                       round_results=round_results,
                       key_expansions=key_expansions)

    except Exception as e:
        return render_template("index.html",
                               result=f"Error: {str(e)}",
                               mode=mode,
                               action=action,
                               message=message,
                               key=key,
                               round_results=[],
                               key_expansions=[])

if __name__ == "__main__":
    app.run(debug=True)