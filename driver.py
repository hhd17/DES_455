from des import DES
from des import modes

# Initialize DES instance
key_hex = '9BC1546914997F6C'
des = DES(key=key_hex)

# Adapter functions for CBC and CFB
def encrypt_block(block, key):
    return bytes.fromhex(des.encrypt(block.hex())[0])

def decrypt_block(block, key):
    return bytes.fromhex(des.decrypt(block.hex())[0])

print("=== DES Mode Demonstrations ===\\n")

# === ECB MODE ===
print("### ECB Mode ###")
plaintext_ecb = '112210F4C023B6D3'
enc_ecb, ecb_rounds, _ = des.encrypt(plaintext_ecb)
dec_ecb, _, _ = des.decrypt(enc_ecb)
print(f"Plaintext (hex): {plaintext_ecb}")
print(f"Encrypted (ECB): {enc_ecb}")
print(f"Decrypted (ECB): {dec_ecb}")
print("Round-by-round results:")
for i, r in enumerate(ecb_rounds, 1):
    print(f"  Round {i}: {r}")
print()

# === CBC MODE ===
print("### CBC Mode ###")
plaintext_cbc = b"HelloWorld12345"
cbc_key = key_hex.encode()
enc_cbc = modes.encrypt_cbc(plaintext_cbc, cbc_key, encrypt_block)
dec_cbc = modes.decrypt_cbc(enc_cbc, cbc_key, decrypt_block)
print(f"Plaintext (raw): {plaintext_cbc}")
print(f"Encrypted (CBC): {enc_cbc.hex()}")
print(f"Decrypted (CBC): {dec_cbc.decode()}")
print()

# === CFB MODE ===
print("### CFB Mode ###")
plaintext_cfb = b"HelloCFB_ModeTest"
cfb_key = key_hex.encode()
enc_cfb = modes.encrypt_cfb(plaintext_cfb, cfb_key, encrypt_block)
dec_cfb = modes.decrypt_cfb(enc_cfb, cfb_key, encrypt_block)
print(f"Plaintext (raw): {plaintext_cfb}")
print(f"Encrypted (CFB): {enc_cfb.hex()}")
print(f"Decrypted (CFB): {dec_cfb.decode()}")
print()

# === OFB MODE ===
print("### OFB Mode ###")
plaintext_ofb = b"HelloOFB_ModeTest"
ofb_key = key_hex.encode()
enc_ofb = modes.encrypt_ofb(plaintext_ofb, ofb_key, encrypt_block)
dec_ofb = modes.decrypt_ofb(enc_ofb, ofb_key, encrypt_block)
print(f"Plaintext (raw): {plaintext_ofb}")
print(f"Encrypted (OFB): {enc_ofb.hex()}")
print(f"Decrypted (OFB): {dec_ofb.decode()}")
print()

# === CTR MODE ===
print("### CTR Mode ###")
plaintext_ctr = b"HelloCTR_ModeTest"
ctr_key = key_hex.encode()
enc_ctr = modes.encrypt_ctr(plaintext_ctr, ctr_key, encrypt_block)
dec_ctr = modes.decrypt_ctr(enc_ctr, ctr_key, encrypt_block)
print(f"Plaintext (raw): {plaintext_ctr}")
print(f"Encrypted (CTR): {enc_ctr.hex()}")
print(f"Decrypted (CTR): {dec_ctr.decode()}")
print()