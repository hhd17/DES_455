from des import DES

plaintext = '112210F4C023B6D3'
key = '9BC1546914997F6C'

des = DES(key=key)

# Standard encryption and decryption
enc_text, enc_round_results, enc_key_expansions = des.encrypt(plaintext)
dec_text, dec_round_results, dec_key_expansions = des.decrypt(enc_text)

print("### Input ###")
print(f"Plaintext: {plaintext}")
print(f"Key (binary): {des.key}\n")

print("### Full Encryption Output ###")
print(f"Encrypted text: {enc_text}")
print(f"Encryption round results: {enc_round_results}")
print(f"Encryption key expansions (pre-PC2): {enc_key_expansions}\n")

print("### Full Decryption Output ###")
print(f"Decrypted text: {dec_text}")
print(f"Decryption round results: {dec_round_results}")
print(f"Decryption key expansions (pre-PC2): {dec_key_expansions}\n")

# ----------- Verbose Round 1 Encryption ------------
print("### Round 1 of Block 1 - Encryption Steps ###")
verbose_enc = des.encrypt(plaintext, verbose=True)
for k, v in verbose_enc.items():
    print(f"{k}: {v}")
print()

# ----------- Verbose Round 1 Decryption ------------
print("### Round 1 of Block 1 - Decryption Steps ###")
verbose_dec = des.decrypt(enc_text, verbose=True)
for k, v in verbose_dec.items():
    print(f"{k}: {v}")
print()

# ----------- Round 1 Key Expansion Breakdown ------------
print("### Round 1 Key Expansion Steps ###")
key_details = des.get_key_expansion_details()
for k, v in key_details.items():
    print(f"{k}: {v}")