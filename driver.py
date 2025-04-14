from des import DES

plaintext = '[$5usnd93e'  # This is equivalent to 48617373616E4461 in HEX
des = DES(key='9i3jd%j')  # This is equivalent to 5365637265744B65 in HEX

enc_text, enc_round_results, enc_key_expansions = des.encrypt(plaintext)
dec_text, dec_round_results, dec_key_expansions = des.decrypt(enc_text)

print('### Input ###')
print(f'Plaintext: {plaintext}')
print(f'Key: {des.key} (Size = {len(des.key)})\n')

print('### Encryption ###')
print(f'Encrypted text: {enc_text}')
print(f'Encryption round results: {enc_round_results}')
print(f'Encryption key expansions: {enc_key_expansions}\n')

print('### Decryption ###')
print(f'Decrypted text: {dec_text}')
print(f'Decryption round results: {dec_round_results}')
print(f'Decryption key expansions: {dec_key_expansions}')
