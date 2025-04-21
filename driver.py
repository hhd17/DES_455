from des import DES

plaintext = '112210F4C023B6D3' 
des = DES(key='9BC1546914997F6C')  

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
