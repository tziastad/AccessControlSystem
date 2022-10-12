"""from Crypto.Cipher import AES
plaintext = "some text"
key='M4st3rRul3zs'
encryptor = AES.new(key, AES.MODE_CBC, iv)
ciphertext = encryptor.encrypt(plaintext*16)
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypttext = cipher.decrypt(ciphertext)
decrypttext = decrypttext[0:len(plaintext)]"""

from Crypto.Cipher import AES
password = b'1234567812345678' #The secret key, b, is expressed as bytes
iv = b'1234567812345678' # iv offset, bytes type
text = b'6f6b' #Content to be encrypted, bytes type
len = 16
text = text.ljust(16, b'0')
print("----:",text)
aes = AES.new(password,AES.MODE_CBC,iv) #Create an aes object
# AES. MODE_ The CBC representation pattern is the CBC pattern
en_text = aes.encrypt(text)
print("Ciphertext:",en_text) #Encrypted plaintext, bytes type
aes = AES.new(password,AES.MODE_CBC,iv) #Decryption in CBC mode requires re creating an aes object
den_text = aes.decrypt(en_text)
print("Plaintext:",den_text)