import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2

BLOCK_SIZE=16
pad = lambda s: s+ (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s)-1:])]
message = input("Enter message you would like to encrypt: ")
password = input("Enter encryption password: ")

def get_private_key(password):
    salt = b"this is a salt phrase"
    kdf = PBKDF2(password, salt, 64, 100)
    key = kdf[:32]
    return key
def encrypt(raw, password):
    private_key = get_private_key(password)
    key = private_key
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return (ciphertext, tag, nonce)
def decrypt(enc, password, tag, nonce):
    private_key = get_private_key(password)
    cipher = AES.new(private_key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(enc)
    try:
        cipher.verify(tag)
        print("Message is authentic: ", plaintext)
    except ValueError:
        print("Key incorrect or message corrupted")
encrypted, tag, nonce= encrypt("This is a secret message", password)
print(encrypted)
print(decrypt(encrypted,password, tag, nonce))
