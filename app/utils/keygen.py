import hashlib

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Random import get_random_bytes


class KeyGen():
    def __init__(self, key_length=16):
        self.key_length = key_length

    def generate_user_key(self, password: str):
        key: RsaKey = RSA.generate(2048)
        salt = get_random_bytes(16)
        iv = get_random_bytes(12)
        # Export des clés
        private_key = key.export_key()
        public_key = key.public_key().exportKey()

        #Chiffrement de la clé en AES 256 GCM et le mdp
        key_derivation = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
        cipher = AES.new(key_derivation, AES.MODE_GCM, iv)
        ciphertext, tag = cipher.encrypt_and_digest(private_key)


        return ciphertext, public_key, salt

