from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import CryptographyUnavailableError
from cryptography.hazmat.primitives.kdf.pbkdf2 import InvalidKeyLength

import os


class ChatEncryption:
    def __init__(self, password):
        self.salt = os.urandom(16)
        self.password = password.encode('utf-8')
        self.kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        self.key = self.derive_key()

    def derive_key(self):
        try:
            return self.kdf.derive(self.password)
        except (CryptographyUnavailableError, InvalidKeyLength):
            print("Error: Cryptography library unavailable or invalid key length.")
            return None

    def encrypt(self, plaintext):
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        return nonce + ciphertext

    def decrypt(self, ciphertext):
        aesgcm = AESGCM(self.key)
        nonce = ciphertext[:12]
        encrypted_data = ciphertext[12:]
        plaintext = aesgcm.decrypt(nonce, encrypted_data, None)
        return plaintext.decode('utf-8')


# Usage Example:
# Alice's side
encryption = ChatEncryption("alice_password")

# Bob's side
# encryption = ChatEncryption("bob_password")

plaintext_message = "Hello, Bob!"
encrypted_message = encryption.encrypt(plaintext_message)
print("Encrypted Message:", encrypted_message)

# Transmit the encrypted_message to the other side (e.g., Bob)

# Bob's side
decrypted_message = encryption.decrypt(encrypted_message)
print("Decrypted Message:", decrypted_message)
