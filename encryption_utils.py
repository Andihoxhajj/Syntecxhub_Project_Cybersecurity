import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# For demo / assignment: same 32-byte key on client and server.
KEY = b"this_is_demo_key_for_chat_app_32b!"[:32]  # 32 bytes (AES-256)


def encrypt_message(plaintext: bytes) -> bytes:
    """
    Encrypt plaintext with AES-GCM.
    Returns nonce (12 bytes) + ciphertext+tag.
    """
    aesgcm = AESGCM(KEY)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt_message(data: bytes) -> bytes:
    """
    Decrypt data of the form nonce (12 bytes) + ciphertext+tag.
    """
    aesgcm = AESGCM(KEY)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)