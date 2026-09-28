"""
Fitur pengayaan: Enkripsi hibrida.
Data dienkripsi dengan AES-256-GCM memakai kunci sesi acak (bukan dari password),
lalu kunci sesi tersebut dibungkus (di-wrap) memakai RSA-OAEP dengan kunci publik penerima.
Ini meniru pola dunia nyata (mis. PGP): AES cepat untuk data besar, RSA untuk pertukaran kunci.
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

SESSION_KEY_LEN = 32
NONCE_LEN = 12


def generate_rsa_keypair(key_size: int = 2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private_key, private_key.public_key()


def serialize_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def serialize_private_key(private_key, password: bytes = None) -> bytes:
    enc = (
        serialization.BestAvailableEncryption(password)
        if password else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )


def load_public_key(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)


def load_private_key(pem_bytes: bytes, password: bytes = None):
    return serialization.load_pem_private_key(pem_bytes, password=password)


def hybrid_encrypt(plaintext: bytes, recipient_public_key) -> dict:
    session_key = os.urandom(SESSION_KEY_LEN)
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    wrapped_key = recipient_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return {
        "wrapped_key": base64.b64encode(wrapped_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def hybrid_decrypt(payload: dict, recipient_private_key) -> bytes:
    wrapped_key = base64.b64decode(payload["wrapped_key"])
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])

    session_key = recipient_private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext, None)
