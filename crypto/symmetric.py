import os
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

KEY_LEN = 32          # 256 bit
SALT_LEN = 16
NONCE_LEN_GCM = 12     # AES-GCM standar 96-bit nonce
NONCE_LEN_CHACHA = 12  # ChaCha20-Poly1305 96-bit nonce

ALGOS = {"aes-gcm": AESGCM, "chacha20-poly1305": ChaCha20Poly1305}
NONCE_LENS = {"aes-gcm": NONCE_LEN_GCM, "chacha20-poly1305": NONCE_LEN_CHACHA}


class DecryptionError(Exception):
    """Dilempar bila kata sandi salah atau cipherteks telah diubah (verifikasi tag gagal)."""
    pass


def derive_key(password: bytes, salt: bytes, kdf: str = "argon2") -> bytes:
    """Menurunkan kunci 256-bit dari kata sandi + salt acak."""
    if kdf == "pbkdf2":
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, iterations=600_000
        ).derive(password)
    elif kdf == "scrypt":
        return Scrypt(salt=salt, length=KEY_LEN, n=2**15, r=8, p=1).derive(password)
    elif kdf == "argon2":
        if not ARGON2_AVAILABLE:
            # fallback aman bila library argon2-cffi tidak tersedia
            return Scrypt(salt=salt, length=KEY_LEN, n=2**15, r=8, p=1).derive(password)
        return hash_secret_raw(
            secret=password, salt=salt, time_cost=3, memory_cost=65536,
            parallelism=4, hash_len=KEY_LEN, type=Type.ID,
        )
    raise ValueError(f"KDF tidak dikenal: {kdf}")


def encrypt_bytes(plaintext: bytes, password: str, algo: str = "aes-gcm", kdf: str = "argon2") -> dict:
    """Mengenkripsi data. Mengembalikan dict berisi salt, nonce, ciphertext (semua base64) + metadata."""
    if algo not in ALGOS:
        raise ValueError(f"Algoritma tidak dikenal: {algo}")
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LENS[algo])
    key = derive_key(password.encode(), salt, kdf)
    cipher = ALGOS[algo](key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)  # tag AEAD sudah tergabung di akhir ciphertext
    return {
        "algo": algo,
        "kdf": kdf,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def decrypt_bytes(payload: dict, password: str) -> bytes:
    """Mendekripsi. Melempar DecryptionError bila password salah atau data telah diubah."""
    try:
        algo = payload["algo"]
        kdf = payload["kdf"]
        salt = base64.b64decode(payload["salt"])
        nonce = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["ciphertext"])
        key = derive_key(password.encode(), salt, kdf)
        cipher = ALGOS[algo](key)
        return cipher.decrypt(nonce, ciphertext, None)
    except (InvalidTag, KeyError, ValueError, base64.binascii.Error) as e:
        raise DecryptionError("Dekripsi gagal: kata sandi salah atau data telah diubah") from e


def payload_to_json(payload: dict) -> str:
    return json.dumps(payload)


def payload_from_json(s: str) -> dict:
    return json.loads(s)
