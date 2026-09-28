"""
Unit test untuk fungsi inti (Ketentuan Teknis Umum: minimal 5 unit test).
Jalankan: python -m pytest tests/ -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from crypto.symmetric import encrypt_bytes, decrypt_bytes, DecryptionError, derive_key
from crypto.hybrid import generate_rsa_keypair, hybrid_encrypt, hybrid_decrypt


# 1. Round-trip dasar AES-256-GCM
def test_aes_gcm_roundtrip():
    payload = encrypt_bytes(b"data rahasia", "password-kuat", algo="aes-gcm", kdf="pbkdf2")
    assert decrypt_bytes(payload, "password-kuat") == b"data rahasia"


# 2. Round-trip dasar ChaCha20-Poly1305
def test_chacha20_roundtrip():
    payload = encrypt_bytes(b"data rahasia lain", "password-kuat", algo="chacha20-poly1305", kdf="scrypt")
    assert decrypt_bytes(payload, "password-kuat") == b"data rahasia lain"


# 3. Dekripsi wajib gagal bila password salah
def test_wrong_password_rejected():
    payload = encrypt_bytes(b"rahasia", "benar123", algo="aes-gcm", kdf="argon2")
    with pytest.raises(DecryptionError):
        decrypt_bytes(payload, "salah456")


# 4. Dekripsi wajib gagal bila ciphertext diubah (tamper -> tag verification gagal)
def test_tampered_ciphertext_rejected():
    payload = encrypt_bytes(b"jangan diubah", "sandi", algo="aes-gcm", kdf="pbkdf2")
    # Ubah satu karakter base64 ciphertext untuk mensimulasikan tampering
    ct = list(payload["ciphertext"])
    ct[0] = "A" if ct[0] != "A" else "B"
    payload["ciphertext"] = "".join(ct)
    with pytest.raises(DecryptionError):
        decrypt_bytes(payload, "sandi")


# 5. Salt dan nonce harus acak & unik tiap enkripsi (walau plaintext & password sama)
def test_salt_and_nonce_are_unique_per_encryption():
    p1 = encrypt_bytes(b"sama persis", "sandi-sama", algo="aes-gcm", kdf="pbkdf2")
    p2 = encrypt_bytes(b"sama persis", "sandi-sama", algo="aes-gcm", kdf="pbkdf2")
    assert p1["salt"] != p2["salt"]
    assert p1["nonce"] != p2["nonce"]
    assert p1["ciphertext"] != p2["ciphertext"]  # ciphertext ikut berbeda meski plaintext sama


# 6. KDF deterministik: salt sama + password sama -> kunci sama
def test_kdf_deterministic_given_same_salt():
    salt = os.urandom(16)
    k1 = derive_key(b"password", salt, kdf="pbkdf2")
    k2 = derive_key(b"password", salt, kdf="pbkdf2")
    assert k1 == k2
    assert len(k1) == 32  # AES-256 / ChaCha20 butuh kunci 256-bit


# 7. Enkripsi hibrida RSA-OAEP round-trip
def test_hybrid_rsa_oaep_roundtrip():
    priv, pub = generate_rsa_keypair()
    payload = hybrid_encrypt(b"pesan sangat rahasia", pub)
    assert hybrid_decrypt(payload, priv) == b"pesan sangat rahasia"


# 8. Enkripsi hibrida gagal didekripsi dengan kunci privat yang salah
def test_hybrid_wrong_private_key_rejected():
    priv1, pub1 = generate_rsa_keypair()
    priv2, _ = generate_rsa_keypair()
    payload = hybrid_encrypt(b"pesan", pub1)
    with pytest.raises(Exception):
        hybrid_decrypt(payload, priv2)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
