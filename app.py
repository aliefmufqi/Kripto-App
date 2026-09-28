"""
Aplikasi Web Enkripsi (Topik A)
Keamanan Informasi - Tugas Proyek Aplikasi Kriptografi

Fitur:
- Enkripsi/dekripsi teks & berkas dengan AES-256-GCM atau ChaCha20-Poly1305
- KDF: PBKDF2 / scrypt / Argon2 dengan salt acak
- Enkripsi hibrida (RSA-OAEP) sebagai fitur pengayaan
"""
import os
import io
import base64
import json
from flask import Flask, render_template, request, jsonify, send_file

from crypto.symmetric import encrypt_bytes, decrypt_bytes, DecryptionError
from crypto import hybrid

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB

# Simpan pasangan kunci RSA demo hybrid IN-MEMORY (untuk keperluan demo saja,
# di produksi kunci privat harus disimpan terenkripsi & di luar kode sumber)
_hybrid_keys = {}


@app.route("/")
def index():
    return render_template("index.html")


# ---------- Enkripsi/Dekripsi Teks ----------
@app.route("/api/encrypt/text", methods=["POST"])
def encrypt_text():
    data = request.get_json(force=True)
    plaintext = data.get("plaintext", "")
    password = data.get("password", "")
    algo = data.get("algo", "aes-gcm")
    kdf = data.get("kdf", "argon2")

    if not plaintext or not password:
        return jsonify({"error": "plaintext dan password wajib diisi"}), 400

    payload = encrypt_bytes(plaintext.encode("utf-8"), password, algo=algo, kdf=kdf)
    return jsonify({"payload": payload, "payload_b64_bundle": base64.b64encode(json.dumps(payload).encode()).decode()})


@app.route("/api/decrypt/text", methods=["POST"])
def decrypt_text():
    data = request.get_json(force=True)
    password = data.get("password", "")
    bundle = data.get("payload_b64_bundle", "")

    try:
        payload = json.loads(base64.b64decode(bundle))
        plaintext = decrypt_bytes(payload, password)
        return jsonify({"plaintext": plaintext.decode("utf-8")})
    except DecryptionError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        return jsonify({"error": "Format data tidak valid"}), 400


# ---------- Enkripsi/Dekripsi Berkas ----------
@app.route("/api/encrypt/file", methods=["POST"])
def encrypt_file():
    if "file" not in request.files:
        return jsonify({"error": "berkas wajib diunggah"}), 400
    f = request.files["file"]
    password = request.form.get("password", "")
    algo = request.form.get("algo", "aes-gcm")
    kdf = request.form.get("kdf", "argon2")

    if not password:
        return jsonify({"error": "password wajib diisi"}), 400

    plaintext = f.read()
    payload = encrypt_bytes(plaintext, password, algo=algo, kdf=kdf)
    payload["original_filename"] = f.filename

    bundle_bytes = json.dumps(payload).encode()
    return send_file(
        io.BytesIO(bundle_bytes),
        as_attachment=True,
        download_name=f"{f.filename}.enc.json",
        mimetype="application/json",
    )


@app.route("/api/decrypt/file", methods=["POST"])
def decrypt_file():
    if "file" not in request.files:
        return jsonify({"error": "berkas wajib diunggah"}), 400
    f = request.files["file"]
    password = request.form.get("password", "")

    try:
        payload = json.loads(f.read())
        plaintext = decrypt_bytes(payload, password)
        original_name = payload.get("original_filename", "decrypted.bin")
        return send_file(
            io.BytesIO(plaintext),
            as_attachment=True,
            download_name=original_name,
        )
    except DecryptionError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        return jsonify({"error": "Berkas terenkripsi tidak valid atau rusak"}), 400


# ---------- Enkripsi Hibrida (RSA-OAEP) ----------
@app.route("/api/hybrid/generate-keys", methods=["POST"])
def hybrid_generate_keys():
    priv, pub = hybrid.generate_rsa_keypair()
    key_id = base64.urlsafe_b64encode(os.urandom(6)).decode()
    _hybrid_keys[key_id] = priv
    pub_pem = hybrid.serialize_public_key(pub).decode()
    return jsonify({"key_id": key_id, "public_key_pem": pub_pem})


@app.route("/api/hybrid/encrypt", methods=["POST"])
def hybrid_encrypt_route():
    data = request.get_json(force=True)
    plaintext = data.get("plaintext", "")
    pub_pem = data.get("public_key_pem", "")
    try:
        pub = hybrid.load_public_key(pub_pem.encode())
        payload = hybrid.hybrid_encrypt(plaintext.encode("utf-8"), pub)
        return jsonify({"payload": payload})
    except Exception as e:
        return jsonify({"error": f"Enkripsi hibrida gagal: {e}"}), 400


@app.route("/api/hybrid/decrypt", methods=["POST"])
def hybrid_decrypt_route():
    data = request.get_json(force=True)
    key_id = data.get("key_id", "")
    payload = data.get("payload", {})
    priv = _hybrid_keys.get(key_id)
    if not priv:
        return jsonify({"error": "key_id tidak dikenal (kunci privat hanya ada di memori server demo)"}), 400
    try:
        plaintext = hybrid.hybrid_decrypt(payload, priv)
        return jsonify({"plaintext": plaintext.decode("utf-8")})
    except Exception as e:
        return jsonify({"error": f"Dekripsi hibrida gagal: {e}"}), 400


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
