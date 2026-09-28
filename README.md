# CryptoVault — Aplikasi Enkripsi Modern

Tugas Proyek Aplikasi Kriptografi — Mata Kuliah Keamanan Informasi
Program Studi Informatika, Fakultas Teknik, Universitas Siliwangi
**Topik A: Aplikasi Enkripsi (Algoritma Modern)**

## Deskripsi

CryptoVault adalah aplikasi web (Flask) untuk mengenkripsi dan mendekripsi teks maupun berkas
memakai algoritma kriptografi modern **AES-256-GCM** dan **ChaCha20-Poly1305**. Kunci diturunkan
dari kata sandi pengguna memakai KDF pilihan (**Argon2id**, **scrypt**, atau **PBKDF2-HMAC-SHA256**)
dengan salt acak, dan setiap enkripsi memakai IV/nonce baru yang dibangkitkan secara acak.
Aplikasi menolak dekripsi apabila kata sandi salah atau cipherteks telah diubah, karena kedua
algoritma tersebut memakai skema AEAD (Authenticated Encryption with Associated Data) yang
memverifikasi tag otentikasi sebelum mengembalikan plainteks.

Fitur pengayaan: **enkripsi hibrida** — kunci sesi AES-256-GCM acak dibungkus dengan **RSA-OAEP**
(kunci publik penerima), meniru pola pertukaran kunci pada dunia nyata (mis. PGP/S-MIME).

## Anggota Kelompok

| Nama | NPM |

| (Alief Mufqi alwany)          | (247006111082) |
| (Ilham Sutiyoso Surahman)     | (247006111085) |
| (Mohammad Rizal Ramadan)      | (247006111112) |

## Struktur Proyek

```
kripto-app/
├── app.py                  # Aplikasi Flask (routing & API)
├── crypto/
│   ├── symmetric.py         # AES-256-GCM, ChaCha20-Poly1305, KDF (Argon2/scrypt/PBKDF2)
│   └── hybrid.py             # Enkripsi hibrida RSA-OAEP (fitur pengayaan)
├── templates/index.html      # Antarmuka web
├── tests/test_crypto.py      # 8 unit test (min. 5 sesuai ketentuan)
├── benchmark/run_benchmark.py# Skrip pengujian kuantitatif -> hasil_pengujian.xlsx
├── sample_data/               # 13 berkas sampel (termasuk gambar & PDF) untuk pengujian
├── hasil_pengujian.xlsx       # Keluaran pengujian (dibuat oleh run_benchmark.py)
└── requirements.txt
```

## Cara Instalasi

Prasyarat: Python 3.10+

```bash
git clone <url-repositori-anda>
cd kripto-app
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Cara Menjalankan

**Menjalankan aplikasi web:**
```bash
python3 app.py
```
Buka `http://localhost:5000` di peramban. Tiga tab tersedia: **Teks**, **Berkas**, dan **Hibrida (RSA-OAEP)**.

**Menjalankan unit test:**
```bash
python -m pytest tests/ -v
```

**Menjalankan pengujian kuantitatif (menghasilkan `hasil_pengujian.xlsx`):**
```bash
python3 benchmark/run_benchmark.py
```

## Contoh Penggunaan

### Enkripsi teks lewat antarmuka web
1. Buka tab **Teks**, isi plainteks dan kata sandi.
2. Pilih algoritma (AES-256-GCM / ChaCha20-Poly1305) dan KDF (Argon2id / scrypt / PBKDF2).
3. Klik **Enkripsi** → bundle base64 (berisi salt, nonce, cipherteks) ditampilkan.
4. Untuk dekripsi, tempel bundle tersebut di tab **Dekripsi** beserta kata sandi yang sama.

### Enkripsi teks lewat API (curl)
```bash
curl -X POST http://localhost:5000/api/encrypt/text \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"data rahasia","password":"kata-sandi-kuat","algo":"aes-gcm","kdf":"argon2"}'
```

### Enkripsi berkas
1. Buka tab **Berkas**, unggah berkas apa pun (gambar, PDF, dsb.), isi kata sandi.
2. Klik **Enkripsi & Unduh** → berkas `<nama>.enc.json` terunduh otomatis.
3. Untuk dekripsi, unggah berkas `.enc.json` tersebut di bagian **Dekripsi Berkas** dengan kata sandi yang sama.

### Enkripsi hibrida (RSA-OAEP)
1. Buka tab **Hibrida**, klik **Bangkitkan Kunci RSA-2048** (mensimulasikan penerima).
2. Salin kunci publik ke bagian enkripsi (mensimulasikan pengirim), isi plainteks, klik **Enkripsi Hibrida**.
3. Salin payload hasil ke bagian dekripsi bersama `key_id` yang sama, klik **Dekripsi Hibrida**.

## Skenario Demo UTS

1. Enkripsi satu berkas PDF lewat tab Berkas.
2. Tunjukkan isi cipherteks (bundle `.enc.json`) — tidak terbaca / tampak acak.
3. Dekripsi dengan kata sandi benar → berkas PDF asli kembali utuh.
4. Coba dekripsi dengan kata sandi salah → aplikasi menolak (`DecryptionError`).
5. Ubah satu byte pada berkas `.enc.json` lalu coba dekripsi → aplikasi menolak (verifikasi tag AEAD gagal).

## Keamanan yang Diterapkan

- Kunci diturunkan dari kata sandi via Argon2id/scrypt/PBKDF2 (>= 600.000 iterasi untuk PBKDF2) dengan salt 128-bit acak per enkripsi.
- Nonce/IV 96-bit dibangkitkan `os.urandom` per enkripsi — tidak pernah dipakai ulang dengan kunci yang sama.
- Skema AEAD (GCM / Poly1305) menjamin integritas dan keaslian, bukan hanya kerahasiaan.
- Tidak ada kunci, kata sandi, atau kunci privat yang ditulis langsung di kode sumber.
- Kunci privat RSA pada fitur hibrida hanya disimpan di memori server untuk keperluan demo — pada implementasi produksi harus dienkripsi at-rest.

## Batasan

- Penyimpanan kunci privat RSA in-memory pada `app.py` hanya untuk demo; hilang saat server direstart.
- Ukuran unggah dibatasi 50 MB (`MAX_CONTENT_LENGTH`) — dapat diubah di `app.py`.
