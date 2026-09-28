"""
Skrip pengujian kuantitatif wajib (Bagian 3, Topik A) untuk laporan teknis.
Menghasilkan: hasil_pengujian.xlsx dengan beberapa sheet.

Uji yang dijalankan:
1. Kebenaran dekripsi pada >= 10 masukan berbeda (termasuk gambar & PDF)
2. Waktu enkripsi/dekripsi untuk berkas 1 KB, 1 MB, 10 MB
3. Avalanche effect (persentase bit cipherteks berubah bila 1 bit plaintext/kunci berubah)
4. Entropi & histogram byte cipherteks vs plainteks
5. Perbandingan AES-256-GCM vs ChaCha20-Poly1305
"""
import sys, os, time, math, glob
from collections import Counter
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crypto.symmetric import encrypt_bytes, decrypt_bytes

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "sample_data")
OUT_XLSX = os.path.join(os.path.dirname(__file__), "..", "hasil_pengujian.xlsx")
PASSWORD = "TestPassword!2026"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def byte_histogram(data: bytes) -> list:
    counts = Counter(data)
    return [counts.get(i, 0) for i in range(256)]


def hamming_distance_bits(a: bytes, b: bytes) -> int:
    diff = 0
    for x, y in zip(a, b):
        diff += bin(x ^ y).count("1")
    return diff


# ---------- 1. Kebenaran dekripsi pada >= 10 masukan ----------
def test_correctness():
    results = []
    files = sorted(glob.glob(os.path.join(SAMPLE_DIR, "*")))
    for algo in ["aes-gcm", "chacha20-poly1305"]:
        for fp in files:
            with open(fp, "rb") as f:
                data = f.read()
            payload = encrypt_bytes(data, PASSWORD, algo=algo, kdf="argon2")
            recovered = decrypt_bytes(payload, PASSWORD)
            results.append({
                "algoritma": algo,
                "berkas": os.path.basename(fp),
                "ukuran_bytes": len(data),
                "benar": recovered == data,
            })
    return results


# ---------- 2. Waktu enkripsi/dekripsi 1KB/1MB/10MB ----------
def test_timing():
    results = []
    size_files = {
        "1KB": os.path.join(SAMPLE_DIR, "text_small_1kb.bin"),
        "1MB": os.path.join(SAMPLE_DIR, "text_1mb.bin"),
        "10MB": os.path.join(SAMPLE_DIR, "text_10mb.bin"),
    }
    for algo in ["aes-gcm", "chacha20-poly1305"]:
        for label, fp in size_files.items():
            with open(fp, "rb") as f:
                data = f.read()
            # rata-rata dari 5 percobaan
            enc_times, dec_times = [], []
            for _ in range(5):
                t0 = time.perf_counter()
                payload = encrypt_bytes(data, PASSWORD, algo=algo, kdf="pbkdf2")
                t1 = time.perf_counter()
                decrypt_bytes(payload, PASSWORD)
                t2 = time.perf_counter()
                enc_times.append(t1 - t0)
                dec_times.append(t2 - t1)
            results.append({
                "algoritma": algo,
                "ukuran": label,
                "waktu_enkripsi_rata_rata_ms": round(sum(enc_times) / len(enc_times) * 1000, 3),
                "waktu_dekripsi_rata_rata_ms": round(sum(dec_times) / len(dec_times) * 1000, 3),
            })
    return results


# ---------- 3. Avalanche effect ----------
def test_avalanche():
    results = []
    base_plain = os.urandom(256)
    base_password = "AvalancheTest123"

    for algo in ["aes-gcm", "chacha20-poly1305"]:
        # a) ubah 1 bit plaintext
        payload1 = encrypt_bytes(base_plain, base_password, algo=algo, kdf="pbkdf2")
        # gunakan salt & nonce YANG SAMA secara manual agar perbandingan adil (mengukur efek cipher, bukan salt/nonce acak)
        from crypto.symmetric import derive_key, ALGOS
        import base64
        salt = base64.b64decode(payload1["salt"])
        nonce = base64.b64decode(payload1["nonce"])
        key = derive_key(base_password.encode(), salt, "pbkdf2")
        cipher = ALGOS[algo](key)

        ct1 = cipher.encrypt(nonce, base_plain, None)
        flipped_plain = bytearray(base_plain)
        flipped_plain[0] ^= 0x01
        ct2 = cipher.encrypt(nonce, bytes(flipped_plain), None)
        bits_changed = hamming_distance_bits(ct1, ct2)
        pct_plain = bits_changed / (len(ct1) * 8) * 100

        # b) ubah 1 bit kunci
        flipped_key = bytearray(key)
        flipped_key[0] ^= 0x01
        cipher2 = ALGOS[algo](bytes(flipped_key))
        ct3 = cipher2.encrypt(nonce, base_plain, None)
        bits_changed_key = hamming_distance_bits(ct1, ct3)
        pct_key = bits_changed_key / (len(ct1) * 8) * 100

        results.append({
            "algoritma": algo,
            "persen_bit_berubah_1bit_plaintext": round(pct_plain, 2),
            "persen_bit_berubah_1bit_kunci": round(pct_key, 2),
            "ideal_acak_sekitar": 50.0,
        })
    return results


# ---------- 4. Entropi & histogram ----------
def test_entropy():
    results = []
    fp = os.path.join(SAMPLE_DIR, "sample_document.pdf")
    with open(fp, "rb") as f:
        plain = f.read()
    for algo in ["aes-gcm", "chacha20-poly1305"]:
        payload = encrypt_bytes(plain, PASSWORD, algo=algo, kdf="pbkdf2")
        import base64
        ct = base64.b64decode(payload["ciphertext"])
        results.append({
            "algoritma": algo,
            "entropi_plainteks_bit_per_byte": round(shannon_entropy(plain), 4),
            "entropi_cipherteks_bit_per_byte": round(shannon_entropy(ct), 4),
            "ideal_maksimum": 8.0,
        })
    return results, plain, {
        algo: base64.b64decode(encrypt_bytes(plain, PASSWORD, algo=algo, kdf="pbkdf2")["ciphertext"])
        for algo in ["aes-gcm", "chacha20-poly1305"]
    }


def main():
    print("Menjalankan pengujian kebenaran...")
    correctness = test_correctness()
    n_ok = sum(r["benar"] for r in correctness)
    print(f"  {n_ok}/{len(correctness)} kasus benar")

    print("Menjalankan pengujian waktu (timing)...")
    timing = test_timing()

    print("Menjalankan pengujian avalanche effect...")
    avalanche = test_avalanche()

    print("Menjalankan pengujian entropi & histogram...")
    entropy_results, plain_sample, ct_samples = test_entropy()

    # ---------- Tulis ke Excel ----------
    import openpyxl
    from openpyxl.chart import BarChart, LineChart, Reference
    from openpyxl.styles import Font, PatternFill

    HEADER_FONT = Font(name="Arial", bold=True, color="FFFFFF")
    HEADER_FILL = PatternFill("solid", fgColor="2F3B47")
    BODY_FONT = Font(name="Arial")

    def style_header(ws, ncols):
        for col in range(1, ncols + 1):
            c = ws.cell(row=1, column=col)
            c.font = HEADER_FONT
            c.fill = HEADER_FILL
        for row in ws.iter_rows(min_row=2):
            for c in row:
                c.font = BODY_FONT
        for col_cells in ws.columns:
            length = max(len(str(c.value)) if c.value is not None else 0 for c in col_cells)
            ws.column_dimensions[col_cells[0].column_letter].width = max(12, length + 2)

    wb = openpyxl.Workbook()

    # Sheet 1: Kebenaran
    ws1 = wb.active
    ws1.title = "Kebenaran Dekripsi"
    ws1.append(["Algoritma", "Berkas", "Ukuran (bytes)", "Benar"])
    for r in correctness:
        ws1.append([r["algoritma"], r["berkas"], r["ukuran_bytes"], "YA" if r["benar"] else "TIDAK"])

    # Sheet 2: Timing
    ws2 = wb.create_sheet("Waktu Proses")
    ws2.append(["Algoritma", "Ukuran", "Waktu Enkripsi (ms)", "Waktu Dekripsi (ms)"])
    for r in timing:
        ws2.append([r["algoritma"], r["ukuran"], r["waktu_enkripsi_rata_rata_ms"], r["waktu_dekripsi_rata_rata_ms"]])
    chart = BarChart()
    chart.title = "Waktu Enkripsi per Ukuran Berkas"
    chart.y_axis.title = "ms"
    data_ref = Reference(ws2, min_col=3, min_row=1, max_row=len(timing) + 1)
    cats_ref = Reference(ws2, min_col=2, min_row=2, max_row=len(timing) + 1)
    chart.add_data(data_ref, titles_from_data=True)
    chart.set_categories(cats_ref)
    ws2.add_chart(chart, "F2")

    # Sheet 3: Avalanche
    ws3 = wb.create_sheet("Avalanche Effect")
    ws3.append(["Algoritma", "% Bit Berubah (1-bit plaintext)", "% Bit Berubah (1-bit kunci)", "Ideal (acak)"])
    for r in avalanche:
        ws3.append([r["algoritma"], r["persen_bit_berubah_1bit_plaintext"], r["persen_bit_berubah_1bit_kunci"], r["ideal_acak_sekitar"]])

    # Sheet 4: Entropi
    ws4 = wb.create_sheet("Entropi")
    ws4.append(["Algoritma", "Entropi Plainteks (bit/byte)", "Entropi Cipherteks (bit/byte)", "Ideal Maks"])
    for r in entropy_results:
        ws4.append([r["algoritma"], r["entropi_plainteks_bit_per_byte"], r["entropi_cipherteks_bit_per_byte"], r["ideal_maksimum"]])

    # Sheet 5: Histogram byte (plain vs cipher AES-GCM sebagai contoh)
    ws5 = wb.create_sheet("Histogram Byte")
    ws5.append(["Nilai Byte (0-255)", "Frekuensi Plainteks", "Frekuensi Cipherteks (AES-GCM)", "Frekuensi Cipherteks (ChaCha20)"])
    hist_plain = byte_histogram(plain_sample)
    hist_ct_aes = byte_histogram(ct_samples["aes-gcm"])
    hist_ct_chacha = byte_histogram(ct_samples["chacha20-poly1305"])
    for i in range(256):
        ws5.append([i, hist_plain[i], hist_ct_aes[i], hist_ct_chacha[i]])
    hist_chart = LineChart()
    hist_chart.title = "Histogram Byte: Plainteks vs Cipherteks"
    hist_chart.y_axis.title = "Frekuensi"
    hist_chart.x_axis.title = "Nilai byte"
    data_ref = Reference(ws5, min_col=2, max_col=4, min_row=1, max_row=257)
    hist_chart.add_data(data_ref, titles_from_data=True)
    ws5.add_chart(hist_chart, "F2")

    style_header(ws1, 4)
    style_header(ws2, 4)
    style_header(ws3, 4)
    style_header(ws4, 4)
    style_header(ws5, 4)

    wb.save(OUT_XLSX)
    print(f"\nHasil pengujian tersimpan di: {OUT_XLSX}")


if __name__ == "__main__":
    main()
