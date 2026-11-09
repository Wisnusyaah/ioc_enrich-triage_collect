Scripting & automation

| File | Isi |
|---|---|
| `ioc_enrich.py` | Validasi dan enrichment IOC (Python 3, tanpa library tambahan) |
| `iocs.txt` | Contoh input: IOC insiden FIN-WS-047 ditambah entri invalid untuk tes |
| `ioc_results.json`, `ioc_results.csv` | Contoh output dari mode mock |
| `triage_collect.ps1` | Triage collector untuk host Windows (PowerShell 5.1+) |

## 1. IOC enrichment

Cara menjalankan:

```
python ioc_enrich.py              # baca iocs.txt
python ioc_enrich.py file_lain.txt
```

Untuk VirusTotal asli, isi variabel `API_KEY` di bagian atas `ioc_enrich.py`. Kalau dikosongkan, script memakai data mock. Hasil ditulis ke `ioc_results.json` dan `ioc_results.csv`.

Cara kerja:

1. Validasi. IPv4 harus 4 angka 0 sampai 255. Hash dikenali dari panjang hex (32 MD5, 40 SHA1, 64 SHA256). Domain harus punya label huruf/angka/tanda hubung dan TLD huruf. Selain itu dibuang. Penulisan defang `[.]` dikembalikan jadi `.` dulu.
2. Enrichment ke VirusTotal API v3, atau mock kalau tidak ada key.
3. Rate limit: jeda 15 detik antar request (kuota gratis 4 per menit). Kalau kena HTTP 429, tunggu 60 detik lalu coba lagi, maksimal 3 kali. Timeout atau error jaringan juga di-retry. Error lain (misalnya 401 karena key salah) dicatat di kolom `note` dan script lanjut ke IOC berikutnya.
4. Verdict: `malicious` kalau minimal 3 engine mendeteksi, `suspicious` kalau 1 sampai 2, `clean` kalau 0, dan `unknown` kalau data tidak didapat. Skor adalah persentase engine yang mendeteksi.

Asumsi: hanya memakai standard library Python 3. `185.220.x.x` di log disamarkan, jadi di `iocs.txt` diganti contoh `185.220.101.4`. Hash contoh adalah hash file uji EICAR karena hash msupd.dll tidak tersedia. Ambang 3 engine bisa disesuaikan dengan kebijakan SOC.

## 2. Triage collector

### Cara menjalankan

Buka PowerShell sebagai Administrator, lalu:

```
powershell -ExecutionPolicy Bypass -File .\triage_collect.ps1
powershell -ExecutionPolicy Bypass -File .\triage_collect.ps1 -OutputRoot D:\IR -Zip
```

Output masuk ke folder `triage_<HOSTNAME>_<yyyyMMdd_HHmmss>Z`:

| File | Isi |
|---|---|
| `processes.csv` | PID, PPID, nama parent, command line, path, owner, waktu dibuat |
| `network_tcp.csv`, `network_udp.csv` | Koneksi dan endpoint aktif beserta PID dan nama proses (`netstat.txt` kalau cmdlet tidak tersedia) |
| `autoruns.csv` | Nilai Run dan RunOnce di HKLM dan hive setiap user yang sedang login, termasuk WOW6432Node |
| `logged_on_users.csv`, `quser.txt` | Sesi login interaktif, RDP, dan cached |
| `collection.log` | Status tiap modul |
| `hashes_sha256.csv` | SHA256 setiap file di atas |

Dengan `-Zip`, folder juga dikemas jadi `.zip` dan hash SHA256 zip-nya ditampilkan di layar.

### Asumsi

- Host target Windows 10/11 atau Server 2016 ke atas dengan Windows PowerShell 5.1. Tidak butuh Python atau tool tambahan.
- Dijalankan sebagai Administrator atau SYSTEM (lewat live response EDR). Tanpa hak admin, command line proses milik user lain bisa kosong, dan script mencatat peringatan di log.
- Script hanya membaca. Tidak ada proses yang dimatikan dan tidak ada nilai registry yang diubah.
- Setiap modul berdiri sendiri. Kalau satu modul gagal, modul lain tetap jalan dan error-nya dicatat di `collection.log`.
- Waktu memakai UTC supaya mudah dikorelasikan dengan SIEM.

## 3. Desain playbook SOAR untuk alert "Suspicious PowerShell"

Trigger: alert EDR "Suspicious PowerShell" masuk ke SOAR, lalu SOAR membuat tiket dan mengisi host, user, command line, dan parent process.

Langkah otomatis:

1. Decode argumen `-enc` (Base64 UTF-16LE) dan ambil domain, IP, URL, dan hash dari command line serta telemetri EDR host itu 30 menit terakhir.
2. Jalankan `ioc_enrich.py` untuk semua IOC tersebut.
3. Jalankan `triage_collect.ps1 -Zip` lewat live response EDR, lalu simpan zip dan hash-nya ke evidence store.
4. Naikkan severity ke critical kalau ada IOC dengan verdict malicious, parent proses berupa aplikasi Office, atau ada akses ke lsass di host yang sama.
5. Cari IOC yang sama di SIEM untuk host lain (proxy, DNS, EDR), lalu tambahkan hasilnya ke tiket.

Titik keputusan manusia:

- Isolasi host. Untuk severity critical, SOAR menyiapkan aksi isolasi dan analis tinggal menyetujui. Isolasi otomatis tanpa persetujuan hanya untuk kombinasi Office → PowerShell plus IOC malicious, karena peluang false positive-nya kecil.
- Blok IOC di proxy, DNS, dan firewall. Analis memastikan IOC bukan layanan bersama, misalnya IP shared hosting.
- Reset password dan pencabutan sesi akun yang terlibat. Untuk akun service seperti svc_backup, keputusan ada di analis bersama pemilik sistem karena bisa menghentikan job backup.
- Eskalasi ke tim IR dan pelibatan legal/DPO jika ada indikasi exfiltration.

Output ke tiket: ringkasan alert, command line yang sudah di-decode, process tree, tabel IOC dengan skor dan verdict, host lain yang terkait, path dan SHA256 paket triage, severity akhir beserta alasannya, serta tindakan yang sudah dan belum disetujui. Tiket ditutup oleh analis, bukan oleh SOAR.
