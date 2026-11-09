import csv, json, os, re, sys, time
import urllib.request, urllib.error

# Isi API key VirusTotal di sini. KOSONGKAN lagi sebelum script dikumpulkan.
API_KEY = ""

# ---------- 1. Deteksi tipe IOC ----------
def detect_type(ioc):
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ioc):
        return "ipv4" if all(0 <= int(x) <= 255 for x in ioc.split(".")) else None
    if re.fullmatch(r"[0-9a-fA-F]+", ioc):
        return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(ioc))
    if re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.[a-z]{2,}", ioc.lower()):
        return "domain"
    return None

# ---------- 2. Ambil data dari VirusTotal (atau mock) ----------
def vt_lookup(ioc, ioc_type, api_key):
    path = {"ipv4": "ip_addresses", "domain": "domains"}.get(ioc_type, "files")
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/{path}/{ioc}",
                                 headers={"x-apikey": api_key})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)["data"]["attributes"]["last_analysis_stats"]

def mock_lookup(ioc, ioc_type, api_key):
    bad = ["198.51.100.37", "cdn-update-sync.net", "invoice-portal.co",
           "44d88612fea8a8f36de82e1278abb02f"]     # IOC insiden + hash uji EICAR
    return {"malicious": 40 if ioc in bad else 0, "suspicious": 0, "harmless": 50, "undetected": 20}

# ---------- 3. Rate limit & error handling ----------
def lookup_with_retry(lookup, ioc, ioc_type, api_key):
    for attempt in range(3):
        try:
            return lookup(ioc, ioc_type, api_key), ""
        except urllib.error.HTTPError as e:
            if e.code == 429:                      # kena rate limit: tunggu lalu coba lagi
                time.sleep(60)
                continue
            if e.code == 404:
                return None, "tidak ada di VirusTotal"
            return None, f"HTTP {e.code}"          # 401 dll: tidak perlu retry
        except Exception:                           # timeout / jaringan putus
            time.sleep(5)
    return None, "gagal setelah 3x coba"

# ---------- 4. Skor & verdict ----------
def verdict(stats):
    if stats is None:
        return None, "unknown"
    score = round(100 * stats["malicious"] / max(sum(stats.values()), 1))
    if stats["malicious"] >= 3:
        return score, "malicious"
    if stats["malicious"] >= 1 or stats["suspicious"] >= 1:
        return score, "suspicious"
    return score, "clean"

def load_env(path=".env"):
    if os.path.exists(path):
        for line in open(path):
            if "=" in line and not line.startswith("#"):
                key, val = line.strip().split("=", 1)
                os.environ.setdefault(key.strip(), val.strip().strip('"'))

def main():
    infile = sys.argv[1] if len(sys.argv) > 1 else "iocs.txt"
    load_env(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
    api_key = API_KEY or os.environ.get("VT_API_KEY")
    lookup = vt_lookup if api_key else mock_lookup
    print("Sumber:", "VirusTotal" if api_key else "mock")

    results = []
    for line in open(infile):
        ioc = line.strip().replace("[.]", ".")
        if not ioc or ioc.startswith("#"):
            continue
        ioc_type = detect_type(ioc)
        if ioc_type is None:
            print(f"  invalid, dibuang: {ioc}")
            continue
        if api_key:
            time.sleep(15)                         # kuota gratis: 4 request/menit
        stats, note = lookup_with_retry(lookup, ioc, ioc_type, api_key)
        score, v = verdict(stats)
        print(f"  {v:<10} {ioc_type:<7} {ioc}")
        results.append({"ioc": ioc, "type": ioc_type, "score": score, "verdict": v, "note": note})

    json.dump(results, open("ioc_results.json", "w"), indent=2)
    with open("ioc_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["ioc", "type", "score", "verdict", "note"])
        w.writeheader()
        w.writerows(results)
    print("Hasil: ioc_results.json dan ioc_results.csv")

if __name__ == "__main__":
    main()
