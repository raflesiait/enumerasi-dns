# 🚀 DNS Enum UI — Fast & Reliable DNS Brute Force Tool (dnsenum-like)

DNS Enum UI adalah **tool DNS enumeration berbasis Python** dengan tampilan **realtime + progress bar**, dirancang agar:
- ⚡ cepat
- 👀 terlihat jelas sedang berjalan
- 🎯 hasilnya **konsisten seperti `dnsenum`**
- 🧠 cocok untuk lab **CPTS / HTB / internal DNS**

Tool ini dibuat karena `dnsenum`:
- lambat,
- tidak ada progress,
- sering bikin ragu apakah masih jalan atau hang.

---

## ✨ Fitur Utama

✅ Multi-threaded (bisa diatur)  
✅ Realtime output (hasil langsung muncul)  
✅ Progress bar + RPS + ETA  
✅ Retry + backoff (anti miss record)  
✅ TCP fallback (anti UDP throttling)  
✅ Support wordlist internal (fierce-hostlist)  
✅ Filter IP suffix (contoh: `.203`)  

---

## 📦 Requirements

- Python **3.8+**
- Kali Linux / Linux (tested on Kali)

### Install dependency
```bash
sudo apt update && sudo apt install -y python3-pip && pip3 install --user dnspython rich



📥 Instalasi

Clone repository:

git clone https://github.com/USERNAME/dns-enum-ui.git && cd dns-enum-ui


Buat script executable:

chmod +x dns_enum_ui.py



🧠 Konsep Singkat

Tool ini melakukan:
brute force hostname → host.domain
query DNS langsung ke authoritative server
lebih toleran terhadap:
latency
throttling
packet loss
(seperti perilaku dnsenum)

📚 Wordlist yang Direkomendasikan (PENTING)

⚠️ Hint CPTS: different wordlists do not always have the same entries

Gunakan wordlist host internal, bukan subdomain web umum.

✅ Recommended

/usr/share/seclists/Discovery/DNS/fierce-hostlist.txt

Berisi hostname seperti:
win2k
dc
fs
sql
exchange
vpn

⚙️ Opsi Parameter
Parameter	Fungsi
--dns	DNS server target (authoritative)
--domain	Domain / subdomain target
--wordlist	Daftar hostname
--threads	Jumlah concurrent thread
--timeout	Timeout DNS query
--retries	Retry jika timeout
--tcp-fallback	Fallback TCP jika UDP gagal
--suffix	Filter IP (mis. .203)
--show-all	Tampilkan semua hasil
--out	Simpan output ke file

▶️ Contoh Penggunaan
1️⃣ Enumerasi DNS dengan output realtime + progress
./dns_enum_ui.py --dns 10.129.22.65 --domain dev.inlanefreight.htb --wordlist /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt --threads 50 --timeout 2.5 --retries 2 --tcp-fallback --show-all


📌 Output contoh:

[+] dev1.dev.inlanefreight.htb -> A:10.12.3.6
[+] ns.dev.inlanefreight.htb -> A:127.0.0.1
[+] sensor.dev.inlanefreight.htb -> A:10.12.3.000

2️⃣ Cari host dengan IP tertentu (contoh .203)
./dns_enum_ui.py --dns 10.129.22.65 --domain dev.inlanefreight.htb --wordlist /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt --threads 50 --timeout 2.5 --retries 2 --tcp-fallback --suffix .203


📌 Sangat berguna untuk soal seperti:

What is the FQDN of the host where the last octet ends with "203"?

3️⃣ Simpan hasil ke file
./dns_enum_ui.py --dns 10.129.22.65 --domain dev.inlanefreight.htb --wordlist /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt --threads 50 --timeout 2.5 --retries 2 --tcp-fallback --show-all --out result_dns.txt


