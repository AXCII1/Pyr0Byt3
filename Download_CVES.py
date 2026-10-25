from dotenv import load_dotenv
import requests
import json
import time
import os
import csv


load_dotenv()
API_KEY = os.getenv("NVD_API_KEY")
headers = {"apiKey": API_KEY}


print(f"[DEBUG] API Key loaded: {'Yes' if API_KEY else 'NO - CHECK .env FILE'}")


# ─── NVD BALANCED CPE DOWNLOAD ────────────────────────────


CPE_TARGETS = [
   ("linux",     "cpe:2.3:o:linux:linux_kernel:"),
   ("windows",   "cpe:2.3:o:microsoft:windows:"),
   ("apache",    "cpe:2.3:a:apache:http_server:"),
   ("android",   "cpe:2.3:o:google:android:"),
   ("macos",     "cpe:2.3:o:apple:macos:"),
   ("nginx",     "cpe:2.3:a:f5:nginx:"),
   ("ssh",       "cpe:2.3:a:openbsd:openssh:"),
   ("wordpress", "cpe:2.3:a:wordpress:wordpress:"),
]


def download_nvd_cpe(name, cpe):
   print(f"\n[*] Downloading {name} CVEs...")
   all_cves = []
   start_index = 0
   results_per_page = 2000


   while True:
       url = (
           f"https://services.nvd.nist.gov/rest/json/cves/2.0"
           f"?virtualMatchString={cpe}"
           f"&startIndex={start_index}"
           f"&resultsPerPage={results_per_page}"
       )


       for attempt in range(5):
           try:
               response = requests.get(url, headers=headers, timeout=60)
               print(f"  [DEBUG] Status: {response.status_code}")
               print(f"  [DEBUG] Response preview: {response.text[:500]}")
               response.raise_for_status()
               data = response.json()
               break
           except Exception as e:
               print(f"[!] Attempt {attempt + 1} failed: {e}")
               time.sleep(5)
       else:
           print(f"[!] All 5 attempts failed at startIndex={start_index}; giving up on {name}.")
           break


       vulnerabilities = data.get("vulnerabilities", [])
       total = data.get("totalResults", 0)
       all_cves.extend(vulnerabilities)
       print(f"  Fetched {len(all_cves)} / {total}")


       if total == 0:
           print(f"[!] No results returned for {name}, skipping.")
           break


       if start_index + results_per_page >= total:
           break


       start_index += results_per_page
       time.sleep(0.6)


   if all_cves:
       filename = f"{name}_cves.json"
       with open(filename, "w") as f:
           json.dump(all_cves, f)
       print(f"[+] Saved {len(all_cves)} {name} CVEs to {filename}")
   else:
       print(f"[!] No CVEs saved for {name}.")


# ─── CISA KEV DOWNLOAD ────────────────────────────────────


def download_cisa_kev():
   print("\n[*] Downloading CISA Known Exploited Vulnerabilities...")
   url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


   for attempt in range(5):
       try:
           response = requests.get(url, timeout=60)
           print(f"  [DEBUG] Status: {response.status_code}")
           response.raise_for_status()
           data = response.json()
           break
       except Exception as e:
           print(f"[!] Attempt {attempt + 1} failed: {e}")
           time.sleep(5)
   else:
       print("[!] Failed to download CISA KEV after 5 attempts.")
       return


   with open("cisa_kev.json", "w") as f:
       json.dump(data, f)
   print(f"[+] Saved {len(data.get('vulnerabilities', []))} CISA KEV entries to cisa_kev.json")


# ─── EXPLOIT-DB DOWNLOAD ──────────────────────────────────


def download_exploitdb():
   print("\n[*] Downloading Exploit-DB CSV...")
   url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"


   for attempt in range(5):
       try:
           response = requests.get(url, timeout=60)
           print(f"  [DEBUG] Status: {response.status_code}")
           response.raise_for_status()
           break
       except Exception as e:
           print(f"[!] Attempt {attempt + 1} failed: {e}")
           time.sleep(5)
   else:
       print("[!] Failed to download Exploit-DB after 5 attempts.")
       return


   with open("exploitdb.csv", "w") as f:
       f.write(response.text)


   rows = response.text.strip().split("\n")
   print(f"[+] Saved {len(rows)-1} exploits to exploitdb.csv")


# ─── RUN ALL ──────────────────────────────────────────────


if __name__ == "__main__":
   for name, cpe in CPE_TARGETS:
       download_nvd_cpe(name, cpe)


   download_cisa_kev()
   download_exploitdb()


   print("\n[+] All downloads complete! Run ingest_all.py next.")
