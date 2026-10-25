from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings
from langchain_core.documents import Document
import ijson
import json
import csv
import os


# ─── CONFIG ───────────────────────────────────────────────


DB_PATH = "./cve_db_v2"
BATCH_SIZE = 500


CVE_FILES = [
   "linux_cves.json",
   "windows_cves.json",
   "apache_cves.json",
   "android_cves.json",
   "macos_cves.json",
   "nginx_cves.json",
   "ssh_cves.json",
   "wordpress_cves.json",
]


# ─── INIT ─────────────────────────────────────────────────


embeddings = OllamaEmbeddings(model="nomic-embed-text")
splitter = RecursiveCharacterTextSplitter(chunk_size=1500, chunk_overlap=0)
vectorstore = None
grand_total = 0


def flush_batch(batch):
   global vectorstore
   chunks = splitter.split_documents(batch)
   # Deterministic IDs so re-running ingest upserts instead of duplicating the
   # whole DB, and so the same CVE appearing in multiple source files collapses
   # to a single entry instead of being stored once per file.
   ids = []
   counter = {}
   for ch in chunks:
       base = f"{ch.metadata.get('source', '?')}::{ch.metadata.get('cve_id', '?')}"
       n = counter.get(base, 0)
       counter[base] = n + 1
       ids.append(f"{base}::{n}")
   if vectorstore is None:
       vectorstore = Chroma.from_documents(chunks, embeddings, ids=ids, persist_directory=DB_PATH)
   else:
       vectorstore.add_documents(chunks, ids=ids)


# ─── NVD JSON FILES ───────────────────────────────────────


def ingest_nvd_file(filepath):
   global grand_total
   name = os.path.basename(filepath)
   print(f"\n[*] Ingesting {name}...")
   batch = []
   total = 0
   seen = set()


   with open(filepath, "rb") as f:
       for item in ijson.items(f, "item"):
           cve = item["cve"]
           cve_id = cve["id"]


           if cve_id in seen:
               continue
           seen.add(cve_id)


           # ── Description ───────────────────────────────
           descriptions = cve.get("descriptions", [])
           desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")


           # ── CVSS Metrics ──────────────────────────────
           score = "N/A"
           severity = "N/A"
           attack_vector = "N/A"
           attack_complexity = "N/A"
           privileges_required = "N/A"
           user_interaction = "N/A"
           scope = "N/A"
           cvss_vector = "N/A"


           metrics = cve.get("metrics", {})


           if "cvssMetricV31" in metrics:
               m = metrics["cvssMetricV31"][0]
               d = m["cvssData"]
               score = d.get("baseScore", "N/A")
               severity = d.get("baseSeverity", "N/A")
               attack_vector = d.get("attackVector", "N/A")
               attack_complexity = d.get("attackComplexity", "N/A")
               privileges_required = d.get("privilegesRequired", "N/A")
               user_interaction = d.get("userInteraction", "N/A")
               scope = d.get("scope", "N/A")
               cvss_vector = d.get("vectorString", "N/A")


           elif "cvssMetricV30" in metrics:
               m = metrics["cvssMetricV30"][0]
               d = m["cvssData"]
               score = d.get("baseScore", "N/A")
               severity = d.get("baseSeverity", "N/A")
               attack_vector = d.get("attackVector", "N/A")
               attack_complexity = d.get("attackComplexity", "N/A")
               privileges_required = d.get("privilegesRequired", "N/A")
               user_interaction = d.get("userInteraction", "N/A")
               scope = d.get("scope", "N/A")
               cvss_vector = d.get("vectorString", "N/A")


           elif "cvssMetricV2" in metrics:
               m = metrics["cvssMetricV2"][0]
               d = m["cvssData"]
               score = d.get("baseScore", "N/A")
               severity = m.get("baseSeverity", "N/A")
               attack_vector = d.get("accessVector", "N/A")
               attack_complexity = d.get("accessComplexity", "N/A")
               privileges_required = d.get("authentication", "N/A")
               cvss_vector = d.get("vectorString", "N/A")


           # ── Weakness (CWE) ────────────────────────────
           weaknesses = cve.get("weaknesses", [])
           cwes = []
           for w in weaknesses:
               for wd in w.get("description", []):
                   if wd.get("lang") == "en":
                       cwes.append(wd.get("value", ""))
           cwe_str = ", ".join(cwes) if cwes else "N/A"


           # ── References ────────────────────────────────
           references = cve.get("references", [])
           ref_urls = ", ".join([r["url"] for r in references[:3]])


           # ── Published / Modified ──────────────────────
           published = cve.get("published", "N/A")[:10]
           last_modified = cve.get("lastModified", "N/A")[:10]


           # ── Affected Configurations ───────────────────
           configs = cve.get("configurations", [])
           affected_products = []
           for config in configs:
               for node in config.get("nodes", []):
                   for cpe_match in node.get("cpeMatch", []):
                       if cpe_match.get("vulnerable"):
                           cpe = cpe_match.get("criteria", "")
                           version_start = cpe_match.get("versionStartIncluding", "")
                           version_end = cpe_match.get("versionEndIncluding",
                                         cpe_match.get("versionEndExcluding", ""))
                           entry = cpe
                           if version_start:
                               entry += f" (from {version_start}"
                           if version_end:
                               entry += f" to {version_end})"
                           elif version_start:
                               entry += ")"
                           affected_products.append(entry)


           affected_str = "\n  ".join(affected_products[:5]) if affected_products else "N/A"


           # ── Build Document Text ───────────────────────
           platform_hint = "N/A"
           for p in affected_products:
               p_lower = p.lower()
               if "windows" in p_lower: platform_hint = "Windows"
               elif "linux" in p_lower: platform_hint = "Linux"
               elif "android" in p_lower: platform_hint = "Android"
               elif "macos" in p_lower or "mac_os" in p_lower: platform_hint = "macOS"
               elif "apache" in p_lower: platform_hint = "Apache"
               elif "nginx" in p_lower: platform_hint = "Nginx"
               elif "openssh" in p_lower: platform_hint = "SSH"
               elif "wordpress" in p_lower: platform_hint = "WordPress"


           text = (
               f"CVE ID: {cve_id}\n"
               f"Platform: {platform_hint}\n"
               f"Severity: {severity} ({score})\n"
               f"Published: {published}\n"
               f"Last Modified: {last_modified}\n"
               f"Attack Vector: {attack_vector}\n"
               f"Attack Complexity: {attack_complexity}\n"
               f"Privileges Required: {privileges_required}\n"
               f"User Interaction: {user_interaction}\n"
               f"Scope: {scope}\n"
               f"CVSS Vector: {cvss_vector}\n"
               f"Weakness (CWE): {cwe_str}\n"
               f"Affected Products:\n  {affected_str}\n"
               f"Description: {desc}\n"
               f"References: {ref_urls}"
           )


           batch.append(Document(
               page_content=text,
               metadata={
                   "cve_id": cve_id,
                   "score": str(score),
                   "severity": severity,
                   "attack_vector": attack_vector,
                   "privileges_required": privileges_required,
                   "published": published,
                   "source": "nvd"
               }
           ))


           if len(batch) >= BATCH_SIZE:
               flush_batch(batch)
               total += len(batch)
               grand_total += len(batch)
               print(f"  Ingested {total} CVEs from {name}...")
               batch = []


   if batch:
       flush_batch(batch)
       total += len(batch)
       grand_total += len(batch)


   print(f"[+] Done with {name} — {total} CVEs ingested.")


# ─── CISA KEV ─────────────────────────────────────────────


def ingest_cisa_kev():
   global grand_total
   filepath = "cisa_kev.json"
   if not os.path.exists(filepath):
       print("[!] cisa_kev.json not found, skipping.")
       return


   print(f"\n[*] Ingesting CISA KEV...")
   with open(filepath, "r") as f:
       data = json.load(f)


   batch = []
   total = 0


   for entry in data.get("vulnerabilities", []):
       cve_id = entry.get("cveID", "N/A")
       vendor = entry.get("vendorProject", "N/A")
       product = entry.get("product", "N/A")
       vuln_name = entry.get("vulnerabilityName", "N/A")
       desc = entry.get("shortDescription", "No description")
       due_date = entry.get("dueDate", "N/A")
       date_added = entry.get("dateAdded", "N/A")
       required_action = entry.get("requiredAction", "N/A")
       known_ransomware = entry.get("knownRansomwareCampaignUse", "Unknown")


       text = (
           f"CVE ID: {cve_id}\n"
           f"Source: CISA Known Exploited Vulnerability\n"
           f"Vulnerability Name: {vuln_name}\n"
           f"Vendor: {vendor} | Product: {product}\n"
           f"Date Added: {date_added} | Patch Due: {due_date}\n"
           f"Known Ransomware Use: {known_ransomware}\n"
           f"Description: {desc}\n"
           f"Required Action: {required_action}"
       )


       batch.append(Document(
           page_content=text,
           metadata={
               "cve_id": cve_id,
               "score": "N/A",
               "severity": "KNOWN_EXPLOITED",
               "attack_vector": "N/A",
               "privileges_required": "N/A",
               "published": date_added,
               "source": "cisa_kev"
           }
       ))


       if len(batch) >= BATCH_SIZE:
           flush_batch(batch)
           total += len(batch)
           grand_total += len(batch)
           print(f"  Ingested {total} CISA KEV entries...")
           batch = []


   if batch:
       flush_batch(batch)
       total += len(batch)
       grand_total += len(batch)


   print(f"[+] Done with CISA KEV — {total} entries ingested.")


# ─── EXPLOIT-DB ───────────────────────────────────────────


def ingest_exploitdb():
   global grand_total
   filepath = "exploitdb.csv"
   if not os.path.exists(filepath):
       print("[!] exploitdb.csv not found, skipping.")
       return


   print(f"\n[*] Ingesting Exploit-DB...")
   batch = []
   total = 0


   with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
       reader = csv.DictReader(f)
       for row in reader:
           exploit_id = row.get("id", "N/A").strip()
           description = row.get("description", "No description").strip()
           date = row.get("date_published", row.get("date", "N/A")).strip()
           exploit_type = row.get("type", "N/A").strip()
           platform = row.get("platform", "N/A").strip()
           author = row.get("author", "N/A").strip()


           if not description or description == "No description":
               continue


           text = (
               f"Exploit-DB ID: {exploit_id}\n"
               f"Source: Exploit-DB\n"
               f"Type: {exploit_type} | Platform: {platform}\n"
               f"Date: {date}\n"
               f"Author: {author}\n"
               f"Description: {description}"
           )


           batch.append(Document(
               page_content=text,
               metadata={
                   "cve_id": f"EDB-{exploit_id}",
                   "score": "N/A",
                   "severity": "N/A",
                   "attack_vector": "N/A",
                   "privileges_required": "N/A",
                   "published": date,
                   "source": "exploitdb"
               }
           ))


           if len(batch) >= BATCH_SIZE:
               flush_batch(batch)
               total += len(batch)
               grand_total += len(batch)
               print(f"  Ingested {total} Exploit-DB entries...")
               batch = []


   if batch:
       flush_batch(batch)
       total += len(batch)
       grand_total += len(batch)


   print(f"[+] Done with Exploit-DB — {total} entries ingested.")


# ─── MAIN ─────────────────────────────────────────────────


if __name__ == "__main__":
   print("\n[*] Starting ingest_all.py...")
   print(f"[*] Target DB: {DB_PATH}\n")


   for filepath in CVE_FILES:
       if os.path.exists(filepath):
           ingest_nvd_file(filepath)
       else:
           print(f"[!] {filepath} not found, skipping.")


   ingest_cisa_kev()
   ingest_exploitdb()


   print(f"\n[+] Ingest complete! {grand_total} total documents loaded into {DB_PATH}")
   print("[*] Update DB_PATH in Pyr0Byt3.py to ./cve_db_v2 before querying.")
