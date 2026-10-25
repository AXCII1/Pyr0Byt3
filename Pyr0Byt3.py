import os
import sys
import socket
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
os.environ["LANGCHAIN_TRACING_V2"] = "false"
os.environ["LANGSMITH_API_KEY"] = ""
from langchain_ollama import OllamaEmbeddings, OllamaLLM
from langchain_chroma import Chroma
from langchain_core.prompts import PromptTemplate
from thefuzz import fuzz
from spellchecker import SpellChecker
# ─── CONFIG ───────────────────────────────────────────────
MODEL     = "qwen2.5-coder:7b"
DB_PATH   = "./cve_db_v2"
TOP_K     = 5
THRESHOLD = 0.45
# ──────────────────────────────────────────────────────────
BANNER = """
██████╗ ██╗   ██╗██████╗  ██████╗ ██████╗ ██╗   ██╗████████╗███████╗
██╔══██╗╚██╗ ██╔╝██╔══██╗██╔═══██╗██╔══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝
██████╔╝ ╚████╔╝ ██████╔╝██║   ██║██████╔╝ ╚████╔╝    ██║   █████╗ 
██╔═══╝   ╚██╔╝  ██╔══██╗██║   ██║██╔══██╗  ╚██╔╝     ██║   ██╔══╝ 
██║        ██║   ██║  ██║╚██████╔╝██████╔╝   ██║      ██║   ███████╗
╚═╝        ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝    ╚═╝      ╚═╝   ╚══════╝
       Local CVE Threat Intelligence & Script Generation
       by AXCII1 | Offline AI Intelligence | Over 300K CVEs
"""
DISCLAIMER = """
╔══════════════════════════════════════════════════════════════╗
║                  ⚠  OFFENSIVE MODE WARNING ⚠                ║
║                                                              ║
║  This mode generates proof-of-concept exploit code for       ║
║  security research and authorized penetration testing ONLY.  ║
║                                                              ║
║  Unauthorized use against systems you do not own or have     ║
║  explicit written permission to test is ILLEGAL and may      ║
║  result in criminal prosecution.                             ║
║                                                              ║
║  By continuing you confirm:                                  ║
║  [1] You have authorization to test the target system        ║
║  [2] This is for educational/research purposes only          ║
║  [3] You accept full legal responsibility                    ║
╚══════════════════════════════════════════════════════════════╝
"""
PROTECT_DISCLAIMER = """
╔══════════════════════════════════════════════════════════════╗
║                  ⚠  ACTIVE SCAN WARNING ⚠                   ║
║                                                              ║
║  This will run an Nmap service scan against the target.      ║
║                                                              ║
║  Only scan systems you own or have explicit written          ║
║  permission to scan. Unauthorized scanning is illegal.       ║
║                                                              ║
║  By continuing you confirm this is YOUR system or you        ║
║  have written authorization to scan it.                      ║
╚══════════════════════════════════════════════════════════════╝
"""
HELP = """
Commands:
 search  <query>              Semantic search across CVE database
 analyze <CVE-ID>             Full threat analysis of a specific CVE
 defend  <CVE-ID>             Generate defensive scripts & detection rules
 exploit <CVE-ID>             Generate offensive PoC (requires disclaimer)
 protect machine              Scan your local machine
 protect network              Scan your local subnet (auto-detect interface)
 protect <IP or hostname>     Scan a single target (requires disclaimer)
 cmds                         Show this command list
 /?  <command>                Explain how a command works
 quit                         Exit Pyr0Byt3
"""
COMMAND_HELP = {
   "search": """
 search <query>
 ─────────────────────────────────────────────────────
 Semantic search across the local CVE database.
 Uses spell correction and fuzzy keyword matching
 before querying ChromaDB for relevant CVEs.
 Examples:
   search linux kernel privilege escalation
   search apache remote code execution
   search ssh buffer overflow 2023
 Key Words:
   linux, windows, apache, cisco, kernel, remote, privilege, escalation, execution, overflow, injection,
   android, microsoft, apple, nginx, ssh, ssl, vpn, vulnerability, exploit, attack, bypass, and disclosure.
 Tips:
   - Use platform names for targeted results (linux, windows, apache)
   - Results are ranked by confidence score
   - Use 'analyze' on any result for full details
""",
   "analyze": """
 analyze <CVE-ID>
 ─────────────────────────────────────────────────────
 Runs a full AI-powered threat analysis on a specific CVE.
 Pulls the CVE from the local database and generates:
   1. Executive Summary
   2. Attack Vector & Complexity
   3. Affected Systems & Versions
   4. Exploitability Assessment
   5. Real World Impact
   6. Threat Actor Likelihood
   7. CVSS Breakdown
 Examples:
   analyze CVE-2021-44228
   analyze CVE-2023-44487
 Tips:
   - CVE ID must exist in your local database
   - Use 'search' first to find relevant CVE IDs
""",
   "defend": """
 defend <CVE-ID>
 ─────────────────────────────────────────────────────
 Generates defensive countermeasures for a specific CVE.
 Output includes:
   1. Detection Rule (Sigma or Snort format)
   2. SIEM Query (Splunk or Elastic format)
   3. Patch/Mitigation Steps
   4. Bash hardening script
   5. Indicators of Compromise (IOCs)
 You will be prompted to save the output to ./output/
 Examples:
   defend CVE-2021-44228
   defend CVE-2014-6271
 Tips:
   - Scripts are saved to ./output/<CVE-ID>_defensive.txt
   - Always test hardening scripts in a lab first
""",
   "exploit": """
 exploit <CVE-ID>
 ─────────────────────────────────────────────────────
 Generates a proof-of-concept exploit for a specific CVE.
 Requires accepting the offensive use disclaimer.
 Output includes:
   1. Vulnerability breakdown & root cause
   2. Attack chain walkthrough
   3. PoC exploit script (Python or Bash)
   4. Payload suggestions
   5. Post exploitation notes
   6. Affected versions to target in lab
 Examples:
   exploit CVE-2021-44228
   exploit CVE-2017-0144
 Tips:
   - Only use against systems you own or have written permission to test
   - Scripts are saved to ./output/<CVE-ID>_offensive_poc.txt
   - Unknown constants are marked with # VERIFY THIS VALUE
""",
   "protect": """
 protect machine              Scan localhost (one-time confirm, no full disclaimer)
 protect network              Auto-detect subnet, pick interface if multiple found
 protect <IPv4>               Single target IPv4 address (full disclaimer)
 protect <IPv6>               Single target IPv6 address (adds -6 flag automatically)
 protect <hostname>           Single target hostname (full disclaimer)
 ─────────────────────────────────────────────────────
 Scans the target with Nmap, detects running services,
 correlates them against your CVE database, and generates
 a full hardening report automatically.
 Flow:
   Nmap scan → service detection → CVE correlation
   → severity ranking → high-risk IP summary → AI hardening report
 Examples:
   protect machine
   protect network
   protect 192.168.1.105
   protect 2001:db8::1
   protect myserver.local
 Tips:
   - Only scan systems you own or have written permission to scan
   - Requires Nmap installed (sudo pacman -S nmap)
   - Report saved to ./output/protect_report_<target>.txt
   - Run as root for more accurate service detection (sudo)
   - High-risk and vulnerable IPs are highlighted in the summary
""",
   "cmds": """
 cmds
 ─────────────────────────────────────────────────────
 Displays the full command list.
""",
   "/?": """
 /? <command>
 ─────────────────────────────────────────────────────
 Shows detailed usage info for a specific command.
 Examples:
   /? search
   /? protect
   /? exploit
"""
}
# ─── PROMPTS ──────────────────────────────────────────────
ANALYZE_PROMPT = PromptTemplate.from_template("""
You are an expert cybersecurity analyst. Use ONLY the following CVE data to answer the question. Do NOT invent, assume, or add any CVE details that are not explicitly present in the data below.
If the data does not contain enough information to answer, say "Insufficient data in local database."
CVE Data:
{context}
CVE ID: {cve_id}
Provide the following analysis:
1. Executive Summary
2. Attack Vector & Complexity
3. Affected Systems & Versions
4. Exploitability Assessment
5. Real World Impact
6. Threat Actor Likelihood
7. CVSS Breakdown
Answer:""")
DEFEND_PROMPT = PromptTemplate.from_template("""
You are an expert defensive security engineer. Based on the following CVE data, generate defensive countermeasures. Do NOT invent, assume, or add any CVE details that are not explicitly present in the data below.
If the data does not contain enough information to answer, say "Insufficient data in local database."
CVE Data:
{context}
CVE ID: {cve_id}
Generate the following as actual working code/rules:
1. Detection Rule (Sigma or Snort format)
2. SIEM Query (Splunk or Elastic format)
3. Patch/Mitigation Steps
4. Bash hardening script
5. Indicators of Compromise (IoCs) to monitor
Answer:""")
EXPLOIT_PROMPT = PromptTemplate.from_template("""
You are an expert penetration tester working in an authorized lab environment.
Use ONLY the CVE data below. Do NOT invent technical details not present in the data.
CRITICAL RULES:
- If attack vector is LOCAL, do NOT generate network-based exploits
- If attack vector is NETWORK, do NOT generate local exploits
- If privileges required is HIGH, note that local access is required
- If you cannot determine a detail from the data, say "Unknown - verify against NVD"
- Never fabricate offsets, addresses, port numbers, or packet structures
CVE Data:
{context}
CVE ID: {cve_id}
Generate the following based ONLY on data above:
1. Vulnerability breakdown & root cause
2. Attack chain walkthrough (must match attack vector in data)
3. PoC exploit script (Python or Bash) - use "# VERIFY THIS VALUE" for any unknown constants
4. Payload suggestions
5. Post exploitation notes
6. Affected versions to target in lab environment
Answer:""")
PROTECT_PROMPT = PromptTemplate.from_template("""
You are an expert defensive security engineer. A vulnerability scan found the following CVEs
affecting services on the scanned target. Generate a consolidated hardening report.
Scan Target (subnet or host that was scanned): {target}
VULNERABLE HOSTS (these are the EXACT IPs with confirmed CVE findings — use these in all output):
{vulnerable_hosts}
Detected Services:
{services}
CVE Findings:
{cve_findings}
IMPORTANT: Every hardening step, bash script, detection rule, and IOC must reference the
specific vulnerable IP address(es) listed above — NOT the scan target subnet.
Do NOT say "the host" generically. Always name the exact IP.
Generate:
1. Executive Risk Summary — list each vulnerable IP and its overall risk rating
2. Per-CVE Hardening Steps — for each IP, list patch commands, config changes, version upgrades
3. Unified Bash Hardening Script — one script with per-IP sections (use SSH or direct commands)
4. Detection Rules (Sigma or Snort) for the highest severity CVEs, referencing the vulnerable IPs
5. Recommended monitoring IOCs — tied to the specific vulnerable IPs above
Only use data provided above. Do not invent CVE details not present.
Answer:""")
SEARCH_PROMPT = PromptTemplate.from_template("""
You are a CVE lookup tool. You must ONLY output information about these exact CVE IDs: {sources}
Do NOT mention any other CVE IDs not in that list.
Do NOT use your training data. ONLY use the CVE Data section below.
Output ONLY this format for each CVE, nothing else:
CVE ID: <id>
Severity: <score>
Description: <one sentence from the data only>
---
CVE Data:
{context}
Question: {question}
Output:""")
# ─── CORE FUNCTIONS ───────────────────────────────────────
def load_db():
   print("\n[*] Loading CVE database...")
   embeddings  = OllamaEmbeddings(model="nomic-embed-text")
   vectorstore = Chroma(persist_directory=DB_PATH, embedding_function=embeddings)
   print("[+] Database loaded successfully\n")
   return vectorstore
def load_llm():
   return OllamaLLM(model=MODEL, streaming=True, num_ctx=2048, num_predict=1024)
def stream_response(llm, prompt_text):
   print("\n" + "─"*60)
   for chunk in llm.stream(prompt_text):
       print(chunk, end="", flush=True)
   print("\n" + "─"*60 + "\n")
def get_context(vectorstore, query, threshold=THRESHOLD, exact_cve_id=None):
   if exact_cve_id:
       try:
           results = vectorstore.similarity_search_with_relevance_scores(
               exact_cve_id,
               k=10,
               filter={"cve_id": {"$eq": exact_cve_id}}
           )
       except Exception:
           results = vectorstore.similarity_search_with_relevance_scores(
               exact_cve_id, k=100
           )
           results = [(doc, score) for doc, score in results
                      if doc.metadata.get("cve_id") == exact_cve_id]
       if not results:
           return None, [], []
       context = "\n\n".join([doc.page_content for doc, _ in results])
       sources = [doc.metadata.get("cve_id") for doc, _ in results]
       scores  = [f"{doc.metadata.get('cve_id')}({score:.2f})" for doc, score in results]
       return context, sources, scores
   # General search
   results  = vectorstore.similarity_search_with_relevance_scores(query, k=20)
   filtered = [(doc, score) for doc, score in results if score >= threshold]
   if not filtered:
       return None, [], []
   seen   = set()
   deduped = []
   for doc, score in filtered:
       cve_id = doc.metadata.get("cve_id")
       if cve_id not in seen:
           seen.add(cve_id)
           deduped.append((doc, score))
   context = "\n\n".join([doc.page_content for doc, _ in deduped])
   sources = [doc.metadata.get("cve_id") for doc, _ in deduped]
   scores  = [f"{doc.metadata.get('cve_id')}({score:.2f})" for doc, score in deduped]
   return context, sources, scores
def offensive_disclaimer():
   print(DISCLAIMER)
   confirm = input("Type ACCEPT to continue or anything else to cancel: ").strip()
   return confirm.upper() == "ACCEPT"
def protect_disclaimer():
   print(PROTECT_DISCLAIMER)
   confirm = input("Type AGREE to continue or anything else to cancel: ").strip()
   return confirm.upper() == "AGREE"
def save_script(cve_id, mode, content):
   os.makedirs("./output", exist_ok=True)
   filename = f"./output/{cve_id}_{mode}.txt"
   with open(filename, "w") as f:
       f.write(content)
   print(f"[+] Script saved to {filename}")
def save_report(target, content):
   os.makedirs("./output", exist_ok=True)
   safe_target = target.replace("/", "_").replace(".", "_")
   filename = f"./output/protect_report_{safe_target}.txt"
   with open(filename, "w") as f:
       f.write(content)
   print(f"[+] Report saved to {filename}")
# ─── NMAP FUNCTIONS ───────────────────────────────────────
def run_nmap(target, extra_flags=None):
   print(f"\n[*] Running Nmap service scan on {target}...")
   print("[*] This may take a minute...\n")
   cmd = ["nmap", "-sV", "--version-intensity", "5", "-T4", "--open", "-oX", "-"]
   if extra_flags:
       cmd += extra_flags
   cmd.append(target)
   try:
       result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
       if result.returncode != 0:
           print(f"[!] Nmap error: {result.stderr}")
           return None
       return result.stdout
   except FileNotFoundError:
       print("[!] Nmap not found. Install it with: sudo pacman -S nmap")
       return None
   except subprocess.TimeoutExpired:
       print("[!] Nmap scan timed out.")
       return None
def parse_nmap_xml(xml_output):
   """
   Returns a dict keyed by host IP:
     { "192.168.1.1": [ {port, protocol, name, product, version, display}, ... ] }
   """
   hosts = {}
   try:
       root = ET.fromstring(xml_output)
       for host in root.findall("host"):
           addr_el = host.find("address[@addrtype='ipv4']")
           if addr_el is None:
               addr_el = host.find("address[@addrtype='ipv6']")
           host_ip = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"
           services = []
           for port in host.findall(".//port"):
               state = port.find("state")
               if state is None or state.get("state") != "open":
                   continue
               port_id  = port.get("portid", "?")
               protocol = port.get("protocol", "tcp")
               service  = port.find("service")
               if service is not None:
                   name      = service.get("name", "unknown")
                   product   = service.get("product", "")
                   version   = service.get("version", "")
                   extrainfo = service.get("extrainfo", "")
                   service_str = name
                   if product:
                       service_str += f" ({product}"
                       if version:
                           service_str += f" {version}"
                       if extrainfo:
                           service_str += f" {extrainfo}"
                       service_str += ")"
                   services.append({
                       "port":     port_id,
                       "protocol": protocol,
                       "name":     name,
                       "product":  product,
                       "version":  version,
                       "display":  service_str
                   })
           if services:
               hosts[host_ip] = services
   except ET.ParseError as e:
       print(f"[!] Failed to parse Nmap XML: {e}")
   return hosts
def correlate_services_to_cves(vectorstore, services):


   findings  = []
   seen_cves = set()


   # Generic protocol/service names that are too broad to match on alone.
   # A match against ONLY these (with no product string) is unverified.
   GENERIC_NAMES = {"http", "https", "ftp", "ssh", "telnet", "smtp", "dns",
                     "rdp", "smb", "ssl", "tls", "vnc", "snmp"}


   for svc in services:
       query_parts = [svc["name"]]
       if svc.get("product"):
           query_parts.append(svc["product"])
       if svc.get("version"):
           query_parts.append(svc["version"])


       query = " ".join(query_parts)
       print(f"  [*] Searching CVEs for: {query} (port {svc['port']})")


       try:
           results = vectorstore.similarity_search_with_relevance_scores(
               query, k=100, filter={"source": {"$in": ["nvd", "cisa_kev"]}}
           )
       except Exception:
           results = vectorstore.similarity_search_with_relevance_scores(query, k=100)


       svc_cves = []
       for doc, score in results:
           if score < 0.45:
               continue


           cve_id  = doc.metadata.get("cve_id")
           content = doc.page_content.lower()


           if cve_id in seen_cves:
               continue


           product = svc.get("product", "").strip()
           name    = svc["name"].strip().lower()


           # ── Require a SPECIFIC match, not just the generic protocol name ──
           product_match = bool(product) and product.lower() in content


           if not product_match:
               # No product string to verify against (banner grab failed) —
               # OR product didn't actually appear in the CVE text.
               # A bare name match ("http" in content) is NOT sufficient on its own.
               if name in GENERIC_NAMES:
                   continue
               # For non-generic names (e.g. a specific named daemon Nmap
               # identified directly as the service name), allow it through.
               name_match = name in content
               if not name_match:
                   continue


           # ── Date sanity filter ──────────────────────────────────────
           # If the CVE was published well before this software/version
           # could plausibly have existed, it's almost certainly a false
           # positive from keyword/embedding overlap, not a real match.
           if svc.get("version"):
               published = doc.metadata.get("published", "N/A")
               if published not in ("N/A", ""):
                   try:
                       pub_year = int(published[:4])
                       # Conservative cutoff: BusyBox httpd (and most modern
                       # embedded services) didn't exist in usable form before
                       # ~2005. Adjust per-product if you want this tighter.
                       if pub_year < 2005:
                           continue
                   except (ValueError, TypeError):
                       pass


           seen_cves.add(cve_id)
           svc_cves.append({
               "cve_id":        cve_id,
               "severity":      doc.metadata.get("severity", "N/A"),
               "score":         doc.metadata.get("score", "N/A"),
               "attack_vector": doc.metadata.get("attack_vector", "N/A"),
               "content":       doc.page_content
           })


       svc_cves.sort(
           key=lambda x: float(x["score"]) if x["score"] != "N/A" else 0,
           reverse=True
       )


       if svc_cves:
           findings.append({"service": svc, "cves": svc_cves[:100]})


   return findings
# ─── PROTECT HELPERS ──────────────────────────────────────
def _validate_ip(target):
   """Return 'ipv4', 'ipv6', or None."""
   for family in (socket.AF_INET, socket.AF_INET6):
       try:
           socket.inet_pton(family, target)
           return "ipv6" if family == socket.AF_INET6 else "ipv4"
       except socket.error:
           pass
   return None
def _get_interfaces():
   """Return list of (iface_name, cidr) for active non-loopback IPv4 interfaces."""
   results = []
   try:
       out = subprocess.check_output(
           ["ip", "-o", "-f", "inet", "addr", "show"],
           text=True
       )
       for line in out.splitlines():
           parts = line.split()
           iface = parts[1]
           cidr  = parts[3]
           if iface == "lo":
               continue
           results.append((iface, cidr))
   except Exception as e:
       print(f"[!] Could not read interfaces: {e}")
   return results
def _display_findings(hosts_findings):
   """
   Print per-host CVE summary.
   Returns (total, critical, high, host_risk_map) where host_risk_map is:
     { "192.168.1.x": {"critical": N, "high": N, "medium": N, "low": N, "total": N} }
   """
   total        = 0
   critical     = 0
   high         = 0
   host_risk_map = {}
   for host_ip, findings in hosts_findings.items():
       host_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
       print(f"\n{'═'*60}")
       print(f"  HOST: {host_ip}")
       print(f"{'═'*60}")
       if not findings:
           print("  No CVE matches found for detected services.")
           host_risk_map[host_ip] = host_counts
           continue
       for finding in findings:
           svc  = finding["service"]
           cves = finding["cves"]
           total += len(cves)
           host_counts["total"] += len(cves)
           print(f"\n  Service: {svc['display']} (port {svc['port']})")
           for cve in cves:
               sev = cve["severity"].upper()
               if sev in ("CRITICAL", "KNOWN_EXPLOITED"):
                   indicator = "[EXP]" if sev == "KNOWN_EXPLOITED" else "[!!!]"
                   critical += 1
                   host_counts["critical"] += 1
               elif sev == "HIGH":
                   indicator = "[!! ]"
                   high += 1
                   host_counts["high"] += 1
               elif sev == "MEDIUM":
                   indicator = "[!  ]"
                   host_counts["medium"] += 1
               else:
                   indicator = "[   ]"
                   host_counts["low"] += 1
               print(
                   f"    {indicator} {cve['cve_id']} | {sev} ({cve['score']}) "
                   f"| AV:{cve['attack_vector']}"
               )
       host_risk_map[host_ip] = host_counts
   print("\n" + "─"*60)
   print(f"  Total CVEs found: {total}")
   print(f"  Critical: {critical} | High: {high}")
   print("─"*60)
   return total, critical, high, host_risk_map
def _display_high_risk_summary(host_risk_map):
   """
   Print a dedicated HIGH RISK / VULNERABLE IP summary table.
   A host is flagged if it has any CRITICAL or HIGH severity CVEs.
   """
   # Sort hosts: critical desc, then high desc
   risky = {
       ip: counts for ip, counts in host_risk_map.items()
       if counts["critical"] > 0 or counts["high"] > 0
   }
   print("\n" + "═"*60)
   if not risky:
       print("  ✔  HIGH-RISK IP SUMMARY: No critical or high-severity hosts found.")
       print("═"*60 + "\n")
       return
   print("  ⚠  HIGH-RISK / VULNERABLE IP SUMMARY")
   print("═"*60)
   print(f"  {'IP ADDRESS':<22} {'CRITICAL':>8} {'HIGH':>6} {'MEDIUM':>8} {'TOTAL':>7}")
   print("  " + "─"*56)
   # Sort by critical count descending, then high count descending
   sorted_hosts = sorted(
       risky.items(),
       key=lambda x: (x[1]["critical"], x[1]["high"]),
       reverse=True
   )
   for ip, counts in sorted_hosts:
       risk_label = "  [!!!] CRITICAL RISK" if counts["critical"] > 0 else "  [!! ] HIGH RISK"
       print(
           f"  {ip:<22} {counts['critical']:>8} {counts['high']:>6} "
           f"{counts['medium']:>8} {counts['total']:>7}"
       )
       print(risk_label)
       print()
   print("═"*60)
   print(f"  {len(risky)} host(s) require immediate attention.\n")
def _build_report_strings(all_services, hosts_findings):
   """Build services_str and cve_findings_str for the LLM prompt."""
   services_str = ""
   for host_ip, services in all_services.items():
       services_str += f"\n  Host: {host_ip}\n"
       for svc in services:
           services_str += f"    Port {svc['port']}/{svc['protocol']}: {svc['display']}\n"
   cve_findings_str = ""
   for host_ip, findings in hosts_findings.items():
       cve_findings_str += f"\nHost: {host_ip}\n"
       for finding in findings:
           svc = finding["service"]
           cve_findings_str += f"\n  Service: {svc['display']} (port {svc['port']})\n"
           for cve in finding["cves"]:
               cve_findings_str += f"\n{cve['content']}\n"
               cve_findings_str += "─"*40 + "\n"
   return services_str, cve_findings_str
def _build_high_risk_report_section(host_risk_map):
   """Return a plain-text high-risk IP section suitable for saved reports."""
   risky = {
       ip: counts for ip, counts in host_risk_map.items()
       if counts["critical"] > 0 or counts["high"] > 0
   }
   lines = []
   lines.append("HIGH-RISK / VULNERABLE IP SUMMARY")
   lines.append("=" * 60)
   if not risky:
       lines.append("No critical or high-severity hosts found.")
       lines.append("")
       return "\n".join(lines)
   lines.append(f"  {'IP ADDRESS':<22} {'CRITICAL':>8} {'HIGH':>6} {'MEDIUM':>8} {'TOTAL':>7}")
   lines.append("  " + "-" * 56)
   sorted_hosts = sorted(
       risky.items(),
       key=lambda x: (x[1]["critical"], x[1]["high"]),
       reverse=True
   )
   for ip, counts in sorted_hosts:
       risk_label = "[!!!] CRITICAL RISK" if counts["critical"] > 0 else "[!! ] HIGH RISK"
       lines.append(
           f"  {ip:<22} {counts['critical']:>8} {counts['high']:>6} "
           f"{counts['medium']:>8} {counts['total']:>7}   {risk_label}"
       )
   lines.append("")
   lines.append(f"{len(risky)} host(s) require immediate attention.")
   lines.append("")
   return "\n".join(lines)
def _run_protect(vectorstore, llm, target, nmap_extra_flags=None):
   """
   Shared core: run nmap → parse → correlate → display → high-risk summary → LLM → save.
   Called by all three protect modes after disclaimer/confirm is handled.
   """
   xml_output = run_nmap(target, extra_flags=nmap_extra_flags)
   if not xml_output:
       return
   hosts = parse_nmap_xml(xml_output)
   if not hosts:
       print("[!] No open services found or failed to parse Nmap output.\n")
       return
   # Show detected services
   total_services = sum(len(svcs) for svcs in hosts.values())
   print(f"\n[+] Detected {total_services} open service(s) across {len(hosts)} host(s):\n")
   print("─"*60)
   for host_ip, services in hosts.items():
       print(f"  {host_ip}")
       for svc in services:
           print(f"    Port {svc['port']}/{svc['protocol']}  →  {svc['display']}")
   print("─"*60)
   # Correlate CVEs per host
   print("\n[*] Correlating services to CVE database...")
   hosts_findings = {}
   for host_ip, services in hosts.items():
       hosts_findings[host_ip] = correlate_services_to_cves(vectorstore, services)
   any_findings = any(f for f in hosts_findings.values())
   if not any_findings:
       print("\n[+] No CVEs found matching detected services. Host looks clean.\n")
       return
   # Display per-host CVE detail
   print("\n[!] CVE Findings Summary:\n")
   total, critical, high, host_risk_map = _display_findings(hosts_findings)
   # ── NEW: High-risk IP summary table ──────────────────────
   _display_high_risk_summary(host_risk_map)
   # Build LLM prompt
   services_str, cve_findings_str = _build_report_strings(hosts, hosts_findings)
   # Build an explicit list of vulnerable IPs with their severity counts for the prompt.
   # Key context the LLM needs to name specific hosts instead of the subnet.
   vuln_lines = []
   for host_ip, counts in host_risk_map.items():
       if counts["total"] == 0:
           continue
       risk_label = (
           "CRITICAL RISK" if counts["critical"] > 0
           else "HIGH RISK"   if counts["high"]     > 0
           else "MEDIUM RISK" if counts["medium"]   > 0
           else "LOW RISK"
       )
       vuln_lines.append(
           f"  {host_ip}  —  {risk_label}  "
           f"(Critical:{counts['critical']} High:{counts['high']} "
           f"Medium:{counts['medium']} Total:{counts['total']})"
       )
   vulnerable_hosts_str = "\n".join(vuln_lines) if vuln_lines else "  None"
   print(f"\n[*] Generating hardening report for {target}...")
   prompt = PROTECT_PROMPT.format(
       target=target,
       vulnerable_hosts=vulnerable_hosts_str,
       services=services_str,
       cve_findings=cve_findings_str
   )
   output = []
   print("\n" + "─"*60)
   for chunk in llm.stream(prompt):
       print(chunk, end="", flush=True)
       output.append(chunk)
   print("\n" + "─"*60 + "\n")
   save = input("[?] Save hardening report to file? (y/n): ").strip().lower()
   if save == "y":
       full_report  = f"PROTECT REPORT — {target}\n"
       full_report += "="*60 + "\n\n"
       # ── Include high-risk summary at the top of saved report ──
       full_report += _build_high_risk_report_section(host_risk_map)
       full_report += "\n" + "="*60 + "\n\n"
       full_report += "DETECTED SERVICES:\n"
       full_report += services_str + "\n\n"
       full_report += "CVE FINDINGS:\n"
       for host_ip, findings in hosts_findings.items():
           full_report += f"\nHost: {host_ip}\n"
           for finding in findings:
               svc = finding["service"]
               full_report += f"  {svc['display']} (port {svc['port']}):\n"
               for cve in finding["cves"]:
                   full_report += f"    {cve['cve_id']} | {cve['severity']} ({cve['score']})\n"
       full_report += "\n" + "="*60 + "\n\n"
       full_report += "HARDENING REPORT:\n\n"
       full_report += "".join(output)
       save_report(target, full_report)
# ─── COMMAND HANDLERS ─────────────────────────────────────
def cmd_search(vectorstore, llm, query):
   stopwords = {"and", "or", "the", "a", "an", "in", "of", "for", "to", "with"}
   TECH_TERMS = {
       "linux", "windows", "apache", "cisco", "kernel", "remote",
       "privilege", "escalation", "execution", "overflow", "injection",
       "android", "microsoft", "apple", "nginx", "ssh", "ssl", "vpn",
       "exploit", "attack", "bypass", "disclosure", "rce", "lfi", "sqli",
       "wordpress", "macos", "cve", "buffer", "heap", "stack", "use-after-free",
       "uaf", "xss", "csrf", "samba", "smb", "ftp", "http", "https", "rdp",
       "openssl", "openssh", "sudo", "bash", "perl", "php", "java", "python"
   }
   PLATFORM_TERMS = {
       "linux", "windows", "apache", "android", "macos", "nginx",
       "ssh", "wordpress", "cisco", "microsoft", "apple", "kernel",
       "openssh", "openssl", "samba", "smb", "rdp", "php", "java"
   }
   spell = SpellChecker()
   raw_words = query.lower().split()
   corrected_keywords = []
   for word in raw_words:
       if word in stopwords:
           continue
       if word in TECH_TERMS:
           corrected_keywords.append(word)
           continue
       # Don't spell-"correct" version numbers or CVE IDs (e.g. "9.1", "cve-2021-44228")
       if any(c.isdigit() for c in word) or "-" in word:
           corrected_keywords.append(word)
           continue
       corrected = spell.correction(word)
       corrected_keywords.append(corrected if corrected else word)
   corrected_str = " ".join(corrected_keywords)
   original_str  = " ".join(w for w in raw_words if w not in stopwords)
   if corrected_str != original_str:
       print(f"[*] Spell corrected: {corrected_str}\n")
   searched_platforms = [kw for kw in corrected_keywords if kw in PLATFORM_TERMS]
   k_val = 200 if searched_platforms else 50
   results = vectorstore.similarity_search_with_relevance_scores(corrected_str, k=k_val)
   seen_ids          = set()
   seen_descriptions = set()
   filtered          = []
   min_score         = 0.45 if searched_platforms else THRESHOLD
   for doc, score in results:
       cve_id   = doc.metadata.get("cve_id")
       content  = doc.page_content.lower()
       desc_key = doc.page_content[:150]
       if score < min_score:
           continue
       if cve_id in seen_ids or desc_key in seen_descriptions:
           continue
       if searched_platforms:
           if not any(platform in content for platform in searched_platforms):
               continue
       keyword_match = any(kw in content for kw in corrected_keywords)
       if not keyword_match:
           continue
       if "cisco" not in corrected_keywords:
           leading = content[:120]
           if "cisco" in leading and not any(p in leading for p in searched_platforms):
               continue
       seen_ids.add(cve_id)
       seen_descriptions.add(desc_key)
       filtered.append((doc, score))
   if not filtered:
       print(f"\n[!] No confident matches found for: {corrected_str}")
       print("[*] Try different keywords.\n")
       return
   def sort_key(item):
       doc, sim = item
       try:
           return float(doc.metadata.get("score", 0))
       except (ValueError, TypeError):
           return sim
   filtered.sort(key=sort_key, reverse=True)
   print(f"\n[*] Found {len(filtered)} matching CVEs:\n")
   print("─"*60)
   for doc, score in filtered:
       cve_id    = doc.metadata.get("cve_id")
       score_val = doc.metadata.get("score", "N/A")
       print(f"CVE ID:     {cve_id}")
       print(f"CVSS Score: {score_val}")
       print(f"Confidence: {score:.2f}")
       print(f"{doc.page_content}")
       print("─"*40)
   print("─"*60)
   print(f"\n[*] Use 'analyze <CVE-ID>' for full threat analysis\n")
def cmd_analyze(vectorstore, llm, cve_id):
   print(f"\n[*] Running threat analysis on {cve_id}...")
   result = get_context(vectorstore, cve_id, exact_cve_id=cve_id)
   if result[0] is None:
       print(f"[!] {cve_id} not found in database.\n")
       return
   context, sources, scores = result
   prompt = ANALYZE_PROMPT.format(context=context, cve_id=cve_id)
   stream_response(llm, prompt)
   print(f"[*] Sources: {', '.join(sources)}")
def cmd_defend(vectorstore, llm, cve_id):
   print(f"\n[*] Generating defensive scripts for {cve_id}...")
   result = get_context(vectorstore, cve_id, exact_cve_id=cve_id)
   if result[0] is None:
       print(f"[!] {cve_id} not found in database.\n")
       return
   context, sources, scores = result
   prompt = DEFEND_PROMPT.format(context=context, cve_id=cve_id)
   output = []
   print("\n" + "─"*60)
   for chunk in llm.stream(prompt):
       print(chunk, end="", flush=True)
       output.append(chunk)
   print("\n" + "─"*60 + "\n")
   save = input("[?] Save defensive script to file? (y/n): ").strip().lower()
   if save == "y":
       save_script(cve_id, "defensive", "".join(output))
def cmd_exploit(vectorstore, llm, cve_id):
   if not offensive_disclaimer():
       print("\n[!] Offensive mode cancelled.\n")
       return
   print(f"\n[*] Generating PoC for {cve_id}...")
   result = get_context(vectorstore, cve_id, exact_cve_id=cve_id)
   if result[0] is None:
       print(f"[!] {cve_id} not found in database.\n")
       return
   context, sources, scores = result
   prompt = EXPLOIT_PROMPT.format(context=context, cve_id=cve_id)
   output = []
   print("\n" + "─"*60)
   for chunk in llm.stream(prompt):
       print(chunk, end="", flush=True)
       output.append(chunk)
   print("\n" + "─"*60 + "\n")
   save = input("[?] Save PoC script to file? (y/n): ").strip().lower()
   if save == "y":
       save_script(cve_id, "offensive_poc", "".join(output))
# Module-level flag — machine disclaimer fires only once per session
_MACHINE_CONFIRMED = False
def cmd_protect(vectorstore, llm, arg):
   global _MACHINE_CONFIRMED
   parts = arg.strip().split()
   if not parts:
       print("[!] Usage: protect machine | protect network | protect <IP or hostname>")
       return
   mode = parts[0].lower()
   # ── MODE: machine ──────────────────────────────────────
   if mode == "machine":
       if not _MACHINE_CONFIRMED:
           print("\n[*] This will run an Nmap scan against your local machine (127.0.0.1).")
           ans = input("    Confirm this is your own system [y/N]: ").strip().lower()
           if ans != "y":
               print("[!] Scan cancelled.\n")
               return
           _MACHINE_CONFIRMED = True
       _run_protect(vectorstore, llm, "127.0.0.1")
       return
   # ── MODE: network ──────────────────────────────────────
   if mode == "network":
       ifaces = _get_interfaces()
       if not ifaces:
           print("[!] Could not detect any active network interfaces.\n")
           return
       if len(ifaces) == 1:
           iface, cidr = ifaces[0]
           print(f"[*] Detected interface: {iface}  ({cidr})")
       else:
           print("\n[*] Multiple interfaces detected:")
           for i, (iface, cidr) in enumerate(ifaces):
               print(f"    [{i + 1}] {iface}  —  {cidr}")
           try:
               pick       = int(input("    Choose interface number: ").strip()) - 1
               iface, cidr = ifaces[pick]
           except (ValueError, IndexError):
               print("[!] Invalid selection. Scan cancelled.\n")
               return
       try:
           network = str(ipaddress.ip_interface(cidr).network)
       except ValueError:
           print(f"[!] Could not parse subnet from {cidr}. Scan cancelled.\n")
           return
       print(f"[*] Scanning subnet: {network} via {iface}")
       if not protect_disclaimer():
           print("\n[!] Protect scan cancelled.\n")
           return
       _run_protect(vectorstore, llm, network)
       return
   # ── MODE: single IP or hostname ────────────────────────
   # FIX: use the full arg (parts[0]) — already correct for single token,
   # but preserve original casing from parts[0] rather than mode (which is lowercased)
   target  = parts[0]
   ip_type = _validate_ip(target)
   extra   = ["-6"] if ip_type == "ipv6" else []
   if not protect_disclaimer():
       print("\n[!] Protect scan cancelled.\n")
       return
   _run_protect(vectorstore, llm, target, nmap_extra_flags=extra)
# ─── MAIN LOOP ────────────────────────────────────────────
def main():
   print(BANNER)
   vectorstore = load_db()
   llm         = load_llm()
   print(HELP)
   while True:
       try:
           user_input = input("Pyr0Byt3 > ").strip()
           if not user_input:
               continue
           parts = user_input.split(maxsplit=1)
           cmd   = parts[0].lower()
           arg   = parts[1] if len(parts) > 1 else ""
           if cmd in ["quit", "exit"]:
               print("\n[*] Shutting down Pyr0Byt3. Stay safe.\n")
               sys.exit(0)
           elif cmd == "cmds":
               print(HELP)
           elif cmd == "/?":
               if not arg:
                   print("[!] Usage: /? <command>")
                   print("[*] Available: search, analyze, defend, exploit, protect, cmds, /?")
               else:
                   topic = arg.strip().lower()
                   if topic in COMMAND_HELP:
                       print(COMMAND_HELP[topic])
                   else:
                       print(f"[!] No help found for '{topic}'")
                       print("[*] Available: search, analyze, defend, exploit, protect, cmds, /?")
           elif cmd == "search":
               if not arg:
                   print("[!] Usage: search <query>")
               else:
                   cmd_search(vectorstore, llm, arg)
           elif cmd == "analyze":
               if not arg:
                   print("[!] Usage: analyze <CVE-ID>")
               else:
                   cmd_analyze(vectorstore, llm, arg)
           elif cmd == "defend":
               if not arg:
                   print("[!] Usage: defend <CVE-ID>")
               else:
                   cmd_defend(vectorstore, llm, arg)
           elif cmd == "exploit":
               if not arg:
                   print("[!] Usage: exploit <CVE-ID>")
               else:
                   cmd_exploit(vectorstore, llm, arg)
           elif cmd == "protect":
               if not arg:
                   print("[!] Usage: protect machine | protect network | protect <IP or hostname>")
               else:
                   cmd_protect(vectorstore, llm, arg)
           else:
               print(f"[!] Unknown command: {cmd} — type 'cmds' for commands")
       except KeyboardInterrupt:
           print("\n\n[*] Shutting down Pyr0Byt3. Stay safe.\n")
           sys.exit(0)
if __name__ == "__main__":
   main()
