# Pyr0Byt3 - Local CVE Threat Intelligence & Script Generation

Fully offline, AI-powered CVE research tool. Query 300K+ CVE vulnerabilities in
natural language, run threat analysis, generate defensive/offensive scripts, and
correlate live Nmap scans against your local CVE database — all without sending
data to the cloud after setup.

Everything runs locally once the data is downloaded. The only internet needed is
during setup, to pull CVE data (NVD, CISA KEV, Exploit-DB) and the Ollama models.

## System Stack

- Ollama ~ Local LLM runner
- qwen2.5-coder:7b ~ Language model
- nomic-embed-text ~ Embedding model
- ChromaDB ~ Vector database
- LangChain ~ RAG pipeline
- NVD API + CISA KEV + Exploit-DB ~ CVE data sources

## Requirements

- Python 3.10+
- Ollama installed
- NVIDIA GPU recommended (tested on a 3060 laptop GPU)
- 16GB RAM minimum
- 6GB free storage
- Nmap (only needed for the `protect` scan command)
- Linux preferred (Arch based systems)

## Setup

### 1 - Install Ollama
Download from https://ollama.com and pull the required models:
```bash
ollama pull qwen2.5-coder:7b
ollama pull nomic-embed-text
```

### 2 - Clone the repo
```bash
git clone https://github.com/AXCII1/Pyr0Byt3.git
cd Pyr0Byt3
```

### 3 - Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate  # or venv/bin/activate.fish for Fish shell
```

### 4 - Install dependencies
```bash
pip install langchain langchain-ollama langchain-chroma langchain-community \
            langchain-text-splitters chromadb ijson python-dotenv requests \
            thefuzz pyspellchecker
```

### 5 - Set up your NVD API key
Get a free NVD API key at https://nvd.nist.gov/developers/request-an-api-key

Create a `.env` file:
```
NVD_API_KEY=your-key-here
```

### 6 - Download CVE data
Pulls CPE-targeted CVEs from NVD plus the CISA KEV and Exploit-DB feeds:
```bash
python Download_CVES.py
```

### 7 - Ingest into ChromaDB
```bash
python ingest_all.py
```

### 8 - Run Pyr0Byt3
```bash
python Pyr0Byt3.py
```

## Commands

```
search  <query>              Semantic search across the CVE database
analyze <CVE-ID>             Full threat analysis of a specific CVE
defend  <CVE-ID>             Generate defensive scripts & detection rules
exploit <CVE-ID>             Generate offensive PoC (requires disclaimer)
protect machine              Scan your local machine
protect network              Scan your local subnet (auto-detect interface)
protect <IP or hostname>     Scan a single target (requires disclaimer)
cmds                         Show the command list
/?  <command>                Explain how a command works
quit                         Exit Pyr0Byt3
```

## Usage Examples
```
Pyr0Byt3 > search linux kernel privilege escalation
Pyr0Byt3 > analyze CVE-2021-44228
Pyr0Byt3 > defend CVE-2014-6271
Pyr0Byt3 > protect machine
```

## Legal

The `exploit` and `protect` commands are for authorized security research and
testing only. Only scan or test systems you own or have explicit written
permission to assess. Unauthorized use is illegal and is your responsibility.

## Notes
- Requires internet during setup to download CVE data and models; fully offline afterward.
- `Download_CVES.py` and `ingest_all.py` are safe to re-run — ingest upserts by a
  deterministic ID, so you won't duplicate the database.
- 300K+ CVEs searchable via semantic search.
