# Pyr0Byt3 Version 1 - CVE Intelligence Tool


Fully offline AI powered CVE reasearch tool that lets you query 347k CVE vunerabilites using Natural Language. 

No Internet after set up, only API key needed is the MITRE CVE list found here: 

https://cve.mitre.org/data/downloads/


## System STACK

- Ollama ~ Local LLM Runner
- gemma3:4b ~ Language Model
- nomic-embed text ~ Embedding model
- ChromeDB ~ Vector database
- LangChain - RAG pipeline
- NVD API - CVE data source


## REQUIREMENTS
- Python 3.10+ installed
- Ollama installed
- NVIDIA GPU reccomended (3060 laptop GPU is what I have)
- 16GB RAM minimum
- 6GB free storage
- Probably linux, as Windows Slop is SLOP

## Setup

### 1 - Install Ollama
Download from https://ollama.com and pull the required models:
```bash
ollama pull gemma3:4b
ollama pull nomic-embed-text
```

### 2 - Clone the repo
```bash
git clone https://github.com/AXCII1/Pyr0Byt3.git
cd Pyr0Byt3
```

### 3 - Create virtual environment
```bash
python -m venv venv
source venv/bin/activate  # or venv/bin/activate.fish for Fish shell
```

### 4 - Install dependencies
```bash
pip install langchain langchain-ollama chromadb langchain-community langchain-text-splitters ijson python-dotenv requests
```

### 5 - Set up your API key
Get a free NVD API key at https://nvd.nist.gov/developers/request-an-api-key

Create a `.env` file:
```
NVD_API_KEY=your-key-here
```

### 6 - Download CVE data
```bash
python Download_CVES.py
```

### 7 - Ingest into ChromaDB
```bash
python ingest.py
```

### 8 - Query
```bash
python query.py
```

## Usage Examples
```
User: What CVEs affect Apache Log4j?
User1: Show me critical RCE vulnerabilities from 2024
user: How is CVE-2024-1234 exploited?
user: What CVEs involve privilege escalation in Windows?
user:  good morning (this breaks it, need to fix on a later version)
```

## Notes
- **Requires internet to download CVE data and models**
- Everything runs fully offline after setup
- 347k CVEs searchable via semantic search
