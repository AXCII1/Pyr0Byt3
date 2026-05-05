from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_ollama import OllamaEmbeddings
from langchain_core.documents import Document
import ijson

BATCH_SIZE = 500

embeddings = OllamaEmbeddings(model="nomic-embed-text")
splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
vectorstore = None
batch = []
total = 0

print("Streaming and ingesting CVEs...")

with open("cves.json", "rb") as f:
    for item in ijson.items(f, "item"):
        cve = item["cve"]
        cve_id = cve["id"]

        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")

        score = "N/A"
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        text = f"CVE ID: {cve_id}\nSeverity Score: {score}\nDescription: {desc}"
        batch.append(Document(page_content=text, metadata={"cve_id": cve_id, "score": str(score)}))

        if len(batch) >= BATCH_SIZE:
            chunks = splitter.split_documents(batch)
            if vectorstore is None:
                vectorstore = Chroma.from_documents(chunks, embeddings, persist_directory="./cve_db")
            else:
                vectorstore.add_documents(chunks)
            total += len(batch)
            print(f"Ingested {total} CVEs...")
            batch = []

# Process remaining
if batch:
    chunks = splitter.split_documents(batch)
    if vectorstore is None:
        vectorstore = Chroma.from_documents(chunks, embeddings, persist_directory="./cve_db")
    else:
        vectorstore.add_documents(chunks)
    total += len(batch)

print(f"Done! {total} CVEs EATEN")