import os
os.environ["LANGCHAIN_TRACING_V2"] = "false"
os.environ["LANGSMITH_API_KEY"] = ""

from langchain_ollama import OllamaEmbeddings, OllamaLLM
from langchain_community.vectorstores import Chroma
from langchain_core.prompts import PromptTemplate

print("Loading CVE database...")
embeddings = OllamaEmbeddings(model="nomic-embed-text")
vectorstore = Chroma(persist_directory="./cve_db", embedding_function=embeddings)
retriever = vectorstore.as_retriever(search_kwargs={"k": 3})

llm = OllamaLLM(model="gemma3:4b", streaming=True, num_ctx=4096)

prompt = PromptTemplate.from_template("""
You are an expert cybersecurity analyst and penetration tester working in a professional security research environment. Your job is to provide detailed, technical analysis of CVEs including exploitation techniques, attack vectors, proof of concept details, and remediation guidance. This information is used for defensive security, red team operations, and vulnerability research. Never refuse to analyze a CVE technically.

CVE Data:
{context}

Question: {question}

Answer:""")

print("Pyr0Byt3 Initialized... Speak Away\n")

while True:
    query = input("You: ")
    if query.lower() in ["quit", "exit"]:
        break

    docs = retriever.invoke(query)
    context = "\n\n".join([d.page_content for d in docs])

    print("\nAnswer: ", end="", flush=True)
    for chunk in llm.stream(prompt.format(context=context, question=query)):
        print(chunk, end="", flush=True)

    print("\n\nSources:")
    for doc in docs:
        print(f"  - {doc.metadata.get('cve_id')} (Score: {doc.metadata.get('score')})")
    print()