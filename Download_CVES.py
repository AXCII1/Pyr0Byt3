import requests
import json
import time
from dotenv import load_dotenv
import os

load_dotenv()
API_KEY = os.getenv("NVD_API_KEY") 

all_cves = []
start_index = 0
results_per_page = 2000

while True:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={start_index}&resultsPerPage={results_per_page}"
    response = requests.get(url, headers=headers)
    data = response.json()

    vulnerabilities = data["vulnerabilities"]
    all_cves.extend(vulnerabilities)

    print(f"Fetched {len(all_cves)} / {data['totalResults']}")

    if start_index + results_per_page >= data["totalResults"]:
        break

    start_index += results_per_page
    time.sleep(0.6)

with open("cves.json", "w") as f:
    json.dump(all_cves, f)

print("Done! cves.json saved.")
