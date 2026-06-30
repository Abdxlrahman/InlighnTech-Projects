#!/usr/bin/env python3
"""
Elasticsearch Ingestion Validation Script
"""
import sys
import json
import urllib.request
import ssl

ES_HOST = "https://127.0.0.1:9200"
ES_USER = "elastic"
ES_PASS = "elastic123"

def query_elasticsearch(endpoint, method="GET", payload=None):
    url = f"{ES_HOST}/{endpoint}"
    context = ssl._create_unverified_context()
    auth_handler = urllib.request.HTTPBasicAuthHandler()
    auth_handler.add_password(realm=None, uri=ES_HOST, user=ES_USER, passwd=ES_PASS)
    opener = urllib.request.build_opener(auth_handler)
    req = urllib.request.Request(url, method=method)
    req.add_header("Content-Type", "application/json")
    data = json.dumps(payload).encode("utf-8") if payload else None
    try:
        with opener.open(req, data=data, timeout=5) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return 500, {"error": str(e)}

if __name__ == "__main__":
    print("[*] Contacting local Elasticsearch instance index registry...")
    status, response = query_elasticsearch("_cat/indices?format=json")
    if status == 200:
        print("[+] Log Ingestion Active Indices:")
        for idx in response:
            if "logs-" in idx.get("index", ""):
                print(f"    - Index: {idx.get('index')} | Docs: {idx.get('docs.count')}")
    else:
        print(f"[-] Error querying indices: {response}")\n