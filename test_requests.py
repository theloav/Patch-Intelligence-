# test_requests.py
import requests

try:
    print("Testing connection to google.com...")
    response = requests.get("https://www.google.com")
    response.raise_for_status()
    print("Connection to google.com successful.")

    print("Testing connection to services.nvd.nist.gov...")
    response = requests.get("https://services.nvd.nist.gov")
    response.raise_for_status()
    print("Connection to services.nvd.nist.gov successful.")

except requests.exceptions.RequestException as e:
    print(f"Request failed: {e}")