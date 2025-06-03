
---

### 🐍 `phishing_detector.py`

```python
import argparse
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import ssl
import socket
import re
import joblib
import os

# ---------- Rule-Based Checks ----------
def is_ip(url):
    return bool(re.match(r"http[s]?://\d+\.\d+\.\d+\.\d+", url))

def has_at_symbol(url):
    return '@' in url

def has_https(url):
    return url.startswith("https://")

def get_ssl_cert(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert()
    except Exception:
        return None

# ---------- Feature Extraction ----------
def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    features = [
        len(url),
        is_ip(url),
        has_at_symbol(url),
        has_https(url),
        1 if get_ssl_cert(hostname) else 0
    ]
    return features

# ---------- ML Prediction ----------
def load_model():
    model_path = "phishing_model.pkl"
    if os.path.exists(model_path):
        return joblib.load(model_path)
    return None

def predict_ml(url):
    model = load_model()
    if model:
        features = extract_features(url)
        prediction = model.predict([features])[0]
        return "Phishing" if prediction == 1 else "Legit"
    return "Model not available"

# ---------- Web Scraping (Optional Use) ----------
def scrape_page(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.content, 'html.parser')
        print("[INFO] Page title:", soup.title.string if soup.title else "None")
    except Exception as e:
        print("[ERROR] Could not scrape page:", str(e))

# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="URL to analyze")
    args = parser.parse_args()

    url = args.url
    print(f"[INFO] Analyzing URL: {url}")

    print(f"- Uses IP instead of domain: {is_ip(url)}")
    print(f"- Contains '@' symbol: {has_at_symbol(url)}")
    print(f"- Uses HTTPS: {has_https(url)}")
    
    parsed = urlparse(url)
    ssl_cert = get_ssl_cert(parsed.hostname or "")
    print(f"- SSL Certificate valid: {bool(ssl_cert)}")

    result = predict_ml(url)
    print(f"✅ Final verdict (ML model): {result}")

if __name__ == "__main__":
    main()
