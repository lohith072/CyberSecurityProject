# CyberSecurityProject
Phishing Website Detector using Python to analyze URLs with rule-based checks and ML to identify phishing threats.
# 🛡️ Phishing Website Detector

A Python-based tool to detect phishing websites using both rule-based heuristics (e.g., suspicious links, bad SSL certificates) and a machine learning classifier trained on phishing and legitimate URLs.

## 🔧 Tech Stack

- Python
- scikit-learn
- BeautifulSoup (bs4)
- requests
- joblib

## 📦 Features

- Scrapes and analyzes a given URL for phishing indicators:
  - Suspicious domains or subdomains
  - Bad or missing SSL certificates
  - Embedded `@` symbols or IP-based URLs
- Bonus: Machine Learning classifier to detect phishing URLs

## 🚀 Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/phishing-website-detector.git
   cd phishing-website-detector
