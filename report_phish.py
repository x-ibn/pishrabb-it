#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ===== IMPORT LIBRARIES =====
import cloudscraper
import requests
import urllib.parse
import time
import logging
import os
import random
import socket
import sys
from datetime import datetime
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from colorama import Fore, Style, init

# ===== INITIALIZE COLORAMA =====
init(autoreset=True)

# ===== CHECK & CREATE LOGS FOLDER =====
if not os.path.exists("logs"):
    os.makedirs("logs")

# ===== SETUP AUTO CLEAN OLD LOGS =====
def clean_old_logs(log_folder="logs"):
    now = time.time()
    max_days = int(os.getenv("MAX_LOG_DAYS", 30))
    cutoff = now - (max_days * 86400)
    if not os.path.exists(log_folder):
        return
    for filename in os.listdir(log_folder):
        filepath = os.path.join(log_folder, filename)
        if os.path.isfile(filepath):
            file_mtime = os.path.getmtime(filepath)
            if file_mtime < cutoff:
                try:
                    os.remove(filepath)
                    print(f"[INFO] Deleted old log: {filename}")
                except Exception as e:
                    print(f"[ERROR] Failed to delete {filename}: {e}")

clean_old_logs()

# ===== SETUP AUTO LOG FILE =====
today_str = datetime.now().strftime("%Y-%m-%d")
log_file_path = os.path.join("logs", f"phishing-{today_str}.log")

class LoggerToFile(object):
    def __init__(self):
        self.terminal = sys.stdout
        self.logfile = open(log_file_path, "a", encoding="utf-8")

    def write(self, message):
        self.terminal.write(message)
        self.logfile.write(message)

    def flush(self):
        self.terminal.flush()
        self.logfile.flush()

sys.stdout = LoggerToFile()
sys.stderr = LoggerToFile()

# ===== CUSTOM LOGGER WITH COLOR =====
def log_info(message):
    print(f"{Fore.LIGHTBLACK_EX}[INFO] {message}{Style.RESET_ALL}")

def log_success(message):
    print(f"{Fore.GREEN}{Style.BRIGHT}[SUCCESS] {message}{Style.RESET_ALL}")

def log_warning(message):
    print(f"{Fore.YELLOW}{Style.BRIGHT}[WARNING] {message}{Style.RESET_ALL}")

def log_error(message):
    print(f"{Fore.RED}{Style.BRIGHT}[ERROR] {message}{Style.RESET_ALL}")

# ===== LOAD .ENV =====
load_dotenv()

# ===== CONFIGURATION =====
CONFIG = {
    "phish_api_key": os.getenv("PHISH_API_KEY"),
    "google_safe_browsing_api_key": os.getenv("SAFE_BROWSING_API_KEY"),
    "virustotal_api_key": os.getenv("VIRUSTOTAL_API_KEY"),
    "abuseipdb_api_key": os.getenv("ABUSEIPDB_API_KEY"),
    "urlscan_api_key": os.getenv("URLSCAN_API_KEY"),
    "telegram_bot_token": os.getenv("TELEGRAM_BOT_TOKEN"),
    "telegram_chat_id": os.getenv("TELEGRAM_CHAT_ID"),
    "google_api_key": os.getenv("GOOGLE_API_KEY"),
    "cse_id": os.getenv("CSE_ID"),
    "keywords": [
        "yourbrand",
        "site:ex.ex yourbrand",
    ],
    "max_pages": 3,
    "min_delay": 10,
    "max_delay": 20,
    "timeout": 30,
    "force_report": True
}

BRAND_KEYWORDS = ["yourbrand"]
PROCESSED_FILE = "processed_urls.txt"
MANUAL_FILE = "manual_urls.txt"

# ===== RANDOM DELAY FUNCTION =====
def random_delay():
    delay = random.randint(CONFIG["min_delay"], CONFIG["max_delay"])
    log_info(f"⏳ Waiting {delay} seconds...")
    time.sleep(delay)

# ===== LOAD PROCESSED URLS =====
def load_processed():
    if not os.path.exists(PROCESSED_FILE):
        return set()
    with open(PROCESSED_FILE, "r") as f:
        return set(f.read().splitlines())

# ===== SAVE PROCESSED URL =====
def save_processed(url):
    with open(PROCESSED_FILE, "a") as f:
        f.write(url + "\n")

# ===== LOAD MANUAL URLS =====
def load_manual_urls():
    if not os.path.exists(MANUAL_FILE):
        log_info(f"📄 No manual URLs file found: {MANUAL_FILE}")
        return []
    with open(MANUAL_FILE, "r") as f:
        urls = [line.strip() for line in f if line.strip()]
    log_info(f"📄 Found {len(urls)} manual URLs")
    return urls

# ===== GOOGLE SEARCH FUNCTION =====
def google_search(query, num_pages=1):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept-Language": "en-US,en;q=0.9"
    }
    urls = []
    for page in range(num_pages):
        try:
            url = f"https://www.googleapis.com/customsearch/v1?q={urllib.parse.quote(query)}&key={CONFIG['google_api_key']}&cx={CONFIG['cse_id']}&start={page*10+1}"
            response = requests.get(url, headers=headers, timeout=CONFIG['timeout'])

            if response.status_code == 429:
                log_warning("⚠️ Rate limit hit! Waiting...")
                random_delay()
                continue

            search_results = response.json()
            if "items" in search_results:
                for item in search_results["items"]:
                    link = item["link"]
                    if urllib.parse.urlparse(link).scheme in ('http', 'https'):
                        urls.append(link)
            else:
                log_error(f"Google CSE Error: {response.status_code} {response.text}")

            random_delay()

        except Exception as e:
            log_error(f"Failed Google Search: {e}")
            random_delay()

    return list(set(urls))

# ===== DETECT BRAND IN URL =====
def detect_branding(url):
    parsed_url = urllib.parse.urlparse(url)
    full_url = url.lower()
    query_params = urllib.parse.parse_qs(parsed_url.query)

    for keyword in BRAND_KEYWORDS:
        if keyword in full_url:
            return True

    for key, values in query_params.items():
        if any(keyword in val.lower() for val in values for keyword in BRAND_KEYWORDS):
            return True

    return False

# ===== DETECT BRAND IN PAGE CONTENT =====
def detect_in_content(url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        response = requests.get(url, headers=headers, timeout=CONFIG["timeout"])
        html = response.text.lower()

        for keyword in BRAND_KEYWORDS:
            if keyword in html:
                return True
    except Exception as e:
        log_error(f"❌ Failed to read content: {e}")
    return False

# ===== PHISHING CHECK FUNCTION =====
def cek_phishing(url):
    try:
        api_url = "https://api.phish.report/v1/url/"
        headers = {"Authorization": f"Bearer {CONFIG['phish_api_key']}"}
        scraper = cloudscraper.create_scraper()
        response = scraper.post(api_url, json={"url": url}, headers=headers, timeout=CONFIG["timeout"])

        if response.status_code == 200:
            result = response.json()
            return result.get("phishing", False)
        else:
            log_error(f"Error phishing check: {response.status_code} {response.text}")
            return False
    except Exception as e:
        log_error(f"Exception phishing check: {e}")
        return False

# ===== SEND TELEGRAM NOTIFICATION =====
def send_telegram(message, phishing=False):
    try:
        emoji = "🚨" if phishing else "✅"
        text = f"{emoji} {message}"
        url = f"https://api.telegram.org/bot{CONFIG['telegram_bot_token']}/sendMessage"
        payload = {
            "chat_id": CONFIG["telegram_chat_id"],
            "text": text,
            "parse_mode": "Markdown"
        }
        response = requests.post(url, data=payload, timeout=CONFIG["timeout"])
        if response.status_code != 200:
            log_error(f"Telegram send failed: {response.text}")
    except Exception as e:
        log_error(f"Telegram exception: {e}")

# ===== REPORT TO VIRUSTOTAL =====
def report_to_virustotal(url):
    try:
        api_url = "https://www.virustotal.com/api/v3/urls"
        headers = {
            "x-apikey": CONFIG["virustotal_api_key"]
        }
        payload = {"url": url}
        response = requests.post(api_url, headers=headers, data=payload, timeout=CONFIG["timeout"])
        if response.status_code == 200:
            data = response.json()
            log_success(f"VirusTotal submit success: {data.get('data', {}).get('id', 'No ID')}")
        else:
            log_error(f"VirusTotal error: {response.status_code} {response.text}")
    except Exception as e:
        log_error(f"VirusTotal exception: {e}")

# ===== REPORT TO ABUSEIPDB =====
def report_to_abuseipdb(url):
    try:
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.hostname

        if not domain:
            log_error(f"❌ Cannot parse domain from {url}")
            return

        ip_address = socket.gethostbyname(domain)
        log_info(f"🌐 IP address of {domain}: {ip_address}")

        api_url = "https://api.abuseipdb.com/api/v2/report"
        headers = {
            "Key": CONFIG["abuseipdb_api_key"],
            "Accept": "application/json"
        }
        payload = {
            "ip": ip_address,
            "categories": "22",  # 22 = Phishing
            "comment": f"Detected phishing URL {url}"
        }
        response = requests.post(api_url, headers=headers, data=payload, timeout=CONFIG["timeout"])
        if response.status_code == 200:
            data = response.json()
            log_success(f"AbuseIPDB report success: {data.get('data', {}).get('ipAddress', 'No IP')}")
        else:
            log_error(f"AbuseIPDB error: {response.status_code} {response.text}")
    except Exception as e:
        log_error(f"AbuseIPDB exception: {e}")

# ===== REPORT TO URLSCAN =====
def report_to_urlscan(url):
    try:
        api_url = "https://urlscan.io/api/v1/scan/"
        headers = {
            "API-Key": CONFIG["urlscan_api_key"],
            "Content-Type": "application/json"
        }
        payload = {
            "url": url,
            "visibility": "private"
        }
        response = requests.post(api_url, headers=headers, json=payload, timeout=CONFIG["timeout"])
        if response.status_code == 200:
            data = response.json()
            log_success(f"URLScan submission success: {data.get('uuid', 'No UUID')}")
        else:
            log_error(f"URLScan error: {response.status_code} {response.text}")
    except Exception as e:
        log_error(f"URLScan exception: {e}")

# ===== PROCESS EACH URL =====
def process_url(url):
    branding_detected = detect_branding(url) or detect_in_content(url)
    phishing_detected = cek_phishing(url)

    if phishing_detected or branding_detected:
        log_warning(f"🚨 Threat Detected: {url}")
        send_telegram(f"*THREAT Detected*\n{url}", phishing=True)
        report_to_virustotal(url)
        report_to_abuseipdb(url)
        report_to_urlscan(url)
        save_processed(url)
    else:
        log_success(f"✅ Safe URL: {url}")
        send_telegram(f"*URL Safe*\n{url}", phishing=False)

# ===== MAIN FUNCTION =====
def main():
    log_info("\n" + "="*50)
    log_info("🟢 AUTO PHISHING & BRANDING SCANNER STARTED")
    log_info("="*50 + "\n")

    processed_urls = load_processed()
    manual_urls = load_manual_urls()

    try:
        # === PROCESS MANUAL URLS FIRST
        for url in manual_urls:
            if url in processed_urls:
                log_info(f"⏭️ Skipping manual URL (already processed): {url}")
                continue
            process_url(url)
            random_delay()

        # === PROCESS GOOGLE SEARCH URLS
        for keyword in CONFIG["keywords"]:
            log_info(f"\n🔍 Searching: {keyword}")
            urls = google_search(keyword, CONFIG["max_pages"])

            if not urls:
                log_warning("❌ No search results found.")
                continue

            log_info(f"📊 Found {len(urls)} unique URLs")

            for url in urls:
                if url in processed_urls:
                    log_info(f"⏭️ Skipping URL (already processed): {url}")
                    continue
                process_url(url)
                random_delay()

    except KeyboardInterrupt:
        log_info("\n🛑 Program interrupted by user.")
    except Exception as e:
        log_error(f"❌ Unexpected Error: {e}")
    finally:
        log_info("\n" + "="*50)
        log_info("🛑 PROGRAM ENDED")
        log_info("="*50)

# ===== RUN PROGRAM =====
if __name__ == "__main__":
    main()
