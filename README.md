# 🛡️ Phishing & Branding Auto Scanner

A professional Python tool to automatically scan phishing URLs from Google, detect brand hijacking attempts, and report threats to multiple security platforms.

---

## 🚀 Features

- Google Custom Search API support (multi-keyword)
- Phish.report API integration
- VirusTotal auto submission
- AbuseIPDB IP reputation reporting
- URLScan.io stealth scan
- Manual URL scan support
- `.env` config system for all API keys
- Auto logging with daily log files
- Auto-clean old logs
- Colored logs for better readability
- Telegram bot alert system
- Ready for daily cronjob (run every 11 AM for example)

---

## 📂 Folder Structure

```plaintext
phishing-scanner/
├── report_phish.py         # Main script
├── .env.example            # Template for environment variables
├── manual_urls.txt         # Input URLs manually
├── open_manual.sh          # Bash helper to open the manual URL file
├── requirements.txt        # Dependencies
├── logs/                   # Auto-generated log files
├── images/                 # (Optional) Screenshots or docs

---

