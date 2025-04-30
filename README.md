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

⚙️ Installation
Clone the Repository

bash
Salin
git clone https://github.com/x-ibn/pishrabb-it.git
cd pishrabb-it
Set Up a Virtual Environment (Optional but Recommended)

bash
Salin
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
Install Dependencies

bash
Salin
pip install -r requirements.txt
Configure Environment Variables

Rename .env.example to .env and populate it with your API keys and configurations.

🛠️ Usage
Manual URL Scanning

Add URLs to manual_urls.txt, then execute:​

bash
Salin
  python report_phish.py --manual
Automated Scanning

Schedule the script using cron or Task Scheduler to run at desired intervals.​

Telegram Alerts

Ensure your Telegram bot token and chat ID are set in the .env file to receive alerts.​

📷 Screenshots
(Include relevant screenshots in the images/ directory and reference them here to provide visual context.)​

📄 License
This project is licensed under the MIT License. See the LICENSE file for details.