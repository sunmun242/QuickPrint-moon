import time
import requests
import subprocess
import tempfile
import os

PRINTER_NAME = "EPSON L3250 Series"
SUMATRA_PATH = r"C:\Users\SUNMUN\AppData\Local\SumatraPDF\SumatraPDF.exe"
SERVER_URL = "https://quickmoonprint.in"  # তোমার লাইভ ডোমেইন

print("🖨️ Local Printer Agent Running... Connected to:", SERVER_URL)

while True:
    try:
        # সার্ভার থেকে নতুন প্রিন্ট কাজ আছে কিনা চেক করো
        resp = requests.get(f"{SERVER_URL}/api/next_print_job", timeout=10)
        if resp.status_code == 200:
            job = resp.json()
            if job.get("file_url"):
                print(f"🆕 New Print Job: {job['transaction_id']}")
                r = requests.get(job["file_url"])
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
                tmp.write(r.content)
                tmp.close()
                subprocess.Popen([SUMATRA_PATH, "-print-to", PRINTER_NAME, tmp.name, "-silent"])
                print("✅ Print started:", job["file_url"])
        time.sleep(5)
    except Exception as e:
        print("⚠️ Error:", e)
        time.sleep(5)
