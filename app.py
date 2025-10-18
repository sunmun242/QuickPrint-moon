# app.py — QuickMoonPrint (PhonePe Live V2 Ready + Printer Agent Integration)

import os
import time
import uuid
import json
import logging
import threading
import subprocess
import tempfile
import requests
from functools import wraps
from datetime import datetime
from flask import Flask, request, render_template, jsonify, redirect, url_for, session, send_from_directory, abort, Response
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from PyPDF2 import PdfReader

# ---------------- Logging ----------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app")

# ---------------- Config ----------------
if os.environ.get("VERCEL"):
    UPLOAD_FOLDER = "/tmp/uploads"
else:
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__, static_folder="static", template_folder="templates")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.secret_key = os.environ.get("SECRET_KEY", "local-secret")

# ---------------- ENV Variables ----------------
PHONEPE_CLIENT_ID = os.environ.get("PHONEPE_CLIENT_ID")
PHONEPE_CLIENT_SECRET = os.environ.get("PHONEPE_CLIENT_SECRET")
PHONEPE_CLIENT_VERSION = os.environ.get("PHONEPE_CLIENT_VERSION", "1")
MERCHANT_ID = os.environ.get("MERCHANT_ID")
CALLBACK_URL = os.environ.get("CALLBACK_URL", "https://quickmoonprint.in/payment_callback")
ENVIRONMENT = os.environ.get("PHONEPE_ENV", "sandbox").lower()  # 'sandbox' or 'live'

# ✅ Correct PhonePe API URLs
if ENVIRONMENT == "sandbox":
    PHONEPE_TOKEN_URL = "https://api-preprod.phonepe.com/apis/pg-sandbox/v1/oauth/token"
    PHONEPE_PAY_URL = "https://api-preprod.phonepe.com/apis/pg-sandbox/checkout/v2/pay"
else:
    PHONEPE_TOKEN_URL = "https://api.phonepe.com/apis/pg/v1/oauth/token"
    PHONEPE_PAY_URL = "https://api.phonepe.com/apis/pg/checkout/v2/pay"

# ---------------- Admin and Printer Config ----------------
WEBHOOK_USERNAME = os.environ.get("WEBHOOK_USERNAME", "quickmoonprint")
WEBHOOK_PASSWORD = os.environ.get("WEBHOOK_PASSWORD", "Sunmun2005")
PRINTER_AGENT_KEY = os.environ.get("PRINTER_AGENT_KEY", "dev-print-key")
PRINTER_NAME = os.environ.get("PRINTER_NAME", "EPSON L3250 Series")
SUMATRA_PATH = os.environ.get("SUMATRA_PATH", r"C:\Users\SUNMUN\AppData\Local\SumatraPDF\SumatraPDF.exe")
SALES_DATA_FILE = os.environ.get("SALES_DATA_FILE", "sales_data.json")

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}

# ---------------- File Helpers ----------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def count_pages(filepath):
    try:
        with open(filepath, "rb") as f:
            return len(PdfReader(f).pages)
    except Exception as e:
        logger.warning("count_pages error: %s", e)
        return 1

# ---------------- Sales Data ----------------
def load_sales_data():
    if not os.path.exists(SALES_DATA_FILE):
        return {"transactions": []}
    with open(SALES_DATA_FILE, "r") as f:
        return json.load(f)

def save_sales_data(data):
    with open(SALES_DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

def update_sales_record(cost, transaction_id, file_url=None, copies=1):
    data = load_sales_data()
    tx = {
        "id": transaction_id,
        "date": datetime.utcnow().isoformat(),
        "cost": cost,
        "file_url": file_url,
        "copies": copies,
        "status": "COMPLETED"
    }
    data["transactions"].append(tx)
    save_sales_data(data)

# ---------------- PhonePe Token ----------------
_token_cache = {"access_token": None, "expires_at": 0}
def get_phonepe_token():
    now = int(time.time())
    if _token_cache.get("access_token") and _token_cache["expires_at"] > now:
        return _token_cache["access_token"]

    payload = {
        "client_id": PHONEPE_CLIENT_ID,
        "client_secret": PHONEPE_CLIENT_SECRET,
        "client_version": PHONEPE_CLIENT_VERSION,
        "grant_type": "client_credentials"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    resp = requests.post(PHONEPE_TOKEN_URL, data=payload, headers=headers)
    if resp.status_code != 200:
        logger.error("Token error: %s", resp.text)
        return None

    data = resp.json()
    token = data.get("access_token")
    expires_in = int(data.get("expires_in", 3000))
    _token_cache["access_token"] = token
    _token_cache["expires_at"] = now + expires_in
    return token

# ---------------- Payment Initiate ----------------
@app.route("/payment_initiate", methods=["POST"])
def payment_initiate():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid data"}), 400

    token = get_phonepe_token()
    if not token:
        return jsonify({"error": "Failed to get PhonePe token"}), 500

    merchant_order_id = str(uuid.uuid4())[:20]
    amount_paise = int(float(data.get("totalCost", 0)) * 100)

    payload = {
        "merchantOrderId": merchant_order_id,
        "amount": amount_paise,
        "expireAfter": 900,
        "paymentFlow": {
            "type": "PG_CHECKOUT",
            "merchantUrls": {"redirectUrl": CALLBACK_URL}
        }
    }

    headers = {
        "Authorization": f"O-Bearer {token}",
        "Content-Type": "application/json"
    }

    resp = requests.post(PHONEPE_PAY_URL, headers=headers, json=payload)
    if resp.status_code != 200:
        return jsonify({"error": "Payment initiation failed", "detail": resp.text}), 500

    data = resp.json()
    redirect_url = data.get("redirectUrl") or data.get("data", {}).get("redirectUrl")
    return jsonify({"success": True, "redirectUrl": redirect_url, "merchantOrderId": merchant_order_id})

# ---------------- Webhook Auth ----------------
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != WEBHOOK_USERNAME or auth.password != WEBHOOK_PASSWORD:
            return Response("Unauthorized", 401, {"WWW-Authenticate": 'Basic realm="Login Required"'})
        return f(*args, **kwargs)
    return decorated

# ---------------- Payment Callback ----------------
@app.route("/payment_callback", methods=["POST"])
@requires_auth
def payment_callback():
    payload = request.get_json() or {}
    logger.info("Payment callback: %s", payload)
    order_id = payload.get("merchantOrderId") or payload.get("orderId")
    status = payload.get("status") or payload.get("state")
    if status and str(status).upper() in ["SUCCESS", "COMPLETED", "PAYMENT_SUCCESS"]:
        update_sales_record(0, order_id)
        return jsonify({"message": "Payment success"}), 200
    return jsonify({"message": "Payment not successful"}), 200

# ---------------- Printer API ----------------
@app.route("/api/next_print_job", methods=["GET"])
def next_print_job():
    data = load_sales_data()
    pending = [tx for tx in data["transactions"] if tx["status"] == "COMPLETED"]
    if not pending:
        return jsonify({"message": "No new job"}), 204
    return jsonify(pending[-1]), 200

# ---------------- Upload ----------------
@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files.get("fileToPrint")
    if not file or file.filename == "":
        return jsonify({"error": "No file uploaded"}), 400
    filename = secure_filename(file.filename)
    unique = f"{uuid.uuid4()}_{filename}"
    path = os.path.join(app.config["UPLOAD_FOLDER"], unique)
    file.save(path)
    page_count = count_pages(path)
    file_url = url_for("uploaded_file", filename=unique, _external=True)
    return jsonify({"success": True, "filename": filename, "file_url": file_url, "page_count": page_count})

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# ---------------- Basic Pages ----------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/payment")
def payment_page():
    return render_template("payment.html")

# ---------------- Run ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
