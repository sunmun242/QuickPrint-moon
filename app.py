# app.py — QuickMoonPrint (PhonePe V2 live-ready) with Printer-Agent support
# Replace your existing app.py with this file (backup old first)

import os
import time
import uuid
import json
import logging
import threading
import subprocess
import tempfile
import requests
import hashlib
from functools import wraps
from datetime import datetime
from flask import Flask, request, render_template, jsonify, redirect, url_for, session, send_from_directory, abort, Response, make_response
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from PyPDF2 import PdfReader

# ---------------- logging ----------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------- config ----------------
if os.environ.get('VERCEL'):
    UPLOAD_FOLDER = '/tmp/uploads'
else:
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__, static_folder='static', template_folder='templates')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-for-local')

# --- PhonePe / env ---
PHONEPE_CLIENT_ID = os.environ.get('PHONEPE_CLIENT_ID')
PHONEPE_CLIENT_SECRET = os.environ.get('PHONEPE_CLIENT_SECRET')
PHONEPE_CLIENT_VERSION = os.environ.get('PHONEPE_CLIENT_VERSION', '1')
MERCHANT_ID = os.environ.get('MERCHANT_ID')
CALLBACK_URL = os.environ.get('CALLBACK_URL', 'https://quickmoonprint.in/payment_callback')
ENVIRONMENT = os.environ.get('PHONEPE_ENV', 'sandbox').lower()  # 'sandbox' or 'live'

# ✅ UPDATED ENDPOINTS (no hermes)
if ENVIRONMENT == 'sandbox':
    PHONEPE_TOKEN_URL = "https://api-preprod.phonepe.com/apis/pg-sandbox/v1/oauth/token"
    PHONEPE_PAY_URL = "https://api-preprod.phonepe.com/apis/pg-sandbox/checkout/v2/pay"
else:
    PHONEPE_TOKEN_URL = "https://api.phonepe.com/apis/pg/v1/oauth/token"
    PHONEPE_PAY_URL = "https://api.phonepe.com/apis/pg/checkout/v2/pay"

# webhook basic auth
WEBHOOK_USERNAME = os.environ.get('WEBHOOK_USERNAME', 'quickmoonprint')
WEBHOOK_PASSWORD = os.environ.get('WEBHOOK_PASSWORD', 'Sunmun2005')

# printer agent key (shared secret)
PRINTER_AGENT_KEY = os.environ.get('PRINTER_AGENT_KEY', 'dev-print-key-please-change')

# local printing config
PRINTER_NAME = os.environ.get('PRINTER_NAME', "EPSON L3250 Series")
SUMATRA_PATH = os.environ.get('SUMATRA_PATH', r"C:\Users\SUNMUN\AppData\Local\SumatraPDF\SumatraPDF.exe")

# sales DB file
SALES_DATA_FILE = os.environ.get('SALES_DATA_FILE', 'sales_data.json')

# admin
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'Skymoon')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'Print@2025')

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

# ---------------- helpers: sales DB ----------------
def load_sales_data():
    try:
        if not os.path.exists(SALES_DATA_FILE):
            return {"total_orders": 0, "total_income": 0.0, "daily_sales": {}, "transactions": []}
        with open(SALES_DATA_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.exception("Error loading sales data: %s", e)
        return {"total_orders": 0, "total_income": 0.0, "daily_sales": {}, "transactions": []}

def save_sales_data(data):
    try:
        with open(SALES_DATA_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.exception("Failed to save sales data: %s", e)

def update_sales_record(cost, transaction_id, file_url=None, copies=1):
    data = load_sales_data()
    data['total_orders'] = data.get('total_orders', 0) + 1
    data['total_income'] = float(data.get('total_income', 0.0)) + float(cost or 0.0)
    today = time.strftime('%Y-%m-%d')
    if today not in data['daily_sales']:
        data['daily_sales'][today] = {"orders": 0, "income": 0.0}
    data['daily_sales'][today]['orders'] += 1
    data['daily_sales'][today]['income'] += float(cost or 0.0)

    tx = {
        'id': transaction_id,
        'date': today,
        'cost': cost,
        'file_url': file_url,
        'copies': copies,
        'status': 'COMPLETED',
        'created_at': datetime.utcnow().isoformat(),
        'printed_at': None
    }
    data.setdefault('transactions', []).append(tx)
    save_sales_data(data)

# ---------------- file helpers ----------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def count_pages(filepath):
    try:
        with open(filepath, 'rb') as f:
            return len(PdfReader(f).pages)
    except Exception as e:
        logger.warning("count_pages error: %s", e)
        return 1

# ---------------- cleanup thread ----------------
def cleanup_uploads():
    logger.info("Background cleanup thread running (local only).")
    CLEANUP_INTERVAL = 120
    MAX_FILE_AGE = 3600
    while True:
        try:
            now = time.time()
            for fname in os.listdir(app.config['UPLOAD_FOLDER']):
                fpath = os.path.join(app.config['UPLOAD_FOLDER'], fname)
                if os.path.isfile(fpath) and now - os.path.getmtime(fpath) > MAX_FILE_AGE:
                    try:
                        os.remove(fpath)
                        logger.info(f"Deleted old file: {fname}")
                    except Exception as e:
                        logger.exception(f"Failed to remove {fname}: {e}")
        except Exception:
            logger.exception("Error during cleanup loop.")
        time.sleep(CLEANUP_INTERVAL)

def start_cleanup_thread():
    if not os.environ.get('VERCEL'):
        t = threading.Thread(target=cleanup_uploads, daemon=True)
        t.start()

# ---------------- webhook basic auth decorator ----------------
def check_auth(username, password):
    return username == WEBHOOK_USERNAME and password == WEBHOOK_PASSWORD

def authenticate():
    return Response('Could not verify your access level for that URL.\nAuthentication required', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            logger.warning("Webhook Authentication Failed!")
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# ---------------- token cache ----------------
_token_cache = {"access_token": None, "expires_at": 0}

def get_phonepe_token():
    now = int(time.time())
    if _token_cache.get('access_token') and _token_cache.get('expires_at', 0) - 30 > now:
        return _token_cache['access_token']

    payload = {
        'client_id': PHONEPE_CLIENT_ID,
        'client_secret': PHONEPE_CLIENT_SECRET,
        'grant_type': 'client_credentials'
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    try:
        resp = requests.post(PHONEPE_TOKEN_URL, data=payload, headers=headers, timeout=20)
        if resp.status_code != 200:
            logger.error("Token error: %s", resp.text)
            return None
        data = resp.json()
        token = data.get('access_token')
        expires_in = int(data.get('expires_in', 3000))
        _token_cache['access_token'] = token
        _token_cache['expires_at'] = int(time.time()) + expires_in
        logger.info("Fetched PhonePe token successfully.")
        return token
    except requests.RequestException as e:
        logger.exception("Failed to fetch PhonePe token: %s", e)
        return None

# ---------------- Payment initiate ----------------
@app.route('/payment_initiate', methods=['POST'])
def payment_initiate():
    data = request.get_json()
    if not data or float(data.get('totalCost', 0)) <= 0:
        return jsonify({'error': 'Invalid order data or cost'}), 400

    merchant_order_id = str(uuid.uuid4())[:30]
    session[merchant_order_id] = {
        'total_cost': data.get('totalCost'),
        'file_url': data.get('file_url'),
        'copies': data.get('copies', 1),
        'filename': data.get('filename')
    }

    token = get_phonepe_token()
    if not token:
        return jsonify({'error': 'Failed to get PhonePe token'}), 500

    amount_paise = int(round(float(data.get('totalCost')) * 100))

    payload = {
        "merchantId": MERCHANT_ID,
        "merchantTransactionId": merchant_order_id,
        "amount": amount_paise,
        "callbackUrl": CALLBACK_URL,
        "merchantUserId": "User001",
        "paymentInstrument": {"type": "PAY_PAGE"}
    }

    checksum_string = json.dumps(payload) + "/pg/v1/pay" + os.environ.get("PHONEPE_SALT_KEY")
    checksum = hashlib.sha256(checksum_string.encode()).hexdigest() + "###" + os.environ.get("PHONEPE_SALT_INDEX")

    headers = {
        "Content-Type": "application/json",
        "X-VERIFY": checksum
    }

    try:
        resp = requests.post(PHONEPE_PAY_URL, headers=headers, json=payload, timeout=30)
        logger.info("PhonePe pay response: %s", resp.text)
        resp_json = resp.json()
    except Exception as e:
        logger.exception("PhonePe request failed: %s", e)
        return jsonify({'error': 'Gateway communication error', 'detail': str(e)}), 500

    redirect_url = resp_json.get("data", {}).get("instrumentResponse", {}).get("redirectInfo", {}).get("url")
    if not redirect_url:
        return jsonify({'error': 'No redirect URL in response', 'detail': resp_json}), 400

    return jsonify({'success': True, 'redirectUrl': redirect_url, 'merchantOrderId': merchant_order_id})

# ---------------- Payment callback ----------------
@app.route('/payment_callback', methods=['POST'])
@requires_auth
def payment_callback():
    payload = request.get_json() or {}
    logger.info("Payment callback payload: %s", payload)

    merchant_order_id = payload.get('merchantTransactionId')
    status = payload.get('code')

    session_data = session.get(merchant_order_id)
    total_cost = session_data.get('total_cost') if session_data else None
    file_url = session_data.get('file_url') if session_data else None
    copies = session_data.get('copies') if session_data else 1

    if status == "PAYMENT_SUCCESS":
        update_sales_record(total_cost or 0.0, merchant_order_id, file_url=file_url, copies=copies)
        return jsonify({"message": "Order recorded"}), 200
    else:
        return jsonify({"message": "Payment not successful"}), 200

# ---------------- Printer Agent API ----------------
@app.route('/api/next_print_job', methods=['GET'])
def next_print_job():
    key = request.args.get('key')
    if key != PRINTER_AGENT_KEY:
        return jsonify({"error": "unauthorized"}), 401

    data = load_sales_data()
    for tx in data.get('transactions', []):
        if tx.get('status') == 'COMPLETED':
            return jsonify(tx)
    return jsonify({"message": "no pending job"}), 200

# ---------------- rest unchanged ----------------
@app.route('/')
def index(): return render_template('index.html')

@app.route('/payment')
def payment_page(): return render_template('payment.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('fileToPrint')
    if not file or file.filename == '': return jsonify({'error': 'No file uploaded'}), 400
    if not allowed_file(file.filename): return jsonify({'error': 'File type not allowed'}), 400
    filename = secure_filename(file.filename)
    unique = f"{uuid.uuid4()}_{filename}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], unique)
    file.save(path)
    page_count = count_pages(path)
    file_url = url_for('uploaded_file', filename=unique, _external=True)
    return jsonify({'success': True, 'filename': filename, 'page_count': page_count, 'file_url': file_url})

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    try: return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError: abort(404)

@app.route('/print_status')
def print_status(): return render_template('print_status.html', status=request.args.get('status'), message=request.args.get('message'))

@app.route('/about')
def about(): return render_template('about.html')
@app.route('/privacy_policy')
def privacy(): return render_template('privacy_policy.html')
@app.route('/refund_policy')
def refund(): return render_template('refund_policy.html')
@app.route('/terms_and_conditions')
def terms(): return render_template('terms_and_conditions.html')

if __name__ == '__main__':
    start_cleanup_thread()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
