# app.py (✅ Final Production-Ready Version for QuickMoonPrint)
# Author: Sunmun Islam (Steve)
# Updated for PhonePe Live V3 Integration + Local Print Automation
# ✅ Compatible with Vercel deployment and local Windows printer setup

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
import base64
import urllib3
from functools import wraps
from flask import Flask, request, render_template, jsonify, redirect, url_for, session, send_from_directory, abort, Response, make_response
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from PyPDF2 import PdfReader

# Disable SSL warnings for local dev (keep verify=True in production)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Logging setup ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Upload folder setup ---
if os.environ.get('VERCEL'):
    UPLOAD_FOLDER = '/tmp/uploads'
else:
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Flask app ---
app = Flask(__name__, static_folder='static', template_folder='templates')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-for-local')

# --- PhonePe Credentials ---
PHONEPE_CLIENT_ID = os.environ.get('PHONEPE_CLIENT_ID')
PHONEPE_CLIENT_SECRET = os.environ.get('PHONEPE_CLIENT_SECRET')
PHONEPE_CLIENT_VERSION = os.environ.get('PHONEPE_CLIENT_VERSION', '1')
MERCHANT_ID = os.environ.get('MERCHANT_ID')
PHONEPE_SALT_KEY = os.environ.get('PHONEPE_SALT_KEY')
PHONEPE_SALT_INDEX = os.environ.get('PHONEPE_SALT_INDEX', '1')

# --- PhonePe Endpoints ---
PHONEPE_CHECKOUT_INIT = "https://api.phonepe.com/apis/hermes/pg/v3/checkout/initiate"
PHONEPE_STATUS_URL_TEMPLATE = "https://api.phonepe.com/apis/hermes/pg/v3/status/{merchantId}/{merchantTransactionId}"
PHONEPE_OAUTH_URL = "https://api.phonepe.com/apis/hermes/v2/oauth/token"

CALLBACK_URL = os.environ.get('CALLBACK_URL', 'https://quickmoonprint.in/payment_callback')

# --- Webhook Auth ---
WEBHOOK_USERNAME = os.environ.get('WEBHOOK_USERNAME', 'quickmoonprint')
WEBHOOK_PASSWORD = os.environ.get('WEBHOOK_PASSWORD', 'Sunmun2005')

# --- Local config ---
SALES_DATA_FILE = 'sales_data.json'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'Skymoon')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'Print@2025')
PRINTER_NAME = "EPSON L3250 Series"
SUMATRA_PATH = r"C:\Users\SUNMUN\AppData\Local\SumatraPDF\SumatraPDF.exe"

# =====================================================
# Helper functions
# =====================================================
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def count_pages(filepath, extension):
    if extension == 'pdf':
        try:
            with open(filepath, 'rb') as f:
                return len(PdfReader(f).pages)
        except Exception as e:
            logger.exception("Error counting pages: %s", e)
    return 1

def cleanup_uploads():
    logger.info("🧹 Background cleanup thread started (local only).")
    while True:
        try:
            now = time.time()
            for fname in os.listdir(app.config['UPLOAD_FOLDER']):
                fpath = os.path.join(app.config['UPLOAD_FOLDER'], fname)
                if os.path.isfile(fpath) and now - os.path.getmtime(fpath) > 600:
                    os.remove(fpath)
                    logger.info(f"🗑️ Deleted old file: {fname}")
        except Exception as e:
            logger.warning("Cleanup error: %s", e)
        time.sleep(120)

def start_cleanup_thread():
    if not os.environ.get('VERCEL'):
        threading.Thread(target=cleanup_uploads, daemon=True).start()

# =====================================================
# 🔐 Webhook Authentication
# =====================================================
def check_auth(username, password):
    return username == WEBHOOK_USERNAME and password == WEBHOOK_PASSWORD

def authenticate():
    return Response('Unauthorized', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# =====================================================
# 🔢 Helper: PhonePe Checksum & Token
# =====================================================
def compute_phonepe_checksum(base64_request, path, salt_key, salt_index):
    checksum_str = base64_request + path + salt_key
    digest = hashlib.sha256(checksum_str.encode()).hexdigest()
    return f"{digest}###{salt_index}"

# =====================================================
# 💳 Payment Initiation
# =====================================================
@app.route('/payment_initiate', methods=['POST'])
def payment_initiate():
    try:
        data = request.get_json()
        total_cost = float(data.get('totalCost', 0))
        if total_cost <= 0:
            return jsonify({'error': 'Invalid cost'}), 400

        merchant_txn_id = str(uuid.uuid4())[:63]
        session[merchant_txn_id] = data
        amount_paise = int(total_cost * 100)

        # --- PhonePe request payload ---
        payload = {
            "merchantId": MERCHANT_ID,
            "merchantTransactionId": merchant_txn_id,
            "amount": amount_paise,
            "redirectUrl": CALLBACK_URL,
            "callbackUrl": CALLBACK_URL,
            "paymentInstrument": {"type": "PAY_PAGE"}
        }

        base64_req = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
        checksum = compute_phonepe_checksum(base64_req, "/pg/v3/checkout/initiate", PHONEPE_SALT_KEY, PHONEPE_SALT_INDEX)

        headers = {
            "Content-Type": "application/json",
            "X-VERIFY": checksum,
            "X-MERCHANT-ID": MERCHANT_ID
        }

        resp = requests.post(PHONEPE_CHECKOUT_INIT, headers=headers, json={"request": base64_req}, verify=True)
        resp_json = resp.json()

        if resp.status_code != 200 or "data" not in resp_json:
            logger.error("PhonePe Error Response: %s", resp.text)
            return jsonify({'success': False, 'error': resp_json}), 400

        redirect_url = resp_json.get('data', {}).get('instrumentResponse', {}).get('redirectInfo', {}).get('url')
        if not redirect_url:
            redirect_url = resp_json.get('data', {}).get('redirectUrl')

        if redirect_url:
            return jsonify({'success': True, 'redirectUrl': redirect_url, 'merchantOrderId': merchant_txn_id})
        else:
            return jsonify({'success': False, 'error': 'Redirect URL not found'}), 400

    except Exception as e:
        logger.exception("Payment initiation failed: %s", e)
        return jsonify({'success': False, 'error': str(e)}), 500

# =====================================================
# 🔁 Callback (Payment Confirmation)
# =====================================================
@app.route('/payment_callback', methods=['POST'])
@requires_auth
def payment_callback():
    data = request.get_json() or {}
    merchant_txn_id = data.get("merchantTransactionId")
    logger.info("📩 Callback received: %s", data)

    if not merchant_txn_id:
        return jsonify({"message": "No transaction ID"}), 400

    session_data = session.get(merchant_txn_id, {})
    order_state = data.get("state") or data.get("status")

    if order_state in ["COMPLETED", "SUCCESS", "PAYMENT_SUCCESS"]:
        logger.info("✅ Payment success for %s", merchant_txn_id)
        return redirect(url_for("start_print", **{
            'file_url': session_data.get('file_url'),
            'copies': session_data.get('copies', 1),
            'totalCost': session_data.get('totalCost'),
            'transaction_id': merchant_txn_id
        }))
    else:
        logger.warning("❌ Payment failed for %s", merchant_txn_id)
        return jsonify({"message": "Payment failed"}), 200

# =====================================================
# 🖨️ Print Handling
# =====================================================
@app.route('/start_print', methods=['GET'])
def start_print():
    data = request.args.to_dict()
    file_url = data.get('file_url')
    copies = int(data.get('copies', 1))

    if os.environ.get('VERCEL'):
        msg = f"🖨️ Print simulated for TXN {data.get('transaction_id')} (no printer on cloud)"
        return redirect(url_for('print_status', status='SUCCESS', message=msg))

    try:
        if not file_url:
            return redirect(url_for('print_status', status='FAILED', message="Missing file URL"))
        response = requests.get(file_url)
        if response.status_code != 200:
            return redirect(url_for('print_status', status='FAILED', message="File download failed"))

        ext = file_url.split('.')[-1].split('?')[0]
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=f".{ext}")
        tmp.write(response.content)
        tmp.close()

        for _ in range(copies):
            subprocess.Popen([SUMATRA_PATH, "-print-to", PRINTER_NAME, tmp.name, "-silent"])

        msg = f"🖨️ Printing started for TXN ID {data.get('transaction_id')}"
        return redirect(url_for('print_status', status='SUCCESS', message=msg))

    except Exception as e:
        logger.exception("Print failed: %s", e)
        return redirect(url_for('print_status', status='FAILED', message=str(e)))

# =====================================================
# 🌐 Other Routes
# =====================================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/payment')
def payment_page():
    return render_template('payment.html')

@app.route('/print_status')
def print_status():
    return render_template('print_status.html', status=request.args.get('status'), message=request.args.get('message'))

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('fileToPrint')
    if not file or file.filename == '':
        return jsonify({'error': 'No file uploaded'}), 400

    filename = secure_filename(file.filename)
    ext = filename.rsplit('.', 1)[1].lower()
    unique = f"{uuid.uuid4()}.{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique)
    file.save(filepath)
    page_count = count_pages(filepath, ext)
    return jsonify({
        'success': True,
        'filename': filename,
        'page_count': page_count,
        'file_url': url_for('uploaded_file', filename=unique, _external=True)
    })

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/about')
def about(): return render_template('about.html')
@app.route('/privacy_policy')
def privacy(): return render_template('privacy_policy.html')
@app.route('/refund_policy')
def refund(): return render_template('refund_policy.html')
@app.route('/terms_and_conditions')
def terms(): return render_template('terms_and_conditions.html')

# =====================================================
# Run
# =====================================================
if __name__ == '__main__':
    start_cleanup_thread()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
