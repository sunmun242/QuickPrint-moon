# app.py — QuickMoonPrint (PhonePe V2 ready, Live-compliant)
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
from flask import Flask, request, render_template, jsonify, redirect, url_for, session, send_from_directory, abort, Response
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
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret')

# --- PhonePe / env ---
PHONEPE_CLIENT_ID = os.environ.get('PHONEPE_CLIENT_ID')
PHONEPE_CLIENT_SECRET = os.environ.get('PHONEPE_CLIENT_SECRET')
MERCHANT_ID = os.environ.get('MERCHANT_ID')
CALLBACK_URL = os.environ.get('CALLBACK_URL', 'https://quickmoonprint.in/payment_callback')
ENVIRONMENT = os.environ.get('PHONEPE_ENV', 'live').lower()
SALT_KEY = os.environ.get('PHONEPE_SALT_KEY')
SALT_INDEX = os.environ.get('PHONEPE_SALT_INDEX')

if ENVIRONMENT == 'sandbox':
    PHONEPE_TOKEN_URL = "https://api-preprod.phonepe.com/apis/pg-sandbox/v1/oauth/token"
    PHONEPE_PAY_URL = "https://api-preprod.phonepe.com/apis/pg-sandbox/checkout/v2/pay"
else:
    PHONEPE_TOKEN_URL = "https://api.phonepe.com/apis/identity-manager/v1/oauth/token"
    PHONEPE_PAY_URL = "https://api.phonepe.com/apis/checkout/v2/pay"

# ---------------- token cache ----------------
_token_cache = {"access_token": None, "expires_at": 0}

def get_phonepe_token():
    now = int(time.time())
    if _token_cache.get('access_token') and _token_cache.get('expires_at', 0) > now:
        return _token_cache['access_token']

    payload = {
        'client_id': PHONEPE_CLIENT_ID,
        'client_secret': PHONEPE_CLIENT_SECRET,
        'grant_type': 'client_credentials'
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    try:
        resp = requests.post(PHONEPE_TOKEN_URL, data=payload, headers=headers, timeout=20)
        logger.info("Token response: %s", resp.text)
        if resp.status_code != 200:
            return None
        data = resp.json()
        token = data.get('access_token')
        expires_in = int(data.get('expires_in', 3600))
        _token_cache['access_token'] = token
        _token_cache['expires_at'] = now + expires_in
        return token
    except Exception as e:
        logger.exception("Token fetch failed: %s", e)
        return None

# ---------------- Payment initiate (PhonePe V2) ----------------
@app.route('/payment_initiate', methods=['POST'])
def payment_initiate():
    data = request.get_json()
    if not data or float(data.get('totalCost', 0)) <= 0:
        return jsonify({'error': 'Invalid order data or cost'}), 400

    merchant_order_id = str(uuid.uuid4())[:30]
    total_cost = float(data.get('totalCost'))
    amount_paise = int(total_cost * 100)

    session[merchant_order_id] = {
        'total_cost': total_cost,
        'file_url': data.get('file_url'),
        'copies': data.get('copies', 1),
        'filename': data.get('filename')
    }

    token = get_phonepe_token()
    if not token:
        return jsonify({'error': 'Failed to get PhonePe token'}), 500

    payload = {
        "merchantOrderId": merchant_order_id,
        "amount": amount_paise,
        "expireAfter": 1200,
        "metaInfo": {
            "udf1": "Print job initiated",
            "udf2": "QuickMoonPrint",
            "udf3": "Live mode",
            "udf4": data.get('filename', ''),
            "udf5": str(data.get('copies', 1))
        },
        "paymentFlow": {
            "type": "PG_CHECKOUT",
            "message": "Payment for automated print order",
            "merchantUrls": {"redirectUrl": CALLBACK_URL}
        }
    }

    # Compute X-VERIFY signature
    base_string = json.dumps(payload, separators=(',', ':')) + PHONEPE_PAY_URL + SALT_KEY
    x_verify = hashlib.sha256(base_string.encode()).hexdigest() + "###" + str(SALT_INDEX)

    headers = {
        "Authorization": f"O-Bearer {token}",
        "Content-Type": "application/json",
        "X-VERIFY": x_verify
    }

    try:
        resp = requests.post(PHONEPE_PAY_URL, headers=headers, json=payload, timeout=30)
        logger.info("PhonePe PAY resp %s %s", resp.status_code, resp.text)
        resp_json = resp.json()
    except Exception as e:
        logger.exception("Payment request failed: %s", e)
        return jsonify({'error': 'Gateway communication error', 'detail': str(e)}), 500

    redirect_url = resp_json.get("redirectUrl") or resp_json.get("data", {}).get("redirectUrl")
    if not redirect_url:
        return jsonify({'error': 'Invalid response', 'detail': resp_json}), 400

    return jsonify({'success': True, 'redirectUrl': redirect_url, 'merchantOrderId': merchant_order_id})

# ---------------- uploads ----------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/payment')
def payment_page():
    return render_template('payment.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('fileToPrint')
    if not file:
        return jsonify({'error': 'No file uploaded'}), 400
    filename = secure_filename(file.filename)
    unique = f"{uuid.uuid4()}_{filename}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], unique)
    file.save(path)
    return jsonify({
        'success': True,
        'filename': filename,
        'file_url': url_for('uploaded_file', filename=unique, _external=True)
    })

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ---------------- run ----------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
