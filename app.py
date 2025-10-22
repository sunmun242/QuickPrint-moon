# app.py — QuickMoonPrint (PhonePe Live FINAL version as per integration team)
# Author: Sunmun Islam

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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

# --- PhonePe ENV ---
PHONEPE_CLIENT_ID = os.environ.get('PHONEPE_CLIENT_ID')
PHONEPE_CLIENT_SECRET = os.environ.get('PHONEPE_CLIENT_SECRET')
PHONEPE_CLIENT_VERSION = os.environ.get('PHONEPE_CLIENT_VERSION', '1')
MERCHANT_ID = os.environ.get('MERCHANT_ID')
CALLBACK_URL = os.environ.get('CALLBACK_URL', 'https://quickmoonprint.in/payment_callback')
ENVIRONMENT = os.environ.get('PHONEPE_ENV', 'sandbox').lower()

# ✅ Correct token + payment endpoints
if ENVIRONMENT == 'sandbox':
    PHONEPE_TOKEN_URL = "https://api-preprod.phonepe.com/apis/pg-sandbox/v1/oauth/token"
    PHONEPE_PAY_URL = "https://api-preprod.phonepe.com/apis/pg-sandbox/checkout/v2/pay"
else:
    PHONEPE_TOKEN_URL = "https://api.phonepe.com/apis/identity-manager/v1/oauth/token"
    PHONEPE_PAY_URL = "https://api.phonepe.com/apis/hermes/checkout/v2/pay"

# webhook & printer
WEBHOOK_USERNAME = os.environ.get('WEBHOOK_USERNAME', 'quickmoonprint')
WEBHOOK_PASSWORD = os.environ.get('WEBHOOK_PASSWORD', 'Sunmun2005')
PRINTER_AGENT_KEY = os.environ.get('PRINTER_AGENT_KEY', 'dev-print-key-please-change')
PRINTER_NAME = os.environ.get('PRINTER_NAME', "EPSON L3250 Series")
SUMATRA_PATH = os.environ.get('SUMATRA_PATH', r"C:\Users\SUNMUN\AppData\Local\SumatraPDF\SumatraPDF.exe")

SALES_DATA_FILE = os.environ.get('SALES_DATA_FILE', 'sales_data.json')
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

# ---------------- token cache ----------------
_token_cache = {"access_token": None, "expires_at": 0}

def get_phonepe_token():
    now = int(time.time())
    if _token_cache.get('access_token') and _token_cache['expires_at'] - 30 > now:
        return _token_cache['access_token']

    payload = {
        'client_id': PHONEPE_CLIENT_ID,
        'client_secret': PHONEPE_CLIENT_SECRET,
        'grant_type': 'client_credentials',
        'client_version': PHONEPE_CLIENT_VERSION  # ✅ Added as requested
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    try:
        resp = requests.post(PHONEPE_TOKEN_URL, data=payload, headers=headers, timeout=20)
        if resp.status_code != 200:
            logger.error("Token fetch error: %s", resp.text)
            return None
        data = resp.json()
        token = data.get('access_token')
        expires_in = int(data.get('expires_in', 3000))
        _token_cache['access_token'] = token
        _token_cache['expires_at'] = now + expires_in
        logger.info("Token generated OK")
        return token
    except requests.RequestException as e:
        logger.exception("PhonePe token fetch failed: %s", e)
        return None

# ---------------- Payment Initiate ----------------
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

    # ✅ Final payload (from PhonePe meeting)
    payload = {
        "merchantOrderId": merchant_order_id,
        "clientVersion": PHONEPE_CLIENT_VERSION,
        "amount": amount_paise,
        "expireAfter": 1200,
        "metaInfo": {f"udf{i}": f"additional-info-{i}" for i in range(1, 6)},
        "paymentFlow": {
            "type": "PG_CHECKOUT",
            "message": "Payment message used for collect requests",
            "merchantUrls": {
                "redirectUrl": CALLBACK_URL
            }
        }
    }

    # ✅ Updated headers (no X-VERIFY)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        resp = requests.post(PHONEPE_PAY_URL, headers=headers, json=payload, timeout=30)
        logger.info("PhonePe pay response: %s", resp.text)
        resp_json = resp.json()
    except Exception as e:
        logger.exception("Payment request failed: %s", e)
        return jsonify({'error': 'Gateway communication error', 'detail': str(e)}), 500

    redirect_url = resp_json.get("redirectUrl") or resp_json.get('data', {}).get('redirectUrl')
    if not redirect_url:
        return jsonify({'error': 'No redirect URL found', 'detail': resp_json}), 400

    return jsonify({'success': True, 'redirectUrl': redirect_url, 'merchantOrderId': merchant_order_id})

# ---------------- routes ----------------
@app.route('/')
def index(): return render_template('index.html')

@app.route('/payment')
def payment_page(): return render_template('payment.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('fileToPrint')
    if not file or file.filename == '':
        return jsonify({'error': 'No file uploaded'}), 400
    filename = secure_filename(file.filename)
    unique = f"{uuid.uuid4()}_{filename}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], unique)
    file.save(path)
    file_url = url_for('uploaded_file', filename=unique, _external=True)
    return jsonify({'success': True, 'filename': filename, 'file_url': file_url})

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        abort(404)

# ---------------- run ----------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
