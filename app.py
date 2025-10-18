# app.py — QuickMoonPrint (PhonePe V2 ready) with Printer-Agent support
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

# Choose endpoints based on ENVIRONMENT
if ENVIRONMENT == 'sandbox':
    PHONEPE_TOKEN_URL = "https://api-preprod.phonepe.com/apis/pg-sandbox/v1/oauth/token"
    PHONEPE_PAY_URL = "https://api-preprod.phonepe.com/apis/pg-sandbox/checkout/v2/pay"
else:
    PHONEPE_TOKEN_URL = "https://api.phonepe.com/apis/hermes/v1/oauth/token"
    PHONEPE_PAY_URL = "https://api.phonepe.com/apis/hermes/checkout/v2/pay"

# webhook basic auth
WEBHOOK_USERNAME = os.environ.get('WEBHOOK_USERNAME', 'quickmoonprint')
WEBHOOK_PASSWORD = os.environ.get('WEBHOOK_PASSWORD', 'Sunmun2005')

# printer agent key (shared secret)
PRINTER_AGENT_KEY = os.environ.get('PRINTER_AGENT_KEY', 'dev-print-key-please-change')

# local printing config
PRINTER_NAME = os.environ.get('PRINTER_NAME', "EPSON L3250 Series")
SUMATRA_PATH = os.environ.get('SUMATRA_PATH', r"C:\Users\SUNMUN\AppData\Local\SumatraPDF\SumatraPDF.exe")

# sales DB file (persistent on server)
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
        'client_version': PHONEPE_CLIENT_VERSION,
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
        logger.info("Fetched PhonePe token, expires_at=%s", _token_cache['expires_at'])
        return token
    except requests.RequestException as e:
        logger.exception("Failed to fetch PhonePe token: %s", e)
        return None

# ---------------- Payment initiate (PhonePe V2) ----------------
@app.route('/payment_initiate', methods=['POST'])
def payment_initiate():
    data = request.get_json()
    if not data or float(data.get('totalCost', 0)) <= 0:
        return jsonify({'error': 'Invalid order data or cost'}), 400

    merchant_order_id = str(uuid.uuid4())[:30]
    # store minimal session data
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
        "merchantOrderId": merchant_order_id,
        "amount": amount_paise,
        "expireAfter": 1200,
        "paymentFlow": {
            "type": "PG_CHECKOUT",
            "merchantUrls": {"redirectUrl": CALLBACK_URL}
        }
    }

    headers = {
        "Authorization": f"O-Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        resp = requests.post(PHONEPE_PAY_URL, headers=headers, json=payload, timeout=30)
        logger.info("PhonePe pay response status=%s body=%s", resp.status_code, resp.text)
        resp_json = resp.json()
    except Exception as e:
        logger.exception("PhonePe request failed: %s", e)
        return jsonify({'error': 'Gateway communication error', 'detail': str(e)}), 500

    redirect_url = resp_json.get("redirectUrl") or resp_json.get('data', {}).get('redirectUrl')
    if not redirect_url:
        return jsonify({'error': 'No redirect URL in response', 'detail': resp_json}), 400

    return jsonify({'success': True, 'redirectUrl': redirect_url, 'merchantOrderId': merchant_order_id})

# ---------------- Payment callback (Webhook) ----------------
@app.route('/payment_callback', methods=['POST'])
@requires_auth
def payment_callback():
    payload = request.get_json() or {}
    logger.info("Payment callback payload: %s", payload)

    # phonepe may send merchantOrderId or orderId
    merchant_order_id = payload.get('merchantOrderId') or payload.get('orderId') or payload.get('merchantOrderId')
    status = payload.get('state') or payload.get('status') or payload.get('orderStatus') or payload.get('statusCode')

    # fallback: if not in callback, just log
    if not merchant_order_id:
        logger.warning("Callback missing merchantOrderId/orderId")
        return jsonify({"message": "Callback received"}), 200

    # If our session has data, create record + mark completed
    session_data = session.get(merchant_order_id)
    total_cost = session_data.get('total_cost') if session_data else None
    file_url = session_data.get('file_url') if session_data else None
    copies = session_data.get('copies') if session_data else 1

    # Consider 'SUCCESS' or 'COMPLETED' or numeric codes — adapt as needed
    if status and str(status).upper() in ('COMPLETED', 'SUCCESS', 'PAYMENT_SUCCESS', '200'):
        # create sales record
        update_sales_record(total_cost or 0.0, merchant_order_id, file_url=file_url, copies=copies)
        logger.info("Order %s marked COMPLETED and saved.", merchant_order_id)
        # respond 200 OK to webhook
        return jsonify({"message": "Order recorded"}), 200
    else:
        logger.warning("Payment not successful for %s status=%s", merchant_order_id, status)
        return jsonify({"message": "Payment not successful"}), 200

# ---------------- Pending prints (for printer agent) ----------------
@app.route('/pending_prints', methods=['GET'])
def pending_prints():
    # security: agent must send key param or X-AGENT-KEY header
    key = request.args.get('key') or request.headers.get('X-AGENT-KEY')
    if key != PRINTER_AGENT_KEY:
        return jsonify({'error': 'unauthorized'}), 401

    data = load_sales_data()
    pending = []
    for tx in data.get('transactions', []):
        if tx.get('status') == 'COMPLETED':
            pending.append({
                'id': tx['id'],
                'file_url': tx.get('file_url'),
                'copies': tx.get('copies', 1),
                'cost': tx.get('cost'),
                'created_at': tx.get('created_at')
            })
    return jsonify({'pending': pending}), 200

# ---------------- Mark printed (agent tells server) ----------------
@app.route('/mark_printed', methods=['POST'])
def mark_printed():
    # security: agent must send key param or X-AGENT-KEY header
    key = request.args.get('key') or request.headers.get('X-AGENT-KEY')
    if key != PRINTER_AGENT_KEY:
        return jsonify({'error': 'unauthorized'}), 401

    body = request.get_json() or {}
    tx_id = body.get('id')
    if not tx_id:
        return jsonify({'error': 'missing id'}), 400

    data = load_sales_data()
    for tx in data.get('transactions', []):
        if tx.get('id') == tx_id:
            tx['status'] = 'PRINTED'
            tx['printed_at'] = datetime.utcnow().isoformat()
            save_sales_data(data)
            logger.info("Marked %s as PRINTED", tx_id)
            return jsonify({'success': True}), 200

    return jsonify({'error': 'not found'}), 404

# ---------------- Start print route (manual/redirect) ----------------
@app.route('/start_print', methods=['GET'])
def start_print():
    data = request.args.to_dict()
    file_url = data.get('file_url')
    copies = int(data.get('copies', 1))
    txn_id = data.get('transaction_id')

    if os.environ.get('VERCEL'):
        # On cloud we cannot access local printer — only simulate
        message = f"Print job (TXN: {txn_id}) submitted (Simulated on cloud)."
        return redirect(url_for('print_status', status='SUCCESS', message=message))

    try:
        if not file_url:
            return redirect(url_for('print_status', status='FAILED', message="Missing file URL"))
        response = requests.get(file_url, timeout=60)
        if response.status_code != 200:
            return redirect(url_for('print_status', status='FAILED', message="File download failed"))

        ext = file_url.split('.')[-1].split('?')[0] or "pdf"
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=f".{ext}")
        tmp.write(response.content)
        tmp.close()

        for _ in range(copies):
            subprocess.Popen([SUMATRA_PATH, "-print-to", PRINTER_NAME, tmp.name, "-silent"])

        # Optionally, mark as printed locally (but agent will also mark)
        return redirect(url_for('print_status', status='SUCCESS', message=f"Printing started for TXN {txn_id}"))
    except Exception as e:
        logger.exception("Print error: %s", e)
        return redirect(url_for('print_status', status='FAILED', message=str(e)))

# ---------------- uploads / basic routes ----------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/payment')
def payment_page():
    return render_template('payment.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('fileToPrint')
    if not file or file.filename == '':
        return jsonify({'error': 'No file uploaded'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400

    filename = secure_filename(file.filename)
    unique = f"{uuid.uuid4()}_{filename}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], unique)
    file.save(path)
    page_count = count_pages(path)
    # Return external URL (server must be reachable)
    file_url = url_for('uploaded_file', filename=unique, _external=True)
    return jsonify({
        'success': True,
        'filename': filename,
        'page_count': page_count,
        'file_url': file_url
    })

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        abort(404)

@app.route('/print_status')
def print_status():
    return render_template('print_status.html', status=request.args.get('status'), message=request.args.get('message'))

@app.route('/about')
def about(): return render_template('about.html')
@app.route('/privacy_policy')
def privacy(): return render_template('privacy_policy.html')
@app.route('/refund_policy')
def refund(): return render_template('refund_policy.html')
@app.route('/terms_and_conditions')
def terms(): return render_template('terms_and_conditions.html')

# ---------------- run ----------------
if __name__ == '__main__':
    start_cleanup_thread()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
