# app.py — QuickMoonPrint (PhonePe V2 ready with Dynamic Print Mode and Admin Report)

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
from datetime import datetime, timedelta # <<< timedelta যোগ করা হলো
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
CALLBACK_URL = os.environ.get('CALLBACK_URL', 'https://quickmoonprint.in/payment_redirect')
ENVIRONMENT = os.environ.get('PHONEPE_ENV', 'sandbox').lower()  # 'sandbox' or 'live'

# UAT/SANDBOX credentials provided by PhonePe team for secure testing (fallback)
UAT_CLIENT_ID = "TEST-M232UJ245EK43_25101"
UAT_CLIENT_SECRET = "ZTIzOTRiYjMtNmE5NS00ZjBiLWE3NjQtMTE0MmIyMDFiMzcx"
UAT_CLIENT_VERSION = "1"
UAT_MERCHANT_ID = "M232UJ245EK43" 

# Choose endpoints based on ENVIRONMENT
if ENVIRONMENT == 'sandbox':
    if not PHONEPE_CLIENT_ID: 
        PHONEPE_CLIENT_ID = UAT_CLIENT_ID
        PHONEPE_CLIENT_SECRET = UAT_CLIENT_SECRET
        PHONEPE_CLIENT_VERSION = UAT_CLIENT_VERSION
        MERCHANT_ID = UAT_MERCHANT_ID

    PHONEPE_TOKEN_URL = "https://api-preprod.phonepe.com/apis/pg-sandbox/v1/oauth/token"
    PHONEPE_PAY_URL = "https://api-preprod.phonepe.com/apis/pg-sandbox/checkout/v2/pay"
else:
    PHONEPE_TOKEN_URL = "https://api.phonepe.com/apis/identity-manager/v1/oauth/token"
    PHONEPE_PAY_URL = "https://api.phonepe.com/apis/pg/checkout/v2/pay"

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

def update_sales_record(cost, transaction_id, file_url=None, copies=1, print_mode='Color'):
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
        'print_mode': print_mode,
        'status': 'COMPLETED',
        'created_at': datetime.utcnow().isoformat(),
        'printed_at': None
    }
    
    # FIX: Search for the existing transaction placeholder to update it
    found = False
    for i, existing_tx in enumerate(data.setdefault('transactions', [])):
        if existing_tx.get('id') == transaction_id and existing_tx.get('status') == 'PENDING':
            # Update the existing placeholder with final data
            data['transactions'][i].update(tx)
            data['transactions'][i]['status'] = 'COMPLETED'
            found = True
            break
            
    if not found:
        # If no placeholder was found (old flow/data), append it as completed
        data['transactions'].append(tx)
        
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

# ---------------- ADMIN AUTH & ROUTES ----------------
def requires_admin_auth(f):
    """Decorator to protect admin routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_logged_in' not in session or not session['admin_logged_in']:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Handles admin login."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            # Assumes you have an admin_login.html template
            return render_template('admin_login.html', error="Invalid credentials") 
    return render_template('admin_login.html', error=None)

@app.route('/admin/logout')
def admin_logout():
    """Handles admin logout."""
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@requires_admin_auth
def admin_dashboard():
    """Renders the admin dashboard with sales reports."""
    data = load_sales_data()
    transactions = data.get('transactions', [])
    
    now = datetime.now()
    today_str = now.strftime('%Y-%m-%d')
    current_month_str = now.strftime('%Y-%m')
    
    # Calculate Last Month Start Date
    last_month_start = (now.replace(day=1) - timedelta(days=1)).replace(day=1)
    last_month_str = last_month_start.strftime('%Y-%m')
    
    # Calculate Summary Stats
    total_income = data.get('total_income', 0.0)
    
    # Get today's income
    today_income = data['daily_sales'].get(today_str, {}).get('income', 0.0)
    
    # Calculate current month's income
    current_month_income = sum(
        d.get('income', 0.0) for date_str, d in data['daily_sales'].items() 
        if date_str.startswith(current_month_str)
    )
    
    # Calculate last month's income
    last_month_income = sum(
        d.get('income', 0.0) for date_str, d in data['daily_sales'].items() 
        if date_str.startswith(last_month_str)
    )

    # Prepare Monthly Breakdown
    monthly_sales = {}
    for date_str, d in data['daily_sales'].items():
        month_year = date_str[:7] # YYYY-MM
        monthly_sales.setdefault(month_year, {'income': 0.0, 'orders': 0})
        monthly_sales[month_year]['income'] += d.get('income', 0.0)
        monthly_sales[month_year]['orders'] += d.get('orders', 0)
        
    # Sort months descending (Newest month first)
    sorted_monthly_sales = dict(sorted(monthly_sales.items(), reverse=True))

    return render_template('admin_dashboard.html', 
                           total_income=total_income,
                           today_income=today_income,
                           current_month_income=current_month_income,
                           last_month_income=last_month_income,
                           monthly_sales=sorted_monthly_sales,
                           transactions=transactions)


# ---------------- WEBHOOK AND TOKEN HANDLERS ----------------
_token_cache = {"access_token": None, "expires_at": 0}

def get_phonepe_token():
    now = int(time.time())
    if _token_cache.get('access_token') and _token_cache.get('expires_at', 0) - 30 > now:
        return _token_cache['access_token']

    # Use the appropriate client details based on environment configuration
    client_id = PHONEPE_CLIENT_ID
    client_secret = PHONEPE_CLIENT_SECRET
    client_version = PHONEPE_CLIENT_VERSION
    
    if not client_id or not client_secret:
        logger.error(f"PhonePe credentials not set for {ENVIRONMENT} environment.")
        return None

    payload = {
        'client_id': client_id,
        'client_version': client_version,
        'client_secret': client_secret,
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
    
    # 🛑 FIX: Get print mode from incoming data, defaulting to 'Color'
    print_mode = data.get('printMode', 'Color')
    
    # Store ALL NECESSARY data directly to the database as PENDING transaction
    try:
        sales_data = load_sales_data()
        pending_tx = {
            'id': merchant_order_id,
            'date': time.strftime('%Y-%m-%d'),
            'cost': data.get('totalCost'),
            'file_url': data.get('file_url'), # Saved directly to DB
            'copies': data.get('copies', 1), # Saved directly to DB
            'print_mode': print_mode,        # <<< Saved directly to DB
            'status': 'PENDING',
            'created_at': datetime.utcnow().isoformat(),
            'printed_at': None
        }
        sales_data.setdefault('transactions', []).append(pending_tx)
        save_sales_data(sales_data)
        logger.info("Created PENDING transaction %s with file URL and mode: %s.", merchant_order_id, print_mode)
    except Exception as e:
        logger.error("Failed to save PENDING transaction: %s", e)
        return jsonify({'error': 'Internal storage error before payment'}), 500


    token = get_phonepe_token()
    if not token:
        return jsonify({'error': 'Failed to get PhonePe token'}), 500

    amount_paise = int(round(float(data.get('totalCost')) * 100))

    payload = {
        "merchantOrderId": merchant_order_id,
        "amount": amount_paise,
        "expireAfter": 1200,
        "metaInfo": {
            # Added print_mode to UDF for debugging/tracking
            "udf1": "Mode: " + print_mode,
            "udf2": "PrintJob Copy Count",
            "udf3": "PrintJob Page Count",
            "udf4": "QuickMoonPrint",
            "udf5": "Additional Payment Info",
        },
        "paymentFlow": {
            "type": "PG_CHECKOUT",
            "message": "Payment for QuickMoonPrint order",
            "merchantUrls": {
                "redirectUrl": "https://quickmoonprint.in/payment_redirect" 
            },
            "paymentModeConfig": {
                "enabledPaymentModes": [
                    {"type": "UPI_INTENT"},
                    {"type": "UPI_COLLECT"},
                    {"type": "UPI_QR"},
                    {"type": "NET_BANKING"},
                    {"type": "CARD", "cardTypes": ["DEBIT_CARD", "CREDIT_CARD"]}
                ]
            }
        }
    }

    headers = {
        "Authorization": f"O-Bearer {token}", 
        "Content-Type": "application/json"
    }

    try:
        resp = requests.post(PHONEPE_PAY_URL, headers=headers, json=payload, timeout=30)
        logger.info("PhonePe pay request sent. Status: %s. Response Body: %s", resp.status_code, resp.text)
        resp_json = resp.json()
    except Exception as e:
        logger.exception("PhonePe request failed: %s", e)
        return jsonify({'error': 'Gateway communication error', 'detail': str(e)}), 500

    redirect_url = resp_json.get("redirectUrl") or resp_json.get('data', {}).get('redirectUrl')
    if not redirect_url:
        return jsonify({'error': 'No redirect URL in response', 'detail': resp_json}), 400

    return jsonify({'success': True, 'redirectUrl': redirect_url, 'merchantOrderId': merchant_order_id})

# ---------------- Payment redirect (User lands here via GET) ----------------
@app.route('/payment_redirect', methods=['GET'])
def payment_redirect():
    """Handles the final GET redirect from PhonePe after payment."""
    
    status = request.args.get('state') or 'COMPLETED' 
    
    if status == 'FAILED':
        message = "Transaction Failed or Print Error. Payment was unsuccessful. Please Try Again."
    else:
        # Assuming Webhook succeeded and the job is in the queue/printed.
        message = "Payment successful! Your print job is now in the queue." 

    return redirect(url_for('print_status', status='COMPLETED', message=message))


# ---------------- Payment callback (Webhook) ----------------
@app.route('/payment_callback', methods=['POST'])
def payment_callback():
    payload_full = request.get_json() or {}
    logger.info("Payment callback payload: %s", payload_full)

    # FIX: Get data from the 'payload' key
    data_payload = payload_full.get('payload', {})
    
    merchant_order_id = data_payload.get('merchantOrderId') or data_payload.get('orderId')
    status = data_payload.get('state') or data_payload.get('status') or data_payload.get('orderStatus') or data_payload.get('statusCode')

    if not merchant_order_id:
        logger.warning("Callback missing merchantOrderId/orderId in sub-payload.")
        return jsonify({"message": "Callback received"}), 200

    # Find data from DB PENDING placeholder
    data = load_sales_data()
    tx_to_update = next((tx for tx in data.get('transactions', []) if tx.get('id') == merchant_order_id), None)
    
    if tx_to_update:
        total_cost = tx_to_update['cost']
        file_url = tx_to_update['file_url']
        copies = tx_to_update['copies']
        print_mode = tx_to_update.get('print_mode', 'Color') # <<< Load print_mode
    else:
        total_cost = 0.0
        file_url = None
        copies = 1
        print_mode = 'Color' # Default fallback


    # Check if payment was a success
    if status and str(status).upper() in ('COMPLETED', 'SUCCESS', 'PAYMENT_SUCCESS', '200'):
        # FIX: Update the existing PENDING transaction to COMPLETED (includes sales record update)
        update_sales_record(total_cost, merchant_order_id, file_url=file_url, copies=copies, print_mode=print_mode) # <<< Pass print_mode
        logger.info("Order %s marked COMPLETED and saved. Print job mode: %s.", merchant_order_id, print_mode)
        return jsonify({"message": "Order recorded"}), 200 
    else:
        # Mark as FAILED if payment was rejected
        logger.warning("Payment not successful for %s status=%s", merchant_order_id, status)
        
        if tx_to_update:
             tx_to_update['status'] = 'FAILED'
             save_sales_data(data)
             
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
                'print_mode': tx.get('print_mode', 'Color'), # <<< Pass print_mode to agent
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
    # ... (Manual start print logic - usually not used with agent) ...
    # Removed for brevity, assuming you rely on printer_agent.py
    pass 

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