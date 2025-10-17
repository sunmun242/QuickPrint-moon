# app.py (updated for PhonePe V2 Standard Checkout)
import os
import time
import uuid
import json
import logging
import random
import threading
import subprocess
import tempfile
import requests
import hashlib 
import base64  

# SSL warning disable করার জন্য (local dev only; production এ verify=True রাখো)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from functools import wraps 
from flask import Flask, request, render_template, jsonify, redirect, url_for, session, send_from_directory, abort, Response, make_response
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from PyPDF2 import PdfReader

# --- logging ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Upload folder config ---
if os.environ.get('VERCEL'):
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/tmp/uploads')
else:
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Flask app ---
app = Flask(__name__, static_folder='static', template_folder='templates')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-for-local')

# ----------------------------------------------------------------------
# 🔑 PHONEPE V2 PAYMENT GATEWAY CONFIG (CLIENT CREDENTIALS)
# ----------------------------------------------------------------------
# NOTE: Replace these with your real V2 credentials (from PhonePe Business Dashboard)
PHONEPE_CLIENT_ID = os.environ.get('PHONEPE_CLIENT_ID', 'YOUR_CLIENT_ID')
PHONEPE_CLIENT_SECRET = os.environ.get('PHONEPE_CLIENT_SECRET', 'YOUR_CLIENT_SECRET')
PHONEPE_CLIENT_VERSION = os.environ.get('PHONEPE_CLIENT_VERSION', '1')  # as provided by PhonePe
# Use sandbox endpoints for local/testing, production endpoints for live
# ✅ LIVE mode endpoints for production
PHONEPE_OAUTH_URL = "https://api.phonepe.com/apis/hermes/v1/oauth/token"
PHONEPE_CREATE_PAY_URL = "https://api.phonepe.com/apis/hermes/checkout/v2/pay"
PHONEPE_STATUS_URL_TEMPLATE = "https://api.phonepe.com/apis/hermes/checkout/v2/order/{merchantOrderId}/status"
CALLBACK_URL = "https://quickmoonprint.in/payment_callback" 

# Webhook Basic Auth Credential (your existing)
WEBHOOK_USERNAME = os.environ.get('WEBHOOK_USERNAME', 'quickmoonprint')
WEBHOOK_PASSWORD = os.environ.get('WEBHOOK_PASSWORD', 'Sunmun2005')
# ----------------------------------------------------------------------

# --- Config & constants (Unchanged) ---
SALES_DATA_FILE = 'sales_data.json'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'Skymoon')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'Print@2025')
PRINTER_NAME = "EPSON L3250 Series"
SUMATRA_PATH = r"C:\Users\SUNMUN\AppData\Local\SumatraPDF\SumatraPDF.exe" 

# --- Sales data helpers (same as before) ---
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
    if os.environ.get('VERCEL'):
        logger.warning("Skipping save_sales_data on Vercel (ephemeral filesystem).")
        return
    try:
        with open(SALES_DATA_FILE, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        logger.exception("Failed to save sales data: %s", e)

def update_sales_record(cost, transaction_id): 
    data = load_sales_data()
    data['total_orders'] = data.get('total_orders', 0) + 1
    data['total_income'] = float(data.get('total_income', 0.0)) + float(cost or 0.0)
    today = time.strftime('%Y-%m-%d')
    if today not in data['daily_sales']:
        data['daily_sales'][today] = {"orders": 0, "income": 0.0}
    data['daily_sales'][today]['orders'] += 1
    data['daily_sales'][today]['income'] += float(cost or 0.0)
    
    if 'transactions' not in data:
        data['transactions'] = []
    data['transactions'].append({
        'date': today,
        'cost': cost,
        'id': transaction_id
    })
    
    save_sales_data(data)

# --- File helpers (Unchanged) ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def count_pages(filepath, extension):
    if extension == 'pdf':
        try:
            with open(filepath, 'rb') as f:
                reader = PdfReader(f)
                return len(reader.pages)
        except Exception as e:
            logger.exception("count_pages error: %s", e)
            return 1
    return 1

# --- Cleanup thread (Unchanged) ---
def cleanup_uploads():
    logger.info("Background cleanup thread running (local only).")
    CLEANUP_INTERVAL = 120  
    MAX_FILE_AGE = 600      
    while True:
        try:
            now = time.time()
            for fname in os.listdir(app.config['UPLOAD_FOLDER']):
                fpath = os.path.join(app.config['UPLOAD_FOLDER'], fname)
                if os.path.isfile(fpath):
                    if now - os.path.getmtime(fpath) > MAX_FILE_AGE:
                        try:
                            os.remove(fpath)
                            logger.info(f"🗑️ Deleted old file: {fname}")
                        except Exception as e:
                            logger.exception(f"Failed to remove {fname}: {e}")
        except Exception:
            logger.exception("Error during cleanup loop.")
        time.sleep(CLEANUP_INTERVAL)

def start_cleanup_thread():
    if not os.environ.get('VERCEL'):
        t = threading.Thread(target=cleanup_uploads, daemon=True)
        t.start()

# ----------------------------------------------------------------------
# 🔐 Webhook Basic Authentication Logic (Unchanged)
# ----------------------------------------------------------------------
def check_auth(username, password):
    return username == WEBHOOK_USERNAME and password == WEBHOOK_PASSWORD

def authenticate():
    return Response(
    'Could not verify your access level for that URL.\n'
    'Authentication required', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            logger.warning("Webhook Authentication Failed!")
            return authenticate()
        return f(*args, **kwargs)
    return decorated
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
# 🔑 PhonePe V2: token handling (client_credentials)
# ----------------------------------------------------------------------
_token_cache = {
    "access_token": None,
    "expires_at": 0  # epoch seconds
}

def get_phonepe_token():
    """
    Fetches and caches PhonePe V2 OAuth token (client_credentials).
    """
    # If token still valid, return it
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
        resp = requests.post(PHONEPE_OAUTH_URL, data=payload, headers=headers, verify=False)
        resp.raise_for_status()
        data = resp.json()
        token = data.get('access_token')
        expires_at = data.get('expires_at')  # epoch seconds - if provided
        if token:
            _token_cache['access_token'] = token
            _token_cache['expires_at'] = int(expires_at) if expires_at else now + 3000
            logger.info("Fetched PhonePe token, expires_at=%s", _token_cache['expires_at'])
            return token
        else:
            logger.error("PhonePe token response missing access_token: %s", data)
            return None
    except requests.RequestException as e:
        logger.exception("Failed to fetch PhonePe token: %s", e)
        return None
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
# 💳 PHONEPE PAYMENT GATEWAY ROUTES (V2)
# ----------------------------------------------------------------------

@app.route('/payment_initiate', methods=['POST'])
def payment_initiate():
    data = request.get_json()
    if not data or data.get('totalCost', 0) <= 0:
        return jsonify({'error': 'Invalid order data or cost'}), 400
    
    # create unique order id for merchant (merchantOrderId)
    merchant_order_id = str(uuid.uuid4())[:63]  # ensure fits 63 chars limit
    # store session data keyed by merchant_order_id
    session[merchant_order_id] = {
        'total_cost': data['totalCost'],
        'filename': data['filename'],
        'file_url': data['file_url'],
        'copies': data['copies'],
        'printType': data['printType'],
        'page_count': data['page_count']
    }
    
    amount_paise = int(round(data['totalCost'] * 100))
    
    # build create payment payload for V2
    payload = {
        "merchantOrderId": merchant_order_id,
        "amount": amount_paise,
        "redirectUrl": CALLBACK_URL,
        "callbackUrl": CALLBACK_URL,
        "paymentFlow": {
            "type": "PG_CHECKOUT"
        },
        # optional: metaInfo or expireAfter
        # "expireAfter": 600,
        # "metaInfo": {"udf1": "value1"}
    }
    
    token = get_phonepe_token()
    if not token:
        return jsonify({'success': False, 'error': 'Failed to get auth token for Payment Gateway.'}), 500
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"O-Bearer {token}"
    }
    
    try:
        response = requests.post(PHONEPE_CREATE_PAY_URL, headers=headers, json=payload, verify=False)
        response.raise_for_status()
        resp_data = response.json()
        logger.info("PhonePe Create Payment response: %s", resp_data)
        # V2 returns redirectUrl at top-level
        redirect_url = resp_data.get('redirectUrl') or resp_data.get('data', {}).get('redirectUrl')
        if redirect_url:
            return jsonify({'success': True, 'redirectUrl': redirect_url, 'merchantOrderId': merchant_order_id})
        else:
            logger.error("Create Payment failed: %s", resp_data)
            return jsonify({'success': False, 'error': resp_data.get('message', 'Payment initiation failed.')}), 500
    except requests.RequestException as e:
        logger.exception("Error initiating payment with PhonePe V2: %s", e)
        return jsonify({'success': False, 'error': 'Server communication error with Payment Gateway.'}), 500

@app.route('/payment_callback', methods=['POST'])
@requires_auth 
def payment_callback():
    # PhonePe will call this callback (V2) with order status details.
    # The exact body may include orderId/merchantOrderId and status info.
    response_data = request.get_json() or {}
    # try to find merchantOrderId in callback
    merchant_order_id = response_data.get('merchantOrderId') or response_data.get('orderId')
    # fallback: some implementations send nested structure
    if not merchant_order_id:
        # if callback doesn't have merchantOrderId, log and fail gracefully
        logger.warning("payment_callback missing merchantOrderId: %s", response_data)
        return jsonify({"message": "Callback received"}), 200
    
    # token validation of callback is already done via BasicAuth (requires_auth)
    # Check latest state (or parse from callback if present)
    order_state = response_data.get('state') or response_data.get('status')
    if not order_state:
        # if callback doesn't contain explicit state, fall back to fetching via status API
        try:
            # call order status API
            token = get_phonepe_token()
            if not token:
                logger.error("No token to validate callback order status")
                return jsonify({"message": "Token error"}), 500
            status_url = PHONEPE_STATUS_URL_TEMPLATE.format(merchantOrderId=merchant_order_id)
            headers = {"Content-Type": "application/json", "Authorization": f"O-Bearer {token}"}
            resp = requests.get(status_url, headers=headers, verify=False)
            resp.raise_for_status()
            status_json = resp.json()
            order_state = status_json.get('state') or status_json.get('status')
            callback_decoded = status_json
        except Exception as e:
            logger.exception("Failed to fetch order status during callback handling: %s", e)
            return jsonify({"message": "Status fetch error"}), 500
    else:
        callback_decoded = response_data
    
    session_data = session.get(merchant_order_id)
    if order_state == 'COMPLETED' or order_state == 'PAYMENT_SUCCESS' or order_state == 'SUCCESS':
        # update sales record if we have session data
        if session_data:
            cost = session_data['total_cost']
            update_sales_record(cost, merchant_order_id)
            # trigger print job as before (redirect to start_print)
            print_job_data = {
                'file_url': session_data['file_url'],
                'copies': session_data['copies'],
                'totalCost': cost,
                'transaction_id': merchant_order_id
            }
            return redirect(url_for('start_print', **print_job_data))
        else:
            logger.warning("Order completed but session data not found for %s", merchant_order_id)
            return jsonify({"message": "Order completed but session data lost"}), 200
    else:
        logger.warning("Payment not successful in callback for %s. state=%s", merchant_order_id, order_state)
        return jsonify({"message": "Payment not successful"}), 200

# ----------------------------------------------------------------------
# 🔍 PhonePe Status Check রুট (V2)
# ----------------------------------------------------------------------
@app.route('/check_payment_status', methods=['POST'])
def check_payment_status():
    data = request.get_json()
    transaction_id = data.get('transaction_id')  # merchantOrderId

    if not transaction_id:
        return jsonify({'status': 'FAILED', 'message': 'Transaction ID missing.'}), 400
    
    token = get_phonepe_token()
    if not token:
        return jsonify({'status': 'FAILED', 'message': 'Auth token error.'}), 500
    
    status_url = PHONEPE_STATUS_URL_TEMPLATE.format(merchantOrderId=transaction_id)
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"O-Bearer {token}",
        # X-MERCHANT-ID may be required for partner integrations. Add if needed:
        # "X-MERCHANT-ID": "<your_merchant_id>"
    }
    try:
        response = requests.get(status_url, headers=headers, verify=False)
        response.raise_for_status()
        status_data = response.json()
        logger.info("PhonePe Status response: %s", status_data)
        state = status_data.get('state') or status_data.get('status')
        if state in ('COMPLETED', 'SUCCESS', 'PAYMENT_SUCCESS'):
            session_data = session.get(transaction_id)
            if session_data:
                print_job_data = {
                    'file_url': session_data['file_url'],
                    'copies': session_data['copies'],
                    'totalCost': session_data['total_cost'],
                    'transaction_id': transaction_id
                }
                return jsonify({'status': 'SUCCESS', 'redirectUrl': url_for('start_print', **print_job_data)}), 200
            return jsonify({'status': 'FAILED', 'message': 'Payment successful but order data lost. Contact support.'}), 500
        elif state == 'PENDING':
            return jsonify({'status': 'PENDING', 'message': 'Payment is still processing.'}), 200
        else:
            return jsonify({'status': 'FAILED', 'message': status_data.get('message', 'Payment failed or declined.')}), 200
    except requests.RequestException as e:
        logger.exception("Error checking payment status with PhonePe V2: %s", e)
        return jsonify({'status': 'FAILED', 'message': 'Server communication error with Payment Gateway.'}), 500

# ----------------------------------------------------------------------
# ⚙️ Other Routes (left unchanged)
# ----------------------------------------------------------------------
@app.route('/payment')
def payment_page():
    return render_template('payment.html')

@app.route('/')
def index():
    response = make_response(render_template('index.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'fileToPrint' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['fileToPrint']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        original_filename = secure_filename(file.filename)
        extension = original_filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4()}.{extension}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        try:
            file.save(filepath)
            page_count = count_pages(filepath, extension)
            
            response_data = {
                'success': True,
                'filename': original_filename,
                'page_count': page_count,
                'file_path': filepath,
                'file_url': url_for('uploaded_file', filename=unique_filename, _external=True) 
            }
            
            response = Response(
                response=json.dumps(response_data),
                status=200,
                mimetype='application/json'
            )
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            return response
            
        except Exception as e:
            logger.exception("Failed to save uploaded file: %s", e)
            return jsonify({'error': 'Failed to save file on server'}), 500
    else:
        return jsonify({'error': 'File type not allowed'}), 400

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    try:
        response = send_from_directory(app.config['UPLOAD_FOLDER'], filename)
        response.headers['Cache-Control'] = 'public, max-age=31536000'
        return response
    except FileNotFoundError:
        abort(404)

@app.route('/start_print', methods=['GET'])
def start_print():
    data = request.args.to_dict()
    file_url = data.get('file_url')
    copies = int(data.get('copies', 1))
    
    if os.environ.get('VERCEL'):
        message = f"Print job (TXN: {data.get('transaction_id', 'N/A')}) submitted successfully (Simulated). Physical printer not connected to this cloud server."
        return redirect(url_for('print_status', status='SUCCESS', message=message))
    
    try:
        if not file_url:
            return redirect(url_for('print_status', status='FAILED', message="No file URL received."))
        
        response = requests.get(file_url)
        if response.status_code != 200:
            return redirect(url_for('print_status', status='FAILED', message=f"File download failed. Status code: {response.status_code}"))
        
        ext = file_url.split('.')[-1].split('?')[0]
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=f".{ext}")
        temp_file.write(response.content)
        temp_file.close()
        temp_filepath = temp_file.name
        
        command = [
            SUMATRA_PATH,
            "-print-to", PRINTER_NAME,
            temp_filepath,
            "-silent"
        ]
        
        for _ in range(copies):
            subprocess.Popen(command)
            
        message = f"Printing started successfully on {PRINTER_NAME} for TXN ID: {data.get('transaction_id', 'N/A')}."
        return redirect(url_for('print_status', status='SUCCESS', message=message))
    
    except Exception as e:
        logger.exception("Final print error: %s", e)
        message = f"Printing Failed. Error: {str(e)}"
        return redirect(url_for('print_status', status='FAILED', message=message))

@app.route('/print_status')
def print_status():
    status = request.args.get('status', 'FAILED')
    message = request.args.get('message', 'Printing status is unknown.')
    return render_template('print_status.html', status=status, message=message)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/terms_and_conditions')
def terms():
    return render_template('terms_and_conditions.html')

@app.route('/refund_policy')
def refund():
    return render_template('refund_policy.html')

@app.route('/privacy_policy')
def privacy():
    return render_template('privacy_policy.html')

# --- Run ---
if __name__ == '__main__':
    start_cleanup_thread()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
