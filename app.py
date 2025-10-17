# app.py (PhonePe V3-ready)
# Updated to support PhonePe checksum-based checkout (preferred) with a
# fallback to token-based approach if checksum credentials are not provided.
# NOTES:
# - Add PHONEPE_SALT_KEY and PHONEPE_SALT_INDEX to your .env to use checksum flow.
# - Keep verify=False only for local/dev. In production set verify=True.

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
# PHONEPE CONFIG (from env)
# Prefer checksum-based V3 checkout using MERCHANT_ID + SALT
# Fallback uses client credentials if provided (legacy)
# ----------------------------------------------------------------------
PHONEPE_CLIENT_ID = os.environ.get('PHONEPE_CLIENT_ID')
PHONEPE_CLIENT_SECRET = os.environ.get('PHONEPE_CLIENT_SECRET')
PHONEPE_CLIENT_VERSION = os.environ.get('PHONEPE_CLIENT_VERSION', '1')

MERCHANT_ID = os.environ.get('MERCHANT_ID')
PHONEPE_SALT_KEY = os.environ.get('PHONEPE_SALT_KEY')
PHONEPE_SALT_INDEX = os.environ.get('PHONEPE_SALT_INDEX', '1')

# Endpoints (V3 checkout endpoints)
PHONEPE_CHECKOUT_INIT = os.environ.get('PHONEPE_CHECKOUT_INIT', 'https://api.phonepe.com/apis/hermes/pg/v3/checkout/initiate')
PHONEPE_STATUS_URL_TEMPLATE = os.environ.get('PHONEPE_STATUS_URL_TEMPLATE', 'https://api.phonepe.com/apis/hermes/checkout/v2/order/{merchantOrderId}/status')
PHONEPE_OAUTH_URL = os.environ.get('PHONEPE_OAUTH_URL', 'https://api.phonepe.com/apis/hermes/v2/oauth/token')

CALLBACK_URL = os.environ.get('CALLBACK_URL', 'https://quickmoonprint.in/payment_callback')

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
# Helper: fallback token flow (improved logging)
# ----------------------------------------------------------------------
_token_cache = {
    "access_token": None,
    "expires_at": 0
}


def get_phonepe_token():
    """Fallback token retrieval (used only if checksum credentials not provided)."""
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
        if resp.status_code != 200:
            logger.error("PhonePe token fetch failed: status=%s body=%s", resp.status_code, resp.text)
            return None
        data = resp.json()
        token = data.get('access_token')
        expires_at = data.get('expires_at')
        if token:
            _token_cache['access_token'] = token
            _token_cache['expires_at'] = int(expires_at) if expires_at else now + 3000
            logger.info("Fetched PhonePe token, expires_at=%s", _token_cache['expires_at'])
            return token
        logger.error("PhonePe token response missing access_token: %s", data)
        return None
    except requests.RequestException as e:
        logger.exception("Failed to fetch PhonePe token: %s", e)
        return None

# ----------------------------------------------------------------------
# Utility: compute PhonePe checksum for V3 /pg/v3/checkout/initiate
# ----------------------------------------------------------------------

def compute_phonepe_checksum(base64_request: str, path: str, salt_key: str, salt_index: str) -> str:
    """Return checksum header (sha256 hex + ### + salt_index)"""
    checksum_str = base64_request + path + salt_key
    digest = hashlib.sha256(checksum_str.encode()).hexdigest()
    return digest + "###" + str(salt_index)

# ----------------------------------------------------------------------
# 💳 PAYMENT ROUTES
# ----------------------------------------------------------------------

@app.route('/payment_initiate', methods=['POST'])
def payment_initiate():
    data = request.get_json()
    if not data or data.get('totalCost', 0) <= 0:
        return jsonify({'error': 'Invalid order data or cost'}), 400

    merchant_order_id = str(uuid.uuid4())[:63]
    session[merchant_order_id] = {
        'total_cost': data['totalCost'],
        'filename': data['filename'],
        'file_url': data['file_url'],
        'copies': data['copies'],
        'printType': data.get('printType'),
        'page_count': data.get('page_count')
    }

    amount_paise = int(round(float(data['totalCost']) * 100))

    # If merchantId + saltKey present, prefer checksum-based V3 flow
    if MERCHANT_ID and PHONEPE_SALT_KEY:
        try:
            payload = {
                "merchantId": MERCHANT_ID,
                "merchantTransactionId": merchant_order_id,
                "amount": amount_paise,
                "redirectUrl": CALLBACK_URL,
                "callbackUrl": CALLBACK_URL,
                "paymentInstrument": {"type": "PAY_PAGE"}
            }

            # base64 encode JSON request
            base_request = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
            path = '/pg/v3/checkout/initiate'
            checksum = compute_phonepe_checksum(base_request, path, PHONEPE_SALT_KEY, PHONEPE_SALT_INDEX)

            headers = {
                'Content-Type': 'application/json',
                'X-VERIFY': checksum,
                'X-MERCHANT-ID': MERCHANT_ID
            }

            # PhonePe expects body like { "request": "<base64>" }
            resp = requests.post(PHONEPE_CHECKOUT_INIT, headers=headers, json={"request": base_request}, verify=False)
            resp.raise_for_status()
            resp_json = resp.json()
            logger.info("PhonePe V3 checkout response: %s", resp_json)

            # Try to find redirect URL in common locations
            redirect_url = None
            # path: data -> instrumentResponse -> redirectInfo -> url
            try:
                redirect_url = resp_json.get('data', {}).get('instrumentResponse', {}).get('redirectInfo', {}).get('url')
            except Exception:
                redirect_url = None

            # fallback direct keys
            if not redirect_url:
                redirect_url = resp_json.get('data', {}).get('redirectUrl') or resp_json.get('redirectUrl')

            if redirect_url:
                return jsonify({'success': True, 'redirectUrl': redirect_url, 'merchantOrderId': merchant_order_id})
            else:
                logger.error('PhonePe response missing redirect url: %s', resp_json)
                return jsonify({'success': False, 'error': 'Payment initiation failed - missing redirect url.'}), 500

        except requests.RequestException as e:
            logger.exception('Error initiating PhonePe V3 checkout: %s', e)
            body = getattr(e, 'response', None).text if getattr(e, 'response', None) is not None else str(e)
            return jsonify({'success': False, 'error': 'Gateway communication error', 'detail': body}), 500

    # ---------------------------
    # Fallback: token-based flow (legacy) if client id/secret provided
    # ---------------------------
    if PHONEPE_CLIENT_ID and PHONEPE_CLIENT_SECRET:
        # legacy flow - try to fetch token then create payment using previous V2 endpoint
        token = get_phonepe_token()
        if not token:
            return jsonify({'success': False, 'error': 'Failed to get auth token for Payment Gateway.'}), 500

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"O-Bearer {token}"
        }
        payload = {
            "merchantOrderId": merchant_order_id,
            "amount": amount_paise,
            "redirectUrl": CALLBACK_URL,
            "callbackUrl": CALLBACK_URL,
            "paymentFlow": {"type": "PG_CHECKOUT"}
        }
        try:
            response = requests.post(os.environ.get('PHONEPE_CREATE_PAY_URL', 'https://api.phonepe.com/apis/hermes/v2/checkout/v2/pay'), headers=headers, json=payload, verify=False)
            response.raise_for_status()
            resp_data = response.json()
            logger.info("PhonePe Create Payment response (legacy): %s", resp_data)
            redirect_url = resp_data.get('redirectUrl') or resp_data.get('data', {}).get('redirectUrl')
            if redirect_url:
                return jsonify({'success': True, 'redirectUrl': redirect_url, 'merchantOrderId': merchant_order_id})
            else:
                logger.error("Create Payment failed (legacy): %s", resp_data)
                return jsonify({'success': False, 'error': resp_data.get('message', 'Payment initiation failed.')}), 500
        except requests.RequestException as e:
            logger.exception("Error initiating payment with PhonePe (legacy): %s", e)
            return jsonify({'success': False, 'error': 'Server communication error with Payment Gateway.'}), 500

    # If we reach here, we do not have credentials to start payment
    return jsonify({'success': False, 'error': 'Payment credentials not configured on server.'}), 500


@app.route('/payment_callback', methods=['POST'])
@requires_auth
def payment_callback():
    response_data = request.get_json() or {}
    merchant_order_id = response_data.get('merchantOrderId') or response_data.get('orderId')
    if not merchant_order_id:
        logger.warning("payment_callback missing merchantOrderId: %s", response_data)
        return jsonify({"message": "Callback received"}), 200

    order_state = response_data.get('state') or response_data.get('status')
    callback_decoded = response_data
    if not order_state:
        # try fetching status using token or just log
        try:
            token = get_phonepe_token() if PHONEPE_CLIENT_ID and PHONEPE_CLIENT_SECRET else None
            if token:
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

    session_data = session.get(merchant_order_id)
    if order_state in ('COMPLETED', 'PAYMENT_SUCCESS', 'SUCCESS'):
        if session_data:
            cost = session_data['total_cost']
            update_sales_record(cost, merchant_order_id)
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


@app.route('/check_payment_status', methods=['POST'])
def check_payment_status():
    data = request.get_json()
    transaction_id = data.get('transaction_id')

    if not transaction_id:
        return jsonify({'status': 'FAILED', 'message': 'Transaction ID missing.'}), 400

    # prefer status API via token if available
    token = get_phonepe_token() if (PHONEPE_CLIENT_ID and PHONEPE_CLIENT_SECRET) else None
    if not token:
        return jsonify({'status': 'FAILED', 'message': 'Auth token error or credentials not configured.'}), 500

    status_url = PHONEPE_STATUS_URL_TEMPLATE.format(merchantOrderId=transaction_id)
    headers = {"Content-Type": "application/json", "Authorization": f"O-Bearer {token}"}
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
        logger.exception("Error checking payment status with PhonePe: %s", e)
        return jsonify({'status': 'FAILED', 'message': 'Server communication error with Payment Gateway.'}), 500

# ----------------------------------------------------------------------
# ⚙️ Other Routes (left mostly unchanged)
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
