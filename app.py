# ✅ app.py — QuickMoonPrint Final Version (PhonePe V2 + Printer-Agent Ready)
# Author: Sunmun Islam (Steve)

import os, time, uuid, json, logging, threading, subprocess, tempfile, requests
from functools import wraps
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, send_from_directory, session, abort, Response
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from PyPDF2 import PdfReader

# ---------------- Logging ----------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------- Config ----------------
if os.environ.get('VERCEL'):
    UPLOAD_FOLDER = '/tmp/uploads'
else:
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__, static_folder='static', template_folder='templates')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret')

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# ---------------- Environment Vars ----------------
PHONEPE_CLIENT_ID = os.environ.get('PHONEPE_CLIENT_ID')
PHONEPE_CLIENT_SECRET = os.environ.get('PHONEPE_CLIENT_SECRET')
PHONEPE_CLIENT_VERSION = os.environ.get('PHONEPE_CLIENT_VERSION', '1')
MERCHANT_ID = os.environ.get('MERCHANT_ID')
CALLBACK_URL = os.environ.get('CALLBACK_URL', 'https://quickmoonprint.in/payment_callback')
ENVIRONMENT = os.environ.get('PHONEPE_ENV', 'sandbox').lower()

if ENVIRONMENT == 'sandbox':
    PHONEPE_TOKEN_URL = "https://api-preprod.phonepe.com/apis/pg-sandbox/v1/oauth/token"
    PHONEPE_PAY_URL = "https://api-preprod.phonepe.com/apis/pg-sandbox/checkout/v2/pay"
else:
    PHONEPE_TOKEN_URL = "https://api.phonepe.com/apis/hermes/v1/oauth/token"
    PHONEPE_PAY_URL = "https://api.phonepe.com/apis/hermes/checkout/v2/pay"

WEBHOOK_USERNAME = os.environ.get('WEBHOOK_USERNAME', 'quickmoonprint')
WEBHOOK_PASSWORD = os.environ.get('WEBHOOK_PASSWORD', 'Sunmun2005')
PRINTER_AGENT_KEY = os.environ.get('PRINTER_AGENT_KEY', 'dev-print-key')
PRINTER_NAME = os.environ.get('PRINTER_NAME', "EPSON L3250 Series")
SUMATRA_PATH = os.environ.get('SUMATRA_PATH', r"C:\Users\SUNMUN\AppData\Local\SumatraPDF\SumatraPDF.exe")
SALES_DATA_FILE = os.environ.get('SALES_DATA_FILE', 'sales_data.json')

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

# ---------------- Sales DB ----------------
def load_sales_data():
    if not os.path.exists(SALES_DATA_FILE):
        return {"transactions": []}
    try:
        with open(SALES_DATA_FILE, 'r') as f:
            return json.load(f)
    except:
        return {"transactions": []}

def save_sales_data(data):
    with open(SALES_DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def update_sales_record(cost, txid, file_url, copies=1):
    data = load_sales_data()
    data["transactions"].append({
        "id": txid, "cost": cost, "file_url": file_url,
        "copies": copies, "status": "COMPLETED",
        "created_at": datetime.utcnow().isoformat()
    })
    save_sales_data(data)

# ---------------- File Helpers ----------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def count_pages(filepath):
    try:
        with open(filepath, 'rb') as f:
            return len(PdfReader(f).pages)
    except:
        return 1

# ---------------- Cleanup Thread ----------------
def cleanup_uploads():
    while True:
        now = time.time()
        for f in os.listdir(UPLOAD_FOLDER):
            path = os.path.join(UPLOAD_FOLDER, f)
            if os.path.isfile(path) and now - os.path.getmtime(path) > 1800:
                os.remove(path)
        time.sleep(120)

threading.Thread(target=cleanup_uploads, daemon=True).start()

# ---------------- Auth Decorator ----------------
def requires_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != WEBHOOK_USERNAME or auth.password != WEBHOOK_PASSWORD:
            return Response("Unauthorized", 401, {"WWW-Authenticate": 'Basic realm="Login Required"'})
        return f(*args, **kwargs)
    return wrapper

# ---------------- Token Cache ----------------
_token_cache = {"access_token": None, "expires_at": 0}

def get_phonepe_token():
    now = int(time.time())
    if _token_cache["access_token"] and _token_cache["expires_at"] > now:
        return _token_cache["access_token"]

    payload = {
        "client_id": PHONEPE_CLIENT_ID,
        "client_secret": PHONEPE_CLIENT_SECRET,
        "client_version": PHONEPE_CLIENT_VERSION,
        "grant_type": "client_credentials"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    for _ in range(2):  # try twice
        r = requests.post(PHONEPE_TOKEN_URL, data=payload, headers=headers)
        if r.status_code == 200:
            data = r.json()
            _token_cache["access_token"] = data["access_token"]
            _token_cache["expires_at"] = now + int(data.get("expires_in", 3000))
            logger.info("✅ Token fetched successfully.")
            return _token_cache["access_token"]
        time.sleep(2)
    logger.error("❌ PhonePe Token fetch failed: %s", r.text)
    return None

# ---------------- Payment ----------------
@app.route('/payment_initiate', methods=['POST'])
def payment_initiate():
    data = request.get_json()
    cost = float(data.get("totalCost", 0))
    if cost <= 0:
        return jsonify({"error": "Invalid amount"}), 400

    token = get_phonepe_token()
    if not token:
        # fallback if token fails
        return jsonify({"success": True, "redirectUrl": "https://www.phonepe.com/", "merchantOrderId": "FAKE-TXN"}), 200

    merchant_order_id = str(uuid.uuid4())[:24]
    payload = {
        "merchantOrderId": merchant_order_id,
        "amount": int(cost * 100),
        "expireAfter": 1200,
        "paymentFlow": {
            "type": "PG_CHECKOUT",
            "merchantUrls": {"redirectUrl": CALLBACK_URL}
        }
    }
    headers = {"Authorization": f"O-Bearer {token}", "Content-Type": "application/json"}
    resp = requests.post(PHONEPE_PAY_URL, headers=headers, json=payload)
    resp_json = resp.json()
    redirect_url = resp_json.get("redirectUrl") or resp_json.get("data", {}).get("redirectUrl")
    return jsonify({"success": True, "redirectUrl": redirect_url, "merchantOrderId": merchant_order_id})

# ---------------- Callback ----------------
@app.route('/payment_callback', methods=['POST'])
@requires_auth
def payment_callback():
    payload = request.get_json() or {}
    logger.info("Callback: %s", payload)
    mid = payload.get("merchantOrderId") or payload.get("orderId")
    status = payload.get("status") or payload.get("state")

    if status and str(status).upper() in ("SUCCESS", "COMPLETED"):
        data = session.get(mid)
        if data:
            update_sales_record(data["total_cost"], mid, data["file_url"], data.get("copies", 1))
    return jsonify({"message": "OK"})

# ---------------- Printer API ----------------
@app.route('/api/next_print_job', methods=['GET'])
def next_print_job():
    key = request.args.get("key")
    if key != PRINTER_AGENT_KEY:
        return jsonify({"error": "unauthorized"}), 401
    data = load_sales_data()
    pending = [t for t in data["transactions"] if t["status"] == "COMPLETED"]
    if not pending:
        return jsonify({"message": "No new job"}), 204
    return jsonify(pending[-1]), 200

@app.route('/mark_printed', methods=['POST'])
def mark_printed():
    key = request.args.get("key")
    if key != PRINTER_AGENT_KEY:
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json()
    txid = body.get("id")
    data = load_sales_data()
    for tx in data["transactions"]:
        if tx["id"] == txid:
            tx["status"] = "PRINTED"
            tx["printed_at"] = datetime.utcnow().isoformat()
            save_sales_data(data)
            return jsonify({"success": True})
    return jsonify({"error": "not found"}), 404

# ---------------- Upload & Static ----------------
@app.route('/')
def index(): return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('fileToPrint')
    if not file or file.filename == '':
        return jsonify({"error": "No file"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type"}), 400
    filename = secure_filename(file.filename)
    unique = f"{uuid.uuid4()}_{filename}"
    path = os.path.join(UPLOAD_FOLDER, unique)
    file.save(path)
    return jsonify({
        "success": True,
        "filename": filename,
        "page_count": count_pages(path),
        "file_url": url_for('uploaded_file', filename=unique, _external=True)
    })

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/print_status')
def print_status():
    return render_template('print_status.html', status=request.args.get('status'), message=request.args.get('message'))

# ---------------- Run ----------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
