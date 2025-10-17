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

# .env ফাইল লোড করার জন্য
from dotenv import load_dotenv

# .env ফাইল লোড করুন
load_dotenv() 


# SSL warning disable করার জন্য
import requests.packages.urllib3 
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


# functools যোগ করা হয়েছে requires_auth ডেকোরেটরের জন্য
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
# 🔑 PHONEPE PAYMENT GATEWAY CONFIG (API Keys) - V2 FIX
# ----------------------------------------------------------------------
# 🚨 .env থেকে মান লোড করা হয়েছে
PHONEPE_MERCHANT_ID = os.environ.get('CLIENT_ID')
PHONEPE_SALT_KEY = os.environ.get('CLIENT_SECRET')
PHONEPE_SALT_INDEX = os.environ.get('CLIENT_VERSION')
CALLBACK_URL = os.environ.get('CALLBACK_URL')

# 🚨 V2 FIX: Production/Live URL ব্যবহার করা হলো এবং V2 Checkout Path সেট করা হলো
PHONEPE_BASE_URL = "https://api.phonepe.com/apis/pg/checkout/v2" 
PHONEPE_PAY_URL = f"{PHONEPE_BASE_URL}/pay"

# 🚨 .env থেকে লোড করা হয়েছে
WEBHOOK_USER = os.environ.get('WEBHOOK_USER')
WEBHOOK_PASSWORD = os.environ.get('WEBHOOK_PASSWORD')
# ----------------------------------------------------------------------


# --- Config & constants (Unchanged) ---
SALES_DATA_FILE = 'sales_data.json'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'Skymoon')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'Print@2025')
PRINTER_NAME = "EPSON L3250 Series"
# 🚨 পরিবর্তন: Sumatra Path রিয়া দত্তের ল্যাপটপ অনুযায়ী ঠিক করা হয়েছে
SUMATRA_PATH = r"C:\Users\Riya Dutta\AppData\Local\SumatraPDF\SumatraPDF.exe" 


# --- Sales data helpers (Unchanged) ---
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
# 🔐 Webhook Basic Authentication Logic
# ----------------------------------------------------------------------
def check_auth(username, password):
    """PhonePe Webhook-এর Username / password সঠিক কি না, তা পরীক্ষা করে।"""
    return username == WEBHOOK_USER and password == WEBHOOK_PASSWORD


def authenticate():
    """401 Unauthorised response পাঠায়"""
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
# 💳 PHONEPE PAYMENT GATEWAY ROUTES 
# ----------------------------------------------------------------------


@app.route('/payment_initiate', methods=['POST'])
def payment_initiate():
    # 🚨 DEBUG PRINT 1: ফ্রন্টএন্ড থেকে আসা ডেটা চেক
    data = request.get_json()
    logger.info("INCOMING REQUEST DATA: %s", data) 
    
    if not data or data.get('totalCost', 0) <= 0:
        logger.error("Error: Invalid or missing data received from frontend.")
        return jsonify({'error': 'Invalid order data or cost'}), 400
    
    session_id = str(uuid.uuid4())
    session[session_id] = {
        'total_cost': data['totalCost'],
        'filename': data['filename'],
        'file_url': data['file_url'],
        'copies': data['copies'],
        'printType': data['printType'],
        'page_count': data['page_count']
    }
    
    # ⚠️ সতর্কতা: টাকা পয়সাতে কনভার্ট করার সময় ফ্লোটিং পয়েন্ট ত্রুটি এড়াতে round করা হয়েছে।
    amount_paise = int(round(data['totalCost'] * 100)) 
    
    payload = {
        "merchantId": PHONEPE_MERCHANT_ID,
        "merchantTransactionId": session_id, 
        "merchantUserId": PHONEPE_MERCHANT_ID,
        "amount": amount_paise,
        "redirectUrl": CALLBACK_URL,
        "redirectMode": "REDIRECT", 
        "callbackUrl": CALLBACK_URL, 
        "paymentInstrument": {
            "type": "PAY_PAGE"
        }
    }


    # 🚨 DEBUG PRINT 2: PhonePe কে পাঠানোর জন্য চূড়ান্ত Payload চেক
    logger.info("FINAL PHONEPE PAYLOAD: %s", payload) 


    base64_payload = base64.b64encode(json.dumps(payload).encode()).decode()
    
    # 🚨 V2 FIX: Checksum তৈরির সময় V2 API Path "/pg/v2/pay" ব্যবহার করা হয়েছে
    checksum_str = base64_payload + "/pg/checkout/v2/pay" + PHONEPE_SALT_KEY 
    sha256_hash = hashlib.sha256(checksum_str.encode()).hexdigest()
    x_verify = f"{sha256_hash}###{PHONEPE_SALT_INDEX}"
    
    logger.info("Checksum String for Pay API: %s", checksum_str)


    headers = {
        "Content-Type": "application/json",
        # 🚨 পরিবর্তন: 'accept' header যোগ করা হয়েছে
        "X-VERIFY": x_verify,
        "accept": "application/json"
    }
    
    try:
        # 🚨 V2 FIX: V2 Pay URL এ কল করা হচ্ছে
        response = requests.post(
            PHONEPE_PAY_URL, 
            headers=headers, 
            json={"request": base64_payload},
            verify=False 
        )
        
        # 🚨 DEBUG FİX: raise_for_status() এর বদলে সরাসরি response চেক করা হচ্ছে
        phonepe_response_data = response.json()
        
        # 🚨 DEBUG PRINT 3: PhonePe-এর Response টি প্রিন্ট করা হবে
        logger.info("PhonePe RAW Response: %s", response.text) 
        
        if phonepe_response_data.get('success') and phonepe_response_data['code'] == 'PAYMENT_INITIATED':
            redirect_url = phonepe_response_data['data']['instrumentUrl']
            return jsonify({'success': True, 'redirectUrl': redirect_url})
        else:
            # এখানে PhonePe এর আসল ত্রুটি কোড এবং বার্তা প্রিন্ট হবে
            logger.error("PhonePe Initiation Failed (API Response): %s", phonepe_response_data)
            return jsonify({'success': False, 'error': phonepe_response_data.get('message', 'Payment initiation failed.')}), 500


    except requests.exceptions.RequestException as e:
        logger.exception("Error initiating payment with PhonePe: %s", e)
        return jsonify({'success': False, 'error': 'Server communication error with Payment Gateway.'}), 500


@app.route('/payment_callback', methods=['POST'])
@requires_auth 
def payment_callback():
    response_data = request.get_json() or {}
    base64_response = response_data.get('response')
    x_verify_header = request.headers.get('X-VERIFY')
    
    if not base64_response or not x_verify_header:
        return redirect(url_for('print_status', status='FAILED', message="Payment callback data missing or invalid format."))


    checksum_str = base64_response + PHONEPE_SALT_KEY 
    sha256_hash = hashlib.sha256(checksum_str.encode()).hexdigest()
    
    try:
        incoming_hash, incoming_index = x_verify_header.split('###')
    except ValueError:
        logger.error("PhonePe X-VERIFY header format error.")
        return redirect(url_for('print_status', status='FAILED', message="Security Check Failed. Invalid header format."))


    if incoming_hash != sha256_hash or incoming_index != PHONEPE_SALT_INDEX:
        logger.error("PhonePe Checksum Mismatch. Possible Tampering.")
        return redirect(url_for('print_status', status='FAILED', message="Security Check Failed. Please retry payment."))


    decoded_payload = json.loads(base64.b64decode(base64_response).decode())
    
    transaction_id = decoded_payload.get('merchantTransactionId')
    payment_status = decoded_payload.get('code') 
    session_data = session.get(transaction_id)
    
    if payment_status == 'PAYMENT_SUCCESS' and session_data:
        cost = session_data['total_cost']
        update_sales_record(cost, transaction_id) 
        
        print_job_data = {
            'file_url': session_data['file_url'],
            'copies': session_data['copies'],
            'totalCost': cost,
            'transaction_id': transaction_id
        }
        
        return redirect(url_for('start_print', **print_job_data))


    else:
        logger.warning(f"Payment Failed or Pending: {payment_status} for TXN ID: {transaction_id}")
        return redirect(url_for('print_status', status='FAILED', message=f"Payment {payment_status.lower().replace('_', ' ')}."))


# ----------------------------------------------------------------------
# 🔍 PhonePe Status Check রুট 
# ----------------------------------------------------------------------
@app.route('/check_payment_status', methods=['POST'])
def check_payment_status():
    data = request.get_json()
    transaction_id = data.get('transaction_id')

    if not transaction_id:
        return jsonify({'status': 'FAILED', 'message': 'Transaction ID missing.'}), 400
    
    # PhonePe স্ট্যাটাস চেক API এর URL তৈরি করা
    status_url = f"{PHONEPE_BASE_URL}/status/{PHONEPE_MERCHANT_ID}/{transaction_id}"
    
    # Checksum তৈরি করা
    checksum_str = f"/pg/v2/status/{PHONEPE_MERCHANT_ID}/{transaction_id}" + PHONEPE_SALT_KEY
    sha256_hash = hashlib.sha256(checksum_str.encode()).hexdigest()
    x_verify = f"{sha256_hash}###{PHONEPE_SALT_INDEX}"
    
    logger.info("Checksum String for Status API: %s", checksum_str)


    headers = {
        "Content-Type": "application/json",
        "X-VERIFY": x_verify,
        "X-MERCHANT-ID": PHONEPE_MERCHANT_ID 
    }
    
    try:
        response = requests.get(status_url, headers=headers, verify=False)
        response.raise_for_status() 
        
        status_data = response.json()
        
        logger.info("PhonePe Response (Status): %s", status_data)
        
        if status_data.get('success') and status_data['code'] == 'PAYMENT_SUCCESS':
            # পেমেন্ট সফল
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


        elif status_data['code'] == 'PAYMENT_PENDING':
             return jsonify({'status': 'PENDING', 'message': 'Payment is still processing.'}), 200
             
        else:
            return jsonify({'status': 'FAILED', 'message': status_data.get('message', 'Payment failed or declined.')}), 200


    except requests.exceptions.RequestException as e:
        logger.exception("Error checking payment status with PhonePe: %s", e)
        return jsonify({'status': 'FAILED', 'message': 'Server communication error with Payment Gateway.'}), 500


# ----------------------------------------------------------------------
# ⚙️ Other Routes 
# ----------------------------------------------------------------------


@app.route('/payment')
def payment_page():
    """index.html থেকে আসা রিকোয়েস্ট হ্যান্ডেল করে payment.html টেমপ্লেট লোড করবে।"""
    return render_template('payment.html')


# (বাকি সব রুট অপরিবর্তিত)
@app.route('/')
def index():
    response = make_response(render_template('index.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
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
        
        # প্রিন্ট সার্ভার ট্রিগার করা হচ্ছে
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


# --- Policy routes (Unchanged) ---
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
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)),debug=True)
