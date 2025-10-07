# app.py (updated for Vercel-ready usage)
import os
import time
import uuid
import json
import logging
import random
import threading

from flask import Flask, request, render_template, jsonify, redirect, url_for, session, send_from_directory, abort
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from PyPDF2 import PdfReader

# --- logging ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Upload folder config ---
# Prefer environment variable; fallback to /tmp/uploads on Vercel or local 'uploads'
if os.environ.get('VERCEL'):
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/tmp/uploads')
else:
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Flask app ---
app = Flask(__name__, static_folder='static', template_folder='templates')
# ProxyFix helps when behind proxies (Vercel)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_MB', 50)) * 1024 * 1024  # default 50 MB
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-for-local')

# --- Config & constants ---
SALES_DATA_FILE = 'sales_data.json'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

# Admin credentials: set these in Vercel env for production
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'Skymoon')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'Print@2025')  # replace with hashed / env var in prod

# --- Sales data helpers ---
def load_sales_data():
    try:
        if not os.path.exists(SALES_DATA_FILE):
            return {"total_orders": 0, "total_income": 0.0, "daily_sales": {}}
        with open(SALES_DATA_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.exception("Error loading sales data: %s", e)
        return {"total_orders": 0, "total_income": 0.0, "daily_sales": {}}

def save_sales_data(data):
    # Vercel filesystem is ephemeral / often read-only; skip saving on Vercel
    if os.environ.get('VERCEL'):
        logger.warning("Skipping save_sales_data on Vercel (ephemeral filesystem).")
        return
    try:
        with open(SALES_DATA_FILE, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        logger.exception("Failed to save sales data: %s", e)

def update_sales_record(cost):
    data = load_sales_data()
    data['total_orders'] = data.get('total_orders', 0) + 1
    data['total_income'] = float(data.get('total_income', 0.0)) + float(cost or 0.0)
    today = time.strftime('%Y-%m-%d')
    if today not in data['daily_sales']:
        data['daily_sales'][today] = {"orders": 0, "income": 0.0}
    data['daily_sales'][today]['orders'] += 1
    data['daily_sales'][today]['income'] += float(cost or 0.0)
    save_sales_data(data)

# --- File helpers ---
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

# Cleanup thread (disabled on Vercel)
def cleanup_uploads():
    logger.info("Background cleanup thread running (only on local).")
    CLEANUP_INTERVAL = int(os.environ.get('CLEANUP_INTERVAL_SEC', 300))
    MAX_FILE_AGE = int(os.environ.get('MAX_FILE_AGE_SEC', 600))
    while True:
        try:
            now = time.time()
            for fname in os.listdir(app.config['UPLOAD_FOLDER']):
                fpath = os.path.join(app.config['UPLOAD_FOLDER'], fname)
                if os.path.isfile(fpath):
                    if now - os.path.getmtime(fpath) > MAX_FILE_AGE:
                        try:
                            os.remove(fpath)
                            logger.info("Removed old upload: %s", fpath)
                        except Exception:
                            logger.exception("Failed to remove: %s", fpath)
        except Exception:
            logger.exception("Error during cleanup loop.")
        time.sleep(CLEANUP_INTERVAL)

def start_cleanup_thread():
    if not os.environ.get('VERCEL'):
        t = threading.Thread(target=cleanup_uploads, daemon=True)
        t.start()

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

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
            # Note: exposing server absolute path is not recommended in prod
            return jsonify({
                'success': True,
                'filename': original_filename,
                'page_count': page_count,
                'file_path': filepath,
                'file_url': url_for('uploaded_file', filename=unique_filename)
            })
        except Exception as e:
            logger.exception("Failed to save uploaded file: %s", e)
            return jsonify({'error': 'Failed to save file on server'}), 500
    else:
        return jsonify({'error': 'File type not allowed'}), 400

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        abort(404)

@app.route('/payment')
def payment():
    return render_template('payment.html')

@app.route('/check_payment_status', methods=['POST'])
def check_payment_status():
    data = request.get_json() or {}
    cost = float(data.get('totalCost', 0.0) or 0.0)
    # Simulate payment verification
    is_paid = random.random() < 0.8
    if is_paid:
        update_sales_record(cost)
        return jsonify({'status': 'SUCCESS', 'transaction_id': 'TXN123456', 'printer_id': "Printer 2"})
    else:
        return jsonify({'status': 'PENDING', 'error': 'Payment verification failed by Payment Gateway.'})

@app.route('/start_print', methods=['GET', 'POST'])
def start_print():
    # On Vercel we can only simulate; physical printing must be on local machine / LAN printer
    if os.environ.get('VERCEL'):
        message = "Print job submitted successfully (Simulated). Physical printer not connected to this cloud server."
        if request.method == 'GET':
            return render_template('print_status.html', message=message, status="Success")
        return jsonify({'status': 'SUCCESS', 'message': "Print command (Simulated) sent successfully."})

    # local printing logic (only runs when not on Vercel)
    try:
        data = request.get_json() or {}
        file_path = data.get('file_path')
        copies = int(data.get('copies', 1))
        # Example: call local printing utility here (platform dependent)
        # subprocess.Popen([...])
        return jsonify({'status': 'SUCCESS', 'message': f"Print command queued for local printer (copies={copies})."})
    except Exception as e:
        logger.exception("Local print error: %s", e)
        return jsonify({'status': 'FAILED', 'message': f"Printing Failed. Error: {e}"}), 500

# --- Admin routes ---
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        return render_template('admin_login.html', error='Invalid credentials.')
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    sales_data = load_sales_data()
    daily_report_list = []
    for date in sorted(sales_data.get('daily_sales', {}).keys(), reverse=True)[:30]:
        rec = sales_data['daily_sales'][date]
        daily_report_list.append({
            'date': date,
            'orders': rec.get('orders', 0),
            'income': f"₹{rec.get('income', 0.0):.2f}"
        })
    return render_template('admin_dashboard.html',
                           total_orders=sales_data.get('total_orders', 0),
                           total_income=f"₹{sales_data.get('total_income', 0.0):.2f}",
                           daily_reports=daily_report_list)

@app.route('/admin/logout')
def admin_logout():
    session.pop('logged_in', None)
    return redirect(url_for('admin_login'))

# --- Run ---
if __name__ == '__main__':
    start_cleanup_thread()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)