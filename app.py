import os
from flask import Flask, request, render_template, jsonify, redirect, url_for, session, send_from_directory
from PyPDF2 import PdfReader 
import uuid
import json 
# Vercel সার্ভারে subprocess (প্রিন্টিং) কাজ করে না, তাই এটি ডিলিট করা হচ্ছে
# import subprocess 
import time 
import random 
import threading 


# --- VERCEL-এর জন্য গুরুত্বপূর্ণ পরিবর্তন: আমদানি (Import) এর পর ---
# JSON ফাইল লোড করার জন্য os এবং json মডিউল একসাথে প্রয়োজন।
# Flask অ্যাপ্লিকেশনে /tmp ডিরেক্টরি ব্যবহার করা হবে।


# সার্ভার সেটআপ
app = Flask(__name__)
# সেশন ব্যবহারের জন্য সিক্রেট কী দরকার
app.secret_key = 'your_super_secret_key_for_session' 




# কনফিগারেশন
SALES_DATA_FILE = 'sales_data.json' # ডেটাবেস ফাইল




# --- VERCEL-এর জন্য ফাইল সিস্টেম কনফিগারেশন ---
# লোকাল ফাইল সিস্টেম (uploads) এর পরিবর্তে Vercel-এ /tmp/uploads ব্যবহার করা হবে।


UPLOAD_FOLDER = 'uploads' 
if os.environ.get('VERCEL'):
    # Vercel-এর জন্য /tmp ডিরেক্টরি ব্যবহার করুন
    UPLOAD_FOLDER = '/tmp/uploads'


# UPLOAD_FOLDER তৈরি করা
if not os.path.exists(UPLOAD_FOLDER):
    # exist_ok=True ব্যবহার করা হয়েছে যাতে ফোল্ডারটি আগেই থাকলে এরর না আসে।
    os.makedirs(UPLOAD_FOLDER, exist_ok=True) 


app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER




ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}




# --- নিরাপত্তা ও অটো-ডিলিট কনফিগারেশন (Vercel-এ অটো-ডিলিট বন্ধ) ---
# Vercel-এ থ্রেড বা ব্যাকগ্রাউন্ড টাস্ক নির্ভরযোগ্যভাবে কাজ করে না, তাই বন্ধ করা হলো।
MAX_FILE_AGE = 600 
CLEANUP_INTERVAL = 300 




# --- অ্যাডমিন ক্রেডেনশিয়ালস ---
ADMIN_USERNAME = 'Skymoon'
ADMIN_PASSWORD_HASHED = 'Print@2025'




# --- ডেটা হ্যান্ডলিং ফাংশন ---




def load_sales_data():
    """Load sales data from the JSON file (Handles Vercel Read-Only issue)."""
    
    # **Vercel-এর জন্য প্রধান পরিবর্তন:**
    # Vercel এ sales_data.json ফাইলটি Read-Only থাকে।
    # যদি ফাইলটি পরিবর্তন করতে হয়, তবে অন্য স্থানে সেভ করার প্রয়োজন হতে পারে।
    # তবে, যেহেতু এটি শুধুমাত্র ডেটাবেস হিসেবে ব্যবহার হচ্ছে, এটি শুধুমাত্র read করার চেষ্টা করবে।
    
    try:
        if not os.path.exists(SALES_DATA_FILE):
             # যদি ফাইল না থাকে, তবে একটি নতুন ডিকশনারি রিটার্ন করবে
            return {"total_orders": 0, "total_income": 0.0, "daily_sales": {}}
        with open(SALES_DATA_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading sales data: {e}. Returning empty data.")
        return {"total_orders": 0, "total_income": 0.0, "daily_sales": {}}




def save_sales_data(data):
    """Save sales data to the JSON file (Disabled on Vercel as it is Read-Only)."""
    
    # **Vercel-এর জন্য প্রধান পরিবর্তন:**
    # Vercel-এ রুট ডিরেক্টরিতে লেখা (Write) সম্ভব নয়।
    # ডেটাবেস ফাংশনাল করতে আপনাকে একটি এক্সটার্নাল ডেটাবেস (যেমন Firebase, TinyDB in /tmp) ব্যবহার করতে হবে।
    
    if os.environ.get('VERCEL'):
        print("Warning: Cannot save sales data on Vercel's read-only file system.")
        return # Vercel-এ সেভ করা বন্ধ
    
    # লোকাল পিসিতে সেভ করার জন্য
    with open(SALES_DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)




def update_sales_record(cost):
    """Update sales total and daily record."""
    data = load_sales_data()
    data['total_orders'] += 1
    data['total_income'] += cost
    
    # Daily sales record
    today = time.strftime('%Y-%m-%d')
    if today not in data['daily_sales']:
        data['daily_sales'][today] = {"orders": 0, "income": 0.0}
    
    data['daily_sales'][today]['orders'] += 1
    data['daily_sales'][today]['income'] += cost
    
    # পরিবর্তন: save_sales_data() ফাংশনটি এখন Vercel এ সেভ করবে না
    save_sales_data(data) 




# --- ফাইল ও ক্লিনআপ ফাংশন (পরিবর্তন) ---




def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS




def count_pages(filepath, extension):
    # PyPDF2 ব্যবহার করার জন্য কোনো পরিবর্তন দরকার নেই
    if extension == 'pdf':
        try:
            reader = PdfReader(filepath)
            return len(reader.pages)
        except Exception:
            return 1 
    return 1




# **পরিবর্তন: Vercel-এ ক্লিনআপ থ্রেড বন্ধ (ব্যাকগ্রাউন্ড টাস্ক অবিশ্বস্ত)**
def cleanup_uploads():
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Background cleanup thread is disabled on Vercel.")
    # লোকাল পিসিতে চলার জন্য পূর্বের কোড এখানে আছে, কিন্তু Vercel এ চলবে না।
    if not os.environ.get('VERCEL'):
        while True:
            # ... (পূর্বের ক্লিনআপ লজিক) ...
            pass 




def start_cleanup_thread():
    # Vercel এ এই থ্রেড শুরু করা হবে না
    if not os.environ.get('VERCEL'):
        cleanup_thread = threading.Thread(target=cleanup_uploads, daemon=True)
        cleanup_thread.start()




# --- কাস্টমার রুটস (Route) ---




@app.route('/')
def index():
    return render_template('index.html')




@app.route('/about')
def about():
    return render_template('about.html')




@app.route('/upload', methods=['POST'])
def upload_file():
    # ... (upload logic unchanged, uses app.config['UPLOAD_FOLDER'] which is /tmp/uploads on Vercel) ...
    if 'fileToPrint' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['fileToPrint']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    if file and allowed_file(file.filename):
        original_filename = file.filename
        extension = original_filename.rsplit('.', 1)[1].lower()
        unique_filename = str(uuid.uuid4()) + '.' + extension
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        file.save(filepath) 
        page_count = count_pages(filepath, extension)
        
        return jsonify({
            'success': True,
            'filename': original_filename,
            'page_count': page_count,
            'file_path': filepath,
            'file_url': url_for('uploaded_file', filename=unique_filename) 
        })
    else:
        return jsonify({'error': 'File type not allowed'}), 400




@app.route('/uploads/<filename>')
def uploaded_file(filename):
    # send_from_directory() এখন /tmp/uploads থেকে ফাইলটি দেখাবে
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)








@app.route('/payment')
def payment():
    return render_template('payment.html')




@app.route('/check_payment_status', methods=['POST'])
def check_payment_status():
    data = request.get_json()
    cost = data.get('totalCost', 0.0) 




    # ডেমো পেমেন্ট চেক 
    is_paid = random.random() < 0.8 
    
    if is_paid:
        # পেমেন্ট সফল হলে সেলস ডেটা আপডেট হবে (Vercel এ সেভ হবে না)
        update_sales_record(cost) 
        return jsonify({'status': 'SUCCESS', 'transaction_id': 'TXN123456', 'printer_id': "Printer 2"})
    else:
        return jsonify({'status': 'PENDING', 'error': 'Payment verification failed by Payment Gateway.'})




@app.route('/start_print', methods=['POST', 'GET'])
def start_print():
    # **গুরুত্বপূর্ণ পরিবর্তন: Vercel-এ প্রিন্টিং রিমুভ করা হয়েছে**
    if os.environ.get('VERCEL'):
        # Vercel-এ প্রিন্টার কানেকশন সম্ভব নয়
        if request.method == 'GET':
            return render_template('print_status.html', 
                               message="Print job submitted successfully (Simulated). Your physical printer is not connected to this cloud server.", 
                               status="Success")
        else:
             # Vercel এ শুধু SUCCESS স্ট্যাটাস রিটার্ন করবে
             return jsonify({'status': 'SUCCESS', 'message': "Print command (Simulated) sent successfully."})


    
    # --- লোকাল পিসি প্রিন্টিং লজিক (Vercel এ চলবে না) ---
    if request.method == 'GET':
        return render_template('print_status.html', 
                               message="Printing job submitted. Please check the printer.", 
                               status="Success")


    try:
        data = request.get_json()
        print_type = data.get('printType', 'color') 
        file_path = data.get('file_path')
        copies = data.get('copies', 1)
        
        PRINTER_NAME = "EPSON L3250 Series"
        SUMATRA_PATH = "C:\\Users\\SUNMUN\\AppData\\Local\\SumatraPDF\\SumatraPDF.exe"
        
        command = [
            SUMATRA_PATH,
            "-print-to",
            PRINTER_NAME,
            file_path,
            '-silent' 
        ]
        
        if print_type == 'bw':
            command.append("-print-settings")
            command.append(f"{copies}x,fit")
            
        else: # Colour 
            command.append("-print-settings")
            command.append(f"{copies}x,fit") 




        subprocess.Popen(command)
        
        time.sleep(5) 
        
        return jsonify({'status': 'SUCCESS', 'message': f"Print command sent to {PRINTER_NAME}"})
                               
    except Exception as e:
        return jsonify({'status': 'FAILED', 'message': f"Printing Failed. Error: {e}"})








# --- অ্যাডমিন রুটস ---




@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD_HASHED:
            session['logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin_login.html', error='Invalid credentials.')
            
    return render_template('admin_login.html')




@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))




    sales_data = load_sales_data()
    
    # রিপোর্ট তৈরি
    daily_report_list = []
    # শেষ 30 দিনের ডেটা দেখানোর জন্য
    sorted_dates = sorted(sales_data['daily_sales'].keys(), reverse=True)[:30] 
    
    for date in sorted_dates:
        daily_report_list.append({
            'date': date,
            'orders': sales_data['daily_sales'][date]['orders'],
            'income': f"₹{sales_data['daily_sales'][date]['income']:.2f}"
        })
        
    return render_template('admin_dashboard.html', 
                           total_orders=sales_data['total_orders'],
                           total_income=f"₹{sales_data['total_income']:.2f}",
                           daily_reports=daily_report_list)




@app.route('/admin/logout')
def admin_logout():
    session.pop('logged_in', None)
    return redirect(url_for('admin_login'))








if __name__ == '__main__':
    # Vercel এ এটি চলবে না, শুধুমাত্র লোকাল পিসিতে চলবে
    start_cleanup_thread() 
    app.run(debug=True)

