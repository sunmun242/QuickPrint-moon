from flask import Flask, request, jsonify
import subprocess
import os
import requests
import tempfile


app = Flask(__name__)


PRINTER_NAME = "EPSON L3250 Series"  # তোমার প্রিন্টারের নাম এখানে দাও
SUMATRA_PATH = r"C:\Users\SUNMUN\AppData\Local\SumatraPDF\SumatraPDF.exe"


@app.route('/print', methods=['POST'])
def print_file():
    data = request.get_json()
    file_url = data.get('file_url')
    copies = int(data.get('copies', 1))
    print_type = data.get('printType', 'color')


    if not file_url:
        return jsonify({"status": "FAILED", "message": "No file URL received"}), 400


    try:
        # ফাইল ডাউনলোড
        response = requests.get(file_url)
        if response.status_code != 200:
            return jsonify({"status": "FAILED", "message": "File download failed"}), 400


        # টেম্পোরারি ফাইল তৈরি
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        temp_file.write(response.content)
        temp_file.close()


        # প্রিন্ট কমান্ড
        command = [
            SUMATRA_PATH,
            "-print-to", PRINTER_NAME,
            temp_file.name,
            "-silent"
        ]


        for _ in range(copies):
            subprocess.Popen(command)


        return jsonify({"status": "SUCCESS", "message": f"Printing started on {PRINTER_NAME}"})
    except Exception as e:
        return jsonify({"status": "FAILED", "message": str(e)}), 500




if __name__ == '__main__':
    app.run(port=5001)