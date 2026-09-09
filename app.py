from flask import Flask, render_template, request, jsonify, send_file
import os
import json
from datetime import datetime

app = Flask(__name__)

CASES_DIR = 'cases'
USERS_FILE = 'users.json'

os.makedirs(CASES_DIR, exist_ok=True)

def init_users():
    if not os.path.exists(USERS_FILE):
        default_users = [
            { "username": "ahmed_jasem", "password": "123", "name": "أحمد جاسم", "rank": "مشرف (آدمن رئيسي)", "isAdmin": True },
            { "username": "ali_hussein", "password": "123", "name": "نقيب علي حسين", "rank": "مشرف (آدمن)", "isAdmin": True },
            { "username": "mufawad1", "password": "123", "name": "مفوض كرار حاتم", "rank": "مفوض", "isAdmin": False },
            { "username": "shurti1", "password": "123", "name": "شرطي حسن علي", "rank": "شرطي", "isAdmin": False }
        ]
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_users, f, ensure_ascii=False, indent=4)

init_users()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        users = json.load(f)
        
    for user in users:
        if user['username'] == username and user['password'] == password:
            return jsonify({"success": True, "user": user})
            
    return jsonify({"success": False, "message": "اسم المستخدم أو كلمة المرور غير صحيحة"})

@app.route('/api/users', methods=['GET', 'POST'])
def handle_users():
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        users = json.load(f)
        
    if request.method == 'GET':
        return jsonify(users)
        
    elif request.method == 'POST':
        new_user = request.json
        # التحقق من عدم تكرار اسم المستخدم
        if any(u['username'] == new_user.get('username') for u in users):
            return jsonify({"success": False, "message": "اسم المستخدم موجود مسبقاً"})
        
        users.append(new_user)
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users, f, ensure_ascii=False, indent=4)
        return jsonify({"success": True, "message": "تم إضافة المستخدم بنجاح"})

@app.route('/api/users/<username>', methods=['DELETE'])
def delete_user(username):
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        users = json.load(f)
        
    filtered_users = [u for u in users if u['username'] != username]
    if len(filtered_users) == len(users):
        return jsonify({"success": False, "message": "المستخدم غير موجود"})
        
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(filtered_users, f, ensure_ascii=False, indent=4)
    return jsonify({"success": True, "message": "تم حذف المستخدم بنجاح"})

@app.route('/api/reports', methods=['GET', 'POST'])
def handle_reports():
    if request.method == 'POST':
        report_data = request.json
        report_id = report_data.get('report_id')
        url = report_data.get('url', '').strip().lower()
        
        # فحص منع التكرار مركزياً على السيرفر
        if os.path.exists(CASES_DIR):
            for filename in os.listdir(CASES_DIR):
                if filename.endswith('.json'):
                    with open(os.path.join(CASES_DIR, filename), 'r', encoding='utf-8') as f:
                        existing = json.load(f)
                        if existing.get('url', '').strip().lower() == url:
                            return jsonify({"success": False, "message": "تنبيه أمني: تم تقديم بلاغ سابق لهذا الرابط بالفعل!"}), 400

        file_path = os.path.join(CASES_DIR, f"{report_id}.json")
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=4)
            
        return jsonify({"success": True, "message": "تم حفظ البلاغ بنجاح"})
        
    elif request.method == 'GET':
        reports = []
        if os.path.exists(CASES_DIR):
            for filename in os.listdir(CASES_DIR):
                if filename.endswith('.json'):
                    with open(os.path.join(CASES_DIR, filename), 'r', encoding='utf-8') as f:
                        reports.append(json.load(f))
        return jsonify(reports)

@app.route('/api/reports/<report_id>', methods=['DELETE'])
def delete_report(report_id):
    file_path = os.path.join(CASES_DIR, f"{report_id}.json")
    if os.path.exists(file_path):
        os.remove(file_path)
        return jsonify({"success": True, "message": "تم حذف البلاغ بنجاح"})
    return jsonify({"success": False, "message": "البلاغ غير موجود"})

@app.route('/api/reports/export/monthly', methods=['GET'])
def export_monthly():
    reports = []
    if os.path.exists(CASES_DIR):
        for filename in os.listdir(CASES_DIR):
            if filename.endswith('.json'):
                with open(os.path.join(CASES_DIR, filename), 'r', encoding='utf-8') as f:
                    reports.append(json.load(f))
                    
    export_path = 'monthly_activity_report.json'
    with open(export_path, 'w', encoding='utf-8') as f:
        json.dump(reports, f, ensure_ascii=False, indent=4)
        
    return send_file(export_path, as_attachment=True, download_name=f"monthly_cyber_report_{datetime.now().strftime('%Y_%m')}.json")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
