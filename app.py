import os
import json
import base64
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# قراءة إعدادات جيت هاب من متغيرات البيئة في Render
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPO = os.environ.get("GITHUB_REPO")  # ahmedmorad2002h-blip/cyber-reports

@app.route('/submit-report', methods=['POST'])
def submit_report():
    data = request.json
    report_id = data.get('id')
    
    if not report_id:
        return jsonify({"status": "error", "message": "Invalid ID"}), 400

    # مسار حفظ ملف البلاغ داخل مستودع cyber-reports
    file_path = f"reports/{report_id}.json"
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{file_path}"
    
    # تحويل البيانات إلى Base64 لكي تقبلها GitHub API
    json_content = json.dumps(data, ensure_ascii=False, indent=4)
    content_base64 = base64.b64encode(json_content.encode('utf-8')).decode('utf-8')
    
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    
    payload = {
        "message": f"Add official report {report_id}",
        "content": content_base64
    }
    
    response = requests.put(url, json=payload, headers=headers)
    
    if response.status_code in [200, 201]:
        return jsonify({"status": "success", "message": "Saved to GitHub successfully"}), 200
    else:
        return jsonify({"status": "error", "details": response.text}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
