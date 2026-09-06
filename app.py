import os
import base64
import json
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests

app = Flask(__name__)
CORS(app)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPO = os.environ.get("GITHUB_REPO")  # صيغة المستودع مثال: username/repo-name

@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "active", "message": "Cyber Security GitHub Storage API is running."})

@app.route("/submit-report", methods=["POST"])
def submit_report():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        # توليد رقم تعريف فريد للبلاغ
        timestamp_str = datetime.now().strftime("%Y%m%d%H%M%S")
        report_id = f"CYBER-REC-{timestamp_str}"
        data["report_id"] = report_id
        data["created_at"] = datetime.now().isoformat()

        file_path = f"reports/{report_id}.json"
        
        # تحويل البيانات إلى JSON ثم ترميزها بنظام Base64 لإرسالها عبر جيت هاب API
        file_content = json.dumps(data, ensure_ascii=False, indent=4)
        encoded_content = base64.b64encode(file_content.encode("utf-8")).decode("utf-8")

        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{file_path}"
        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        payload = {
            "message": f"Add cyber report {report_id}",
            "content": encoded_content
        }

        response = requests.put(url, json=payload, headers=headers)

        if response.status_code in [200, 201]:
            return jsonify({
                "success": True, 
                "report_id": report_id, 
                "message": "Report saved to GitHub successfully."
            }), 200
        else:
            return jsonify({
                "success": False, 
                "error": response.json()
            }), response.status_code

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
