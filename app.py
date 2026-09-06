import os
import base64
import json
import uuid
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests

app = Flask(__name__)
CORS(app)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPO = os.environ.get("GITHUB_REPO")

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "active", 
        "version": "v2.0-uuid", 
        "message": "Cyber Security GitHub Storage API is running."
    })

@app.route("/submit-report", methods=["POST"])
def submit_report():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        timestamp_str = datetime.now().strftime("%Y%m%d%H%M%S")
        random_suffix = uuid.uuid4().hex[:6].upper()
        report_id = f"CYBER-REC-{timestamp_str}-{random_suffix}"
        
        data["report_id"] = report_id
        data["created_at"] = datetime.now().isoformat()

        # الحفظ في مجلد cases الجديد
        file_path = f"cases/{report_id}.json"
        
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

@app.route("/get-report/<report_id>", methods=["GET"])
def get_report(report_id):
    try:
        # القراءة من مجلد cases أيضاً لتتطابق مع مسار الحفظ
        file_path = f"cases/{report_id}.json"
        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{file_path}"
        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            file_data = response.json()
            file_content = base64.b64decode(file_data["content"]).decode("utf-8")
            report_json = json.loads(file_content)
            return jsonify({"success": True, "data": report_json}), 200
        else:
            return jsonify({"success": False, "error": "Report not found"}), 404

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
