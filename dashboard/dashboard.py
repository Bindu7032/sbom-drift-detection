import json
import os
from flask import Flask, render_template, send_file

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_PATH = os.path.join(BASE_DIR, 'sbom', 'drift-report.json')

def load_report():
    try:
        with open(REPORT_PATH) as f:
            return json.load(f)
    except:
        return None

@app.route('/')
def index():
    report = load_report()
    return render_template('index.html', report=report)

@app.route('/download')
def download():
    return send_file(REPORT_PATH, as_attachment=True, download_name='drift-report.json')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
