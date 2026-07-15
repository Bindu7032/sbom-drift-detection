import json
import os
from flask import Flask, render_template, send_file, jsonify, Response

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_PATH = os.path.join(BASE_DIR, 'sbom', 'drift-report.json')

def load_json(filename):
    try:
        with open(os.path.join(BASE_DIR, 'sbom', filename)) as f:
            return json.load(f)
    except:
        return {}

@app.route('/')
def overview():
    report = load_json('drift-report.json')
    ai = load_json('ai-summary.json')
    return render_template('overview.html', report=report, ai=ai, page='overview')

@app.route('/packages')
def packages():
    report = load_json('drift-report.json')
    return render_template('packages.html', report=report, page='packages')

@app.route('/mitre')
def mitre_page():
    report = load_json('drift-report.json')
    mitre = load_json('mitre-report.json')
    return render_template('mitre.html', report=report, mitre=mitre, page='mitre')

@app.route('/compliance')
def compliance_page():
    report = load_json('drift-report.json')
    compliance = load_json('compliance-report.json')
    return render_template('compliance.html', report=report, compliance=compliance, page='compliance')

@app.route('/timeline')
def timeline_page():
    report = load_json('drift-report.json')
    data = load_json('timeline.json')
    timeline = data if isinstance(data, dict) and 'events' in data else {'events': data if isinstance(data, list) else [], 'summary': {}}
    return render_template('timeline.html', report=report, timeline=timeline, page='timeline')

@app.route('/report')
def investigation_report():
    import sys
    sys.path.insert(0, os.path.join(BASE_DIR, 'engine'))
    from report_generator import generate_html_report
    html = generate_html_report()
    return Response(html, mimetype='text/html')

@app.route('/api/ai-summary')
def ai_summary():
    return jsonify(load_json('ai-summary.json'))

@app.route('/api/report')
def api_report():
    return jsonify(load_json('drift-report.json'))

@app.route('/api/mitre')
def api_mitre():
    return jsonify(load_json('mitre-report.json'))

@app.route('/api/compliance')
def api_compliance():
    return jsonify(load_json('compliance-report.json'))

@app.route('/api/timeline')
def api_timeline():
    return jsonify(load_json('timeline.json'))

@app.route('/download')
def download():
    return send_file(REPORT_PATH, as_attachment=True, download_name='drift-report.json')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
