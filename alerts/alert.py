import json
import os
import urllib.request
from datetime import datetime

SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL', '')

def load_report():
    report_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'sbom', 'drift-report.json')
    with open(report_path) as f:
        return json.load(f)

def format_message(report):
    lines = []
    lines.append("=" * 55)
    lines.append("🚨 SBOM DRIFT DETECTION ALERT")
    lines.append(f"Timestamp  : {report['timestamp']}")
    lines.append(f"Risk Score : {report.get('risk_score', 'N/A')}/100 ({report.get('risk_level', 'UNKNOWN')})")
    lines.append(f"Unauthorized Changes: {report['summary'].get('unauthorized', 0)}")
    lines.append(f"Authorized Changes  : {report['summary'].get('authorized', 0)}")
    lines.append("=" * 55)
    if report['added']:
        lines.append("\nADDED PACKAGES:")
        for pkg, ver in report['added'].items():
            sev = report.get('severity', {}).get(pkg, 'No Known CVEs')
            auth = report.get('authorization', {}).get(pkg, {}).get('status', 'Unauthorized')
            lines.append(f"  + {pkg} == {ver} | {sev} | {auth}")
    if report['removed']:
        lines.append("\nREMOVED PACKAGES:")
        for pkg, ver in report['removed'].items():
            sev = report.get('severity', {}).get(pkg, 'No Known CVEs')
            auth = report.get('authorization', {}).get(pkg, {}).get('status', 'Unauthorized')
            lines.append(f"  - {pkg} == {ver} | {sev} | {auth}")
    if report['changed']:
        lines.append("\nCHANGED PACKAGES:")
        for pkg, versions in report['changed'].items():
            sev = report.get('severity', {}).get(pkg, 'No Known CVEs')
            cves = len(report.get('cves', {}).get(pkg, []))
            auth = report.get('authorization', {}).get(pkg, {}).get('status', 'Unauthorized')
            lines.append(f"  ~ {pkg}: {versions['baseline']} -> {versions['runtime']} | {sev} | CVEs: {cves} | {auth}")
    lines.append(f"\nTotal Drift    : {report['summary']['total_drift']}")
    lines.append(f"High/Critical  : {report.get('high_critical_cves', 0)} CVEs")
    lines.append(f"Risk Level     : {report.get('risk_level', 'UNKNOWN')}")
    lines.append("=" * 55)
    return "\n".join(lines)

def send_slack_alert(message):
    if not SLACK_WEBHOOK_URL:
        print("⚠️  SLACK_WEBHOOK_URL not set")
        return
    payload = json.dumps({"text": f"```{message}```"}).encode('utf-8')
    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=payload,
        headers={'Content-Type': 'application/json'}
    )
    try:
        urllib.request.urlopen(req)
        print("✅ Slack alert sent successfully")
    except Exception as e:
        print(f"❌ Slack alert failed: {e}")

def main():
    report = load_report()
    if not report['drift_detected']:
        print("✅ No drift detected. No alert needed.")
        return
    message = format_message(report)
    print(message)
    send_slack_alert(message)

if __name__ == '__main__':
    main()
