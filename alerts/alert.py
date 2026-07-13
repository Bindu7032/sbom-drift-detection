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
    lines.append("=" * 50)
    lines.append("🚨 SBOM DRIFT ALERT")
    lines.append(f"Timestamp: {report['timestamp']}")
    lines.append("=" * 50)
    if report['added']:
        lines.append("\nADDED PACKAGES (not in baseline):")
        for pkg, ver in report['added'].items():
            lines.append(f"  + {pkg} == {ver}")
    if report['removed']:
        lines.append("\nREMOVED PACKAGES (missing from runtime):")
        for pkg, ver in report['removed'].items():
            lines.append(f"  - {pkg} == {ver}")
    if report['changed']:
        lines.append("\nCHANGED PACKAGES (version mismatch):")
        for pkg, versions in report['changed'].items():
            lines.append(f"  ~ {pkg}: {versions['baseline']} -> {versions['runtime']}")
    lines.append(f"\nTotal Added:   {report['summary']['total_added']}")
    lines.append(f"Total Removed: {report['summary']['total_removed']}")
    lines.append(f"Total Changed: {report['summary']['total_changed']}")
    lines.append("=" * 50)
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
