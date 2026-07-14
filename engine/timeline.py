import json
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TIMELINE_PATH = os.path.join(BASE_DIR, 'sbom', 'timeline.json')

def load_timeline():
    try:
        with open(TIMELINE_PATH) as f:
            return json.load(f)
    except:
        return []

def log_event(event_type, description, severity='info', details=None):
    timeline = load_timeline()
    event = {
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "event_type": event_type,
        "description": description,
        "severity": severity,
        "details": details or {}
    }
    timeline.append(event)
    with open(TIMELINE_PATH, 'w') as f:
        json.dump(timeline, f, indent=2)
    return event

def clear_timeline():
    with open(TIMELINE_PATH, 'w') as f:
        json.dump([], f)

if __name__ == '__main__':
    # Test timeline
    clear_timeline()
    log_event('SBOM_GENERATED', 'Baseline SBOM generated during CI/CD build', 'info', {'packages': 122, 'format': 'CycloneDX'})
    log_event('CONTAINER_DEPLOYED', 'Application deployed as Docker container', 'info', {'image': 'sbom-demo:v1'})
    log_event('RUNTIME_SCAN', 'Runtime SBOM extracted from running container', 'info', {'packages': 123})
    log_event('DRIFT_DETECTED', 'Dependency drift detected — 4 changes found', 'high', {'total_drift': 4, 'unauthorized': 3})
    log_event('ALERT_SENT', 'Slack notification sent to security team', 'info', {'channel': '#sbom-alerts'})
    log_event('DASHBOARD_UPDATED', 'Security dashboard updated with findings', 'info', {})
    print("Timeline created successfully")
    timeline = load_timeline()
    for event in timeline:
        print(f"  {event['timestamp']} | {event['event_type']} | {event['description']}")
