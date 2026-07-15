import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def generate_summary(report, mitre=None, compliance=None):
    added = report.get('added', {})
    removed = report.get('removed', {})
    changed = report.get('changed', {})
    severity = report.get('severity', {})
    authorization = report.get('authorization', {})
    risk_score = report.get('risk_score', 0)
    risk_level = report.get('risk_level', 'UNKNOWN')
    high_cves = report.get('high_critical_cves', 0)
    total_drift = report.get('summary', {}).get('total_drift', 0)
    unauthorized = report.get('summary', {}).get('unauthorized', 0)
    authorized = report.get('summary', {}).get('authorized', 0)

    # Build summary text
    lines = []

    # Opening
    if not report.get('drift_detected'):
        return {
            'summary': 'Runtime analysis completed. No dependency drift detected. The runtime software inventory matches the approved build-time SBOM. The system is compliant.',
            'risk_level': risk_level,
            'recommended_actions': ['Continue periodic runtime SBOM monitoring.'],
            'threat_scenario': 'None detected.'
        }

    # Build concise executive summary
    parts = []

    drift_str = f"{total_drift} runtime dependency drift{'s' if total_drift != 1 else ''} detected ({unauthorized} unauthorized, {authorized} authorized)."
    parts.append(drift_str)

    if high_cves > 0:
        parts.append(f"Version downgrades introduced {high_cves} High/Critical CVEs.")

    if mitre and mitre.get('summary'):
        primary_risk = mitre['summary'].get('primary_risk', 'Supply Chain Compromise')
        parts.append(f"Observed behavior is consistent with a potential {primary_risk}.")

    if compliance and compliance.get('summary'):
        violated = compliance['summary'].get('VIOLATED', 0)
        if violated > 0:
            parts.append(f"Violates {violated} security controls across NIST SSDF, CIS Docker Benchmark, NTIA SBOM, and CycloneDX.")

    lines = parts

    # Build recommended actions
    actions = []
    if unauthorized > 0:
        actions.append("Verify whether unauthorized dependency changes were introduced by an authorized administrator or by an external threat actor.")
    if changed:
        actions.append("Restore all downgraded packages to their approved baseline versions.")
    if added and any(authorization.get(p, {}).get('status') != 'Authorized' for p in added):
        actions.append("Remove unauthorized packages from the running container immediately.")
    actions.append("Compare the runtime container image digest against the approved build-time baseline.")
    actions.append("If unauthorized changes are confirmed, redeploy from the trusted build-time image.")
    actions.append("Review CI/CD pipeline access logs for signs of unauthorized modification.")

    # Threat scenario
    if mitre and mitre.get('summary'):
        threat = mitre['summary'].get('primary_scenario', 'Supply Chain Compromise via Runtime Dependency Modification')
    else:
        threat = 'Unauthorized runtime dependency modification detected post-deployment.'

    confidence = 'High' if any(t.get('confidence') == 'High' for t in (mitre or {}).get('techniques', [])) else 'Medium'
    return {
        'summary': ' '.join(lines),
        'risk_level': risk_level,
        'risk_score': risk_score,
        'recommended_actions': actions,
        'threat_scenario': threat,
        'confidence': confidence
    }

def save_ai_summary(summary_data):
    path = os.path.join(BASE_DIR, 'sbom', 'ai-summary.json')
    with open(path, 'w') as f:
        json.dump(summary_data, f, indent=2)
    return path

if __name__ == '__main__':
    with open(os.path.join(BASE_DIR, 'sbom', 'drift-report.json')) as f:
        report = json.load(f)

    mitre = {}
    compliance = {}

    try:
        with open(os.path.join(BASE_DIR, 'sbom', 'mitre-report.json')) as f:
            mitre = json.load(f)
    except:
        pass

    try:
        with open(os.path.join(BASE_DIR, 'sbom', 'compliance-report.json')) as f:
            compliance = json.load(f)
    except:
        pass

    result = generate_summary(report, mitre, compliance)
    save_ai_summary(result)

    print("\nAI Investigation Summary")
    print("=" * 60)
    print(result['summary'])
    print(f"\nRisk Level: {result['risk_level']}")
    print(f"\nThreat Scenario:\n{result['threat_scenario']}")
    print("\nRecommended Actions:")
    for i, action in enumerate(result['recommended_actions'], 1):
        print(f"  {i}. {action}")
