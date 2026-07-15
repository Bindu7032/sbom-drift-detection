import json
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_json(filename):
    try:
        with open(os.path.join(BASE_DIR, 'sbom', filename)) as f:
            return json.load(f)
    except:
        return {}

def generate_html_report():
    report = load_json('drift-report.json')
    mitre = load_json('mitre-report.json')
    compliance = load_json('compliance-report.json')
    ai = load_json('ai-summary.json')
    timeline_raw = load_json('timeline.json')
    if isinstance(timeline_raw, dict):
        timeline_events = timeline_raw.get('events', [])
        timeline_summary = timeline_raw.get('summary', {})
    elif isinstance(timeline_raw, list):
        timeline_events = timeline_raw
        timeline_summary = {}
    else:
        timeline_events = []
        timeline_summary = {}

    generated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    incident_id = timeline_summary.get('incident_id') or f"INC-{datetime.now().strftime('%Y%m%d')}-001"
    risk_level = report.get('risk_level', 'UNKNOWN')
    risk_score = report.get('risk_score', 0)
    risk_color = {'CRITICAL': '#ff4444', 'HIGH': '#ff8c00', 'MEDIUM': '#ffd700', 'LOW': '#3fb950'}.get(risk_level, '#8b949e')

    status_colors = {'VIOLATED': '#f85149', 'REVIEW': '#e3b341', 'PARTIAL': '#ff8c00', 'COMPLIANT': '#3fb950'}

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SBOM Drift Investigation Report — {incident_id}</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:'Segoe UI',Arial,sans-serif; background:#fff; color:#1a1a1a; font-size:13px; }}
  .page {{ max-width:900px; margin:0 auto; padding:40px; }}

  .cover {{ text-align:center; padding:60px 0 40px; border-bottom:3px solid #1a1a1a; margin-bottom:40px; }}
  .cover .product {{ font-size:11px; color:#666; text-transform:uppercase; letter-spacing:2px; margin-bottom:12px; }}
  .cover h1 {{ font-size:28px; font-weight:700; color:#1a1a1a; margin-bottom:8px; }}
  .cover .incident {{ font-size:14px; color:#666; margin-bottom:20px; }}
  .cover .meta {{ display:flex; justify-content:center; gap:40px; margin-top:20px; }}
  .cover .meta-item .label {{ font-size:10px; color:#999; text-transform:uppercase; }}
  .cover .meta-item .value {{ font-size:13px; font-weight:600; color:#1a1a1a; margin-top:3px; }}

  .risk-badge {{ display:inline-block; padding:8px 24px; border-radius:4px; font-size:14px; font-weight:700; color:#fff; background:{risk_color}; margin-top:16px; }}

  h2 {{ font-size:16px; font-weight:700; color:#1a1a1a; margin:32px 0 12px; padding-bottom:6px; border-bottom:2px solid #e0e0e0; }}
  h3 {{ font-size:13px; font-weight:700; color:#333; margin:16px 0 8px; }}

  .summary-box {{ background:#f8f8f8; border-left:4px solid {risk_color}; padding:16px 20px; border-radius:4px; margin-bottom:20px; }}
  .summary-box p {{ font-size:13px; color:#333; line-height:1.7; margin-bottom:10px; }}
  .summary-box .threat {{ font-size:12px; font-weight:600; color:#666; margin-top:8px; }}
  .summary-box .threat span {{ color:{risk_color}; }}

  .kpi-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:20px; }}
  .kpi {{ background:#f8f8f8; border:1px solid #e0e0e0; border-radius:6px; padding:14px; text-align:center; }}
  .kpi .num {{ font-size:28px; font-weight:700; }}
  .kpi .lbl {{ font-size:10px; color:#999; text-transform:uppercase; margin-top:4px; }}

  table {{ width:100%; border-collapse:collapse; margin-bottom:20px; font-size:12px; }}
  thead th {{ background:#1a1a1a; color:#fff; padding:9px 12px; text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:0.5px; }}
  tbody td {{ padding:9px 12px; border-bottom:1px solid #e0e0e0; }}
  tbody tr:nth-child(even) {{ background:#f9f9f9; }}

  .pill {{ display:inline-block; padding:2px 8px; border-radius:3px; font-size:10px; font-weight:700; }}
  .pill-red {{ background:#fff0f0; color:#c0392b; border:1px solid #f85149; }}
  .pill-orange {{ background:#fff8f0; color:#d35400; border:1px solid #ff8c00; }}
  .pill-yellow {{ background:#fffdf0; color:#b7950b; border:1px solid #e3b341; }}
  .pill-green {{ background:#f0fff4; color:#1e8449; border:1px solid #3fb950; }}
  .pill-gray {{ background:#f5f5f5; color:#666; border:1px solid #ccc; }}

  .mitre-card {{ background:#f8f8f8; border:1px solid #e0e0e0; border-left:4px solid #6c3483; border-radius:4px; padding:14px; margin-bottom:10px; }}
  .mitre-id {{ font-size:12px; font-weight:700; color:#6c3483; font-family:monospace; }}
  .mitre-name {{ font-size:13px; font-weight:700; color:#1a1a1a; margin-left:8px; }}
  .mitre-tactic {{ font-size:10px; font-weight:700; padding:2px 8px; border-radius:3px; background:#e8d5f0; color:#6c3483; }}
  .mitre-conf {{ font-size:10px; font-weight:700; padding:2px 8px; border-radius:3px; margin-left:6px; }}
  .conf-high {{ background:#fde8e8; color:#c0392b; }}
  .conf-medium {{ background:#fef3e2; color:#d35400; }}
  .conf-low {{ background:#f5f5f5; color:#666; }}
  .mitre-label {{ font-size:10px; color:#999; text-transform:uppercase; margin-top:8px; margin-bottom:2px; }}
  .mitre-text {{ font-size:12px; color:#333; }}

  .timeline-item {{ display:flex; gap:16px; margin-bottom:12px; }}
  .timeline-dot {{ width:10px; height:10px; border-radius:50%; margin-top:4px; flex-shrink:0; }}
  .timeline-content {{ flex:1; padding-bottom:12px; border-bottom:1px solid #eee; }}
  .timeline-title {{ font-size:12px; font-weight:700; color:#1a1a1a; }}
  .timeline-time {{ font-size:10px; color:#999; margin-top:2px; }}
  .timeline-desc {{ font-size:12px; color:#555; margin-top:3px; }}
  .timeline-duration {{ font-size:10px; color:#999; font-style:italic; margin-top:4px; }}

  .actions ol {{ padding-left:20px; }}
  .actions li {{ font-size:12px; color:#333; margin-bottom:6px; line-height:1.5; }}

  .footer {{ margin-top:40px; padding-top:16px; border-top:1px solid #e0e0e0; display:flex; justify-content:space-between; font-size:10px; color:#999; }}

  @media print {{
    body {{ background:#fff; }}
    .page {{ padding:20px; }}
  }}
</style>
</head>
<body>
<div class="page">

<!-- COVER -->
<div class="cover">
  <div class="product">SBOM Drift Detection Platform</div>
  <h1>Security Investigation Report</h1>
  <div class="incident">Incident ID: <strong>{incident_id}</strong></div>
  <div class="risk-badge">{risk_level} RISK — {risk_score}/100</div>
  <div class="meta">
    <div class="meta-item"><div class="label">Generated</div><div class="value">{generated_at}</div></div>
    <div class="meta-item"><div class="label">Scan Timestamp</div><div class="value">{report.get('timestamp', 'N/A')}</div></div>
    <div class="meta-item"><div class="label">Platform</div><div class="value">Docker · Syft · Grype</div></div>
    <div class="meta-item"><div class="label">SBOM Format</div><div class="value">CycloneDX 1.7</div></div>
  </div>
</div>

<!-- EXECUTIVE SUMMARY -->
<h2>1. Executive Summary</h2>
<div class="summary-box">
  <p>{ai.get('summary', 'No summary available.')}</p>
  <div class="threat">Primary Threat Scenario: <span>{ai.get('threat_scenario', 'N/A')}</span></div>
</div>

<!-- KPIs -->
<div class="kpi-grid">
  <div class="kpi"><div class="num" style="color:{risk_color};">{risk_score}/100</div><div class="lbl">Risk Score</div></div>
  <div class="kpi"><div class="num" style="color:#f85149;">{report.get('summary',{}).get('unauthorized',0)}</div><div class="lbl">Unauthorized Changes</div></div>
  <div class="kpi"><div class="num" style="color:#ff8c00;">{report.get('high_critical_cves',0)}</div><div class="lbl">High/Critical CVEs</div></div>
  <div class="kpi"><div class="num" style="color:#6c3483;">{mitre.get('total',0)}</div><div class="lbl">MITRE Techniques</div></div>
</div>

<!-- DRIFT FINDINGS -->
<h2>2. Runtime Drift Findings</h2>
<p style="color:#666;margin-bottom:12px;">Baseline: {report.get('baseline_packages','N/A')} packages &nbsp;·&nbsp; Runtime: {report.get('runtime_packages','N/A')} packages &nbsp;·&nbsp; Drift: {report.get('summary',{}).get('total_drift',0)} changes</p>
"""

    # Added packages
    added = report.get('added', {})
    if added:
        html += "<h3>Added Packages</h3><table><thead><tr><th>Package</th><th>Runtime Version</th><th>Severity</th><th>CVEs</th><th>Authorization</th></tr></thead><tbody>"
        for pkg, ver in added.items():
            sev = report.get('severity', {}).get(pkg, 'None')
            auth = report.get('authorization', {}).get(pkg, {}).get('status', 'Unauthorized')
            cves = len(report.get('cves', {}).get(pkg, []))
            pill = 'pill-green' if auth == 'Authorized' else 'pill-red'
            html += f"<tr><td><strong>{pkg}</strong></td><td>{ver}</td><td>{sev}</td><td>{cves}</td><td><span class='pill {pill}'>{auth}</span></td></tr>"
        html += "</tbody></table>"

    # Changed packages
    changed = report.get('changed', {})
    if changed:
        html += "<h3>Version Changes</h3><table><thead><tr><th>Package</th><th>Baseline</th><th>Runtime</th><th>Severity</th><th>CVEs</th><th>Authorization</th></tr></thead><tbody>"
        for pkg, versions in changed.items():
            sev = report.get('severity', {}).get(pkg, 'None')
            auth = report.get('authorization', {}).get(pkg, {}).get('status', 'Unauthorized')
            cves = len(report.get('cves', {}).get(pkg, []))
            sev_map = {'Critical': 'pill-red', 'High': 'pill-orange', 'Medium': 'pill-yellow', 'Low': 'pill-green'}
            sev_pill = sev_map.get(sev, 'pill-gray')
            auth_pill = 'pill-green' if auth == 'Authorized' else 'pill-red'
            html += f"<tr><td><strong>{pkg}</strong></td><td>{versions['baseline']}</td><td>{versions['runtime']}</td><td><span class='pill {sev_pill}'>{sev}</span></td><td>{cves}</td><td><span class='pill {auth_pill}'>{auth}</span></td></tr>"
        html += "</tbody></table>"

    # MITRE
    html += "<h2>3. MITRE ATT&CK Mapping</h2>"
    for t in mitre.get('techniques', []):
        conf_cls = {'High': 'conf-high', 'Medium': 'conf-medium', 'Low': 'conf-low'}.get(t.get('confidence', ''), 'conf-low')
        html += f"""<div class="mitre-card">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
    <div><span class="mitre-id">{t.get('id','')}</span><span class="mitre-name">{t.get('name','')}</span></div>
    <div><span class="mitre-tactic">{t.get('tactic','')}</span><span class="mitre-conf {conf_cls}">{t.get('confidence','')} Confidence</span></div>
  </div>
  <div class="mitre-label">Observation</div><div class="mitre-text">{t.get('observation','')}</div>
  <div class="mitre-label">Assessment</div><div class="mitre-text">{t.get('assessment','')}</div>
  <div class="mitre-label">Recommendation</div><div class="mitre-text">{t.get('recommendation','')}</div>
</div>"""

    # Compliance
    html += "<h2>4. Compliance Assessment</h2>"
    comp_summary = compliance.get('summary', {})
    score = compliance.get('compliance_score', 0)
    html += f"<p style='margin-bottom:12px;'>Compliance Score: <strong>{score}%</strong> &nbsp;·&nbsp; Violated: <strong style='color:#f85149;'>{comp_summary.get('VIOLATED',0)}</strong> &nbsp;·&nbsp; Compliant: <strong style='color:#3fb950;'>{comp_summary.get('COMPLIANT',0)}</strong></p>"

    for fw in compliance.get('results', []):
        html += f"<h3>{fw.get('framework','')} <span style='font-weight:400;color:#999;font-size:11px;'>{fw.get('version','')}</span></h3>"
        html += "<table><thead><tr><th>Control</th><th>Title</th><th>Status</th><th>Reason</th></tr></thead><tbody>"
        for ctrl in fw.get('controls', []):
            status = ctrl.get('status', '')
            color = status_colors.get(status, '#666')
            html += f"<tr><td><span class='pill' style='background:{color}22;color:{color};border:1px solid {color};'>{ctrl.get('id','')}</span></td><td>{ctrl.get('title','')}</td><td><span class='pill' style='background:{color}22;color:{color};border:1px solid {color};'>{status}</span></td><td style='font-size:11px;color:#555;'>{ctrl.get('reason','')}</td></tr>"
        html += "</tbody></table>"

    # Timeline
    html += "<h2>5. Investigation Timeline</h2>"
    dot_colors = {'high': '#f85149', 'warning': '#e3b341', 'success': '#3fb950', 'info': '#58a6ff', 'critical': '#f85149'}
    for event in timeline_events:
        dot_color = dot_colors.get(event.get('severity', 'info'), '#58a6ff')
        html += f"""<div class="timeline-item">
  <div class="timeline-dot" style="background:{dot_color};"></div>
  <div class="timeline-content">
    <div class="timeline-title">{event.get('event_type','').replace('_',' ')}</div>
    <div class="timeline-time">{event.get('timestamp','')}</div>
    <div class="timeline-desc">{event.get('description','')}</div>
    {f'<div class="timeline-duration">{event.get("duration_to_next","")}</div>' if event.get('duration_to_next') else ''}
  </div>
</div>"""

    # Recommended Actions
    html += "<h2>6. Recommended Actions</h2><div class='actions'><ol>"
    for action in ai.get('recommended_actions', []):
        html += f"<li>{action}</li>"
    html += "</ol></div>"

    # Footer
    html += f"""
<div class="footer">
  <span>Generated by SBOM Drift Detection Platform &nbsp;·&nbsp; Powered by Syft · Grype · CycloneDX 1.7</span>
  <span>Generated: {generated_at}</span>
</div>

</div>
</body>
</html>"""

    return html

if __name__ == '__main__':
    html = generate_html_report()
    output_path = os.path.join(BASE_DIR, 'sbom', 'investigation-report.html')
    with open(output_path, 'w') as f:
        f.write(html)
    print(f"Report generated: {output_path}")
    print(f"Size: {len(html)} characters")
