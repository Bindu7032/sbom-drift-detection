import json
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_sbom(path):
    with open(path) as f:
        data = json.load(f)
    packages = {}
    for component in data.get('components', []):
        if component.get('type') == 'library':
            name = component.get('name', '').lower()
            version = component.get('version', '')
            if name in packages:
                existing = packages[name]
                if version != existing:
                    packages[name] = min(existing, version)
            else:
                packages[name] = version
    return packages

def load_grype_results(path):
    severity_map = {}
    cve_map = {}
    cvss_map = {}
    fix_map = {}
    try:
        with open(path) as f:
            data = json.load(f)
        for match in data.get('matches', []):
            pkg = match.get('artifact', {}).get('name', '').lower()
            sev = match.get('vulnerability', {}).get('severity', 'No Known CVEs')
            cve = match.get('vulnerability', {}).get('id', '')
            cvss = match.get('vulnerability', {}).get('cvss', [])
            fix = match.get('vulnerability', {}).get('fix', {}).get('versions', [])
            order = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'None']
            if pkg not in severity_map:
                severity_map[pkg] = sev
                cve_map[pkg] = [cve]
                cvss_map[pkg] = cvss[0].get('metrics', {}).get('baseScore', 0) if cvss else 0
                fix_map[pkg] = fix[0] if fix else 'No fix available'
            else:
                existing = severity_map[pkg]
                if sev in order and existing in order:
                    if order.index(sev) < order.index(existing):
                        severity_map[pkg] = sev
                if cve not in cve_map[pkg]:
                    cve_map[pkg].append(cve)
    except Exception as e:
        pass
    return severity_map, cve_map, cvss_map, fix_map

def load_change_log():
    try:
        change_log_path = os.path.join(BASE_DIR, 'engine', 'change_log.json')
        with open(change_log_path) as f:
            data = json.load(f)
        return {entry['name'].lower(): entry for entry in data.get('authorized_changes', [])}
    except:
        return {}

def classify_drift(pkg, change_log):
    if pkg.lower() in change_log:
        entry = change_log[pkg.lower()]
        return 'Authorized', entry.get('reason', 'Approved change')
    return 'Unauthorized', 'Not in approved change log'

def calculate_risk_score(added, removed, changed, severity_map, cve_map):
    score = 0
    sev_weights = {'Critical': 8, 'High': 4, 'Medium': 2, 'Low': 1, 'No Known CVEs': 0, 'Unknown': 0}
    drift_weights = {'added': 10, 'removed': 10, 'changed': 5}

    for pkg in added:
        score += drift_weights['added']
        sev = severity_map.get(pkg, 'None')
        cves = cve_map.get(pkg, [])
        score += sev_weights.get(sev, 0) * len(cves)

    for pkg in removed:
        score += drift_weights['removed']
        sev = severity_map.get(pkg, 'None')
        cves = cve_map.get(pkg, [])
        score += sev_weights.get(sev, 0) * len(cves)

    for pkg in changed:
        score += drift_weights['changed']
        sev = severity_map.get(pkg, 'None')
        cves = cve_map.get(pkg, [])
        score += sev_weights.get(sev, 0) * len(cves)

    score = min(100, score)

    if score >= 75:
        level = 'CRITICAL'
    elif score >= 50:
        level = 'HIGH'
    elif score >= 25:
        level = 'MEDIUM'
    else:
        level = 'LOW'

    return score, level

def count_high_critical_cves(all_pkgs, severity_map, cve_map):
    count = 0
    for pkg in all_pkgs:
        sev = severity_map.get(pkg, 'None')
        if sev in ['Critical', 'High']:
            count += len(cve_map.get(pkg, []))
    return count

def detect_drift(baseline_path, runtime_path):
    baseline = load_sbom(baseline_path)
    runtime  = load_sbom(runtime_path)
    added   = {k: runtime[k] for k in runtime if k not in baseline}
    removed = {k: baseline[k] for k in baseline if k not in runtime}
    changed = {
        k: {'baseline': baseline[k], 'runtime': runtime[k]}
        for k in baseline
        if k in runtime and baseline[k] != runtime[k]
    }
    return added, removed, changed, len(baseline), len(runtime)

def save_report(added, removed, changed, severity_map, cve_map, cvss_map,
                fix_map, risk_score, risk_level, baseline_count, runtime_count,
                authorization, high_critical_cves):
    report = {
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "drift_detected": bool(added or removed or changed),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "baseline_packages": baseline_count,
        "runtime_packages": runtime_count,
        "high_critical_cves": high_critical_cves,
        "added": added,
        "removed": removed,
        "changed": changed,
        "severity": severity_map,
        "cves": cve_map,
        "cvss": cvss_map,
        "fix": fix_map,
        "authorization": authorization,
        "summary": {
            "total_added": len(added),
            "total_removed": len(removed),
            "total_changed": len(changed),
            "total_drift": len(added) + len(removed) + len(changed),
            "authorized": sum(1 for v in authorization.values() if v['status'] == 'Authorized'),
            "unauthorized": sum(1 for v in authorization.values() if v['status'] == 'Unauthorized')
        }
    }
    report_path = os.path.join(BASE_DIR, 'sbom', 'drift-report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\n📄 Report saved to sbom/drift-report.json")

def main():
    baseline_path = os.path.join(BASE_DIR, 'sbom', 'baseline-sbom.json')
    runtime_path  = os.path.join(BASE_DIR, 'sbom', 'runtime-sbom.json')
    grype_path    = os.path.join(BASE_DIR, 'sbom', 'grype-results.json')

    print("=" * 60)
    print("SBOM DRIFT DETECTION REPORT")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    added, removed, changed, baseline_count, runtime_count = detect_drift(baseline_path, runtime_path)
    severity_map, cve_map, cvss_map, fix_map = load_grype_results(grype_path)
    change_log = load_change_log()
    risk_score, risk_level = calculate_risk_score(added, removed, changed, severity_map, cve_map)

    all_pkgs = list(added.keys()) + list(removed.keys()) + list(changed.keys())
    high_critical_cves = count_high_critical_cves(all_pkgs, severity_map, cve_map)

    authorization = {}
    for pkg in all_pkgs:
        status, reason = classify_drift(pkg, change_log)
        authorization[pkg] = {'status': status, 'reason': reason}

    print(f"\nBaseline Packages   : {baseline_count}")
    print(f"Runtime Packages    : {runtime_count}")
    print(f"Risk Score          : {risk_score}/100 ({risk_level})")
    print(f"High/Critical CVEs  : {high_critical_cves}")

    if not added and not removed and not changed:
        print("\n✅ NO DRIFT DETECTED — System is COMPLIANT")
    else:
        total = len(added) + len(removed) + len(changed)
        auth_count = sum(1 for v in authorization.values() if v['status'] == 'Authorized')
        unauth_count = sum(1 for v in authorization.values() if v['status'] == 'Unauthorized')
        print(f"\n🚨 DRIFT DETECTED — {total} changes found")
        print(f"   Authorized:   {auth_count}")
        print(f"   Unauthorized: {unauth_count}\n")

        if added:
            print("ADDED PACKAGES:")
            for pkg, ver in added.items():
                sev = severity_map.get(pkg, 'None')
                sev_display = 'No known vulnerabilities' if sev == 'None' else sev
                cves = cve_map.get(pkg, [])
                auth = authorization.get(pkg, {}).get('status', 'Unauthorized')
                print(f"  + {pkg} == {ver}")
                print(f"    Severity: {sev_display} | CVEs: {len(cves)} | Status: {auth}")

        if removed:
            print("\nREMOVED PACKAGES:")
            for pkg, ver in removed.items():
                sev = severity_map.get(pkg, 'None')
                sev_display = 'No known vulnerabilities' if sev == 'None' else sev
                auth = authorization.get(pkg, {}).get('status', 'Unauthorized')
                print(f"  - {pkg} == {ver}")
                print(f"    Severity: {sev_display} | Status: {auth}")

        if changed:
            print("\nCHANGED PACKAGES:")
            for pkg, versions in changed.items():
                sev = severity_map.get(pkg, 'None')
                sev_display = 'No known vulnerabilities' if sev == 'None' else sev
                cves = cve_map.get(pkg, [])
                auth = authorization.get(pkg, {}).get('status', 'Unauthorized')
                print(f"  ~ {pkg}: {versions['baseline']} → {versions['runtime']}")
                print(f"    Severity: {sev_display} | CVEs: {len(cves)} | Status: {auth}")

    print("\n" + "=" * 60)
    print(f"Total Added:        {len(added)}")
    print(f"Total Removed:      {len(removed)}")
    print(f"Total Changed:      {len(changed)}")
    print(f"Risk Score:         {risk_score}/100")
    print(f"Risk Level:         {risk_level}")
    print(f"High/Critical CVEs: {high_critical_cves}")
    print("=" * 60)

    save_report(added, removed, changed, severity_map, cve_map, cvss_map,
                fix_map, risk_score, risk_level, baseline_count, runtime_count,
                authorization, high_critical_cves)

if __name__ == '__main__':
    main()
