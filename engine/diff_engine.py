import json
from datetime import datetime

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

def save_report(added, removed, changed):
    report = {
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "drift_detected": bool(added or removed or changed),
        "added": added,
        "removed": removed,
        "changed": changed,
        "summary": {
            "total_added": len(added),
            "total_removed": len(removed),
            "total_changed": len(changed)
        }
    }
    with open('sbom/drift-report.json', 'w') as f:
        json.dump(report, f, indent=2)
    print("\n📄 Report saved to sbom/drift-report.json")

def main():
    baseline_path = 'sbom/baseline-sbom.json'
    runtime_path  = 'sbom/runtime-sbom.json'

    print("=" * 60)
    print("SBOM DRIFT DETECTION REPORT")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    added, removed, changed, baseline_count, runtime_count = detect_drift(
        baseline_path, runtime_path
    )

    print(f"\nBaseline Packages : {baseline_count}")
    print(f"Runtime Packages  : {runtime_count}")

    if not added and not removed and not changed:
        print("\n✅ NO DRIFT DETECTED — System is COMPLIANT")
    else:
        print("\n🚨 DRIFT DETECTED — Unauthorized changes found\n")

        if added:
            print("ADDED PACKAGES (not in baseline):")
            for pkg, ver in added.items():
                print(f"  + {pkg} == {ver}")

        if removed:
            print("\nREMOVED PACKAGES (missing from runtime):")
            for pkg, ver in removed.items():
                print(f"  - {pkg} == {ver}")

        if changed:
            print("\nCHANGED PACKAGES (version mismatch):")
            for pkg, versions in changed.items():
                print(f"  ~ {pkg}: {versions['baseline']} → {versions['runtime']}")

    print("\n" + "=" * 60)
    print(f"Total Added:   {len(added)}")
    print(f"Total Removed: {len(removed)}")
    print(f"Total Changed: {len(changed)}")
    print("=" * 60)

    save_report(added, removed, changed)

if __name__ == '__main__':
    main()
