import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TECHNIQUE_MAP = {
    "added": [
        {
            "id": "T1195.001",
            "name": "Supply Chain Compromise: Compromise Software Dependencies",
            "tactic": "Initial Access",
            "confidence": "High",
            "observation": "Unauthorized package introduced into runtime environment after deployment.",
            "assessment": "Behavior is consistent with supply chain dependency compromise.",
            "recommendation": "Validate build pipeline integrity. Verify image digest. Remove unauthorized package and redeploy from trusted baseline.",
            "evidence_type": "added_packages"
        },
        {
            "id": "T1554",
            "name": "Compromise Host Software Binary",
            "tactic": "Persistence",
            "confidence": "Medium",
            "observation": "New package not present in approved baseline detected in running container.",
            "assessment": "Potentially consistent with host software modification for persistent access. Requires further investigation.",
            "recommendation": "Inspect package contents. Verify package source and integrity. Check for unauthorized process execution.",
            "evidence_type": "added_packages"
        }
    ],
    "changed": [
        {
            "id": "T1574",
            "name": "Hijack Execution Flow",
            "tactic": "Privilege Escalation / Defense Evasion",
            "confidence": "Medium",
            "observation": "Package version downgraded from approved baseline to older version in running container.",
            "assessment": "Potentially consistent with execution flow hijacking via vulnerable dependency substitution. Requires confirmation.",
            "recommendation": "Restore approved package versions. Scan for CVEs in downgraded versions. Review runtime process behaviour.",
            "evidence_type": "changed_packages"
        },
        {
            "id": "T1195.002",
            "name": "Supply Chain Compromise: Compromise Software Supply Chain",
            "tactic": "Initial Access",
            "confidence": "High",
            "observation": "Package version changed from approved build-time baseline without authorized change record.",
            "assessment": "Behavior is consistent with software supply chain tampering post-deployment.",
            "recommendation": "Compare runtime image against build-time digest. Initiate incident response. Block further deployments pending review.",
            "evidence_type": "changed_packages"
        },
        {
            "id": "T1036",
            "name": "Masquerading",
            "tactic": "Defense Evasion",
            "confidence": "Low",
            "observation": "Unauthorized version substitution detected — package present under same name with different version.",
            "assessment": "Potentially consistent with masquerading via unauthorized dependency version substitution. Low confidence without further evidence.",
            "recommendation": "Verify package hash against trusted registry. Review package changelog for malicious modifications.",
            "evidence_type": "changed_packages"
        }
    ],
    "removed": [
        {
            "id": "T1562",
            "name": "Impair Defenses",
            "tactic": "Defense Evasion",
            "confidence": "High",
            "observation": "Security-relevant package removed from running container without authorization.",
            "assessment": "Behavior is consistent with deliberate impairment of defensive mechanisms.",
            "recommendation": "Restore removed package immediately. Review container access logs. Investigate who removed the package.",
            "evidence_type": "removed_packages"
        }
    ]
}

def map_techniques(report):
    techniques = []
    seen = set()
    added = report.get("added", {})
    removed = report.get("removed", {})
    changed = report.get("changed", {})

    def build_evidence(pkg_dict, change_type):
        evidence = []
        for pkg, val in pkg_dict.items():
            if change_type == "added":
                evidence.append(f"{pkg} {val} — added to runtime")
            elif change_type == "removed":
                evidence.append(f"{pkg} {val} — removed from runtime")
            elif change_type == "changed":
                evidence.append(f"{pkg} {val['baseline']} to {val['runtime']} — version changed")
        return evidence

    if added:
        evidence = build_evidence(added, "added")
        for t in TECHNIQUE_MAP["added"]:
            if t["id"] not in seen:
                techniques.append({**t, "packages": list(added.keys()), "evidence": evidence})
                seen.add(t["id"])

    if changed:
        evidence = build_evidence(changed, "changed")
        for t in TECHNIQUE_MAP["changed"]:
            if t["id"] not in seen:
                techniques.append({**t, "packages": list(changed.keys()), "evidence": evidence})
                seen.add(t["id"])

    if removed:
        evidence = build_evidence(removed, "removed")
        for t in TECHNIQUE_MAP["removed"]:
            if t["id"] not in seen:
                techniques.append({**t, "packages": list(removed.keys()), "evidence": evidence})
                seen.add(t["id"])

    tactics = list(set(t["tactic"] for t in techniques))
    high_conf = sum(1 for t in techniques if t["confidence"] == "High")
    primary_risk = "Supply Chain Compromise" if any("Supply Chain" in t["name"] for t in techniques) else "Dependency Drift"

    summary = {
        "total_techniques": len(techniques),
        "total_tactics": len(tactics),
        "highest_confidence": "High" if high_conf > 0 else "Medium",
        "primary_risk": primary_risk,
        "primary_scenario": "Supply Chain Compromise via Runtime Dependency Modification"
    }

    return techniques, summary

def save_mitre_report(techniques, summary):
    path = os.path.join(BASE_DIR, "sbom", "mitre-report.json")
    with open(path, "w") as f:
        json.dump({"techniques": techniques, "summary": summary, "total": len(techniques)}, f, indent=2)

if __name__ == "__main__":
    report_path = os.path.join(BASE_DIR, "sbom", "drift-report.json")
    with open(report_path) as f:
        report = json.load(f)
    techniques, summary = map_techniques(report)
    save_mitre_report(techniques, summary)
    print(f"MITRE ATT&CK Mapping Complete")
    print(f"Techniques: {summary['total_techniques']}")
    print(f"Primary Risk: {summary['primary_risk']}")
    for t in techniques:
        print(f"  [{t['confidence']}] {t['id']} — {t['name']}")
