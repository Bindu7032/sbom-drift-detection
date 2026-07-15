#!/bin/bash

echo "=============================================="
echo "  SBOM DRIFT DETECTION PLATFORM"
echo "  Automated Runtime Security Scan"
echo "=============================================="
echo ""

# Step 1 - Generate runtime SBOM
echo "📦 Step 1: Extracting runtime SBOM from container..."
docker export sbom-demo -o /tmp/runtime-container.tar 2>/dev/null
SYFT_CHECK_FOR_APP_UPDATE=false syft /tmp/runtime-container.tar -o cyclonedx-json > sbom/runtime-sbom.json 2>/dev/null

if [ ! -s sbom/runtime-sbom.json ]; then
    echo "❌ Failed to generate runtime SBOM"
    exit 1
fi
echo "✅ Runtime SBOM generated"

# Step 2 - Run diff engine (detects drift, runs MITRE, compliance, timeline, AI summary)
echo ""
echo "🔍 Step 2: Running drift detection engine..."
python3 engine/diff_engine.py

# Step 3 - Send Slack alert
echo ""
echo "📢 Step 3: Sending Slack alert..."
source .env 2>/dev/null; python3 alerts/alert.py

echo ""
echo "=============================================="
echo "✅ Detection complete. Open dashboard to view results."
echo "   http://$(hostname -I | awk '{print $1}'):8080"
echo "=============================================="
