#!/bin/bash
#
# Snyk Studio Recipes - Build Script
# ====================================
#
# Reads manifest.json, collects source files, creates a base64-encoded tarball,
# and injects it into template.sh to produce dist/snyk-studio-install.sh.
#
# Usage:
#   cd installer/
#   ./build.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

MANIFEST="$SCRIPT_DIR/manifest.json"
TEMPLATE="$SCRIPT_DIR/template.sh"
DIST_DIR="$SCRIPT_DIR/dist"
OUTPUT="$DIST_DIR/snyk-studio-install.sh"

echo -e "${CYAN}Snyk Studio Recipes — Build${NC}"
echo "──────────────────────────────────────────"

# Validate inputs exist
if [[ ! -f "$MANIFEST" ]]; then
    echo -e "${RED}Error: manifest.json not found at $MANIFEST${NC}"
    exit 1
fi

if [[ ! -f "$TEMPLATE" ]]; then
    echo -e "${RED}Error: template.sh not found at $TEMPLATE${NC}"
    exit 1
fi

# Create dist directory
mkdir -p "$DIST_DIR"

# Create temp staging area
STAGING=$(mktemp -d 2>/dev/null || mktemp -d -t 'snyk-build')
cleanup() { rm -rf "$STAGING"; }
trap cleanup EXIT

echo -e "${GREEN}1.${NC} Collecting source files from manifest..."

# Copy manifest and lib scripts
cp "$MANIFEST" "$STAGING/manifest.json"
mkdir -p "$STAGING/lib"
cp "$SCRIPT_DIR/lib/merge_json.py" "$STAGING/lib/merge_json.py"
cp "$SCRIPT_DIR/lib/transform.py" "$STAGING/lib/transform.py"

# Parse manifest to collect all src paths
SRC_FILES=$(python3 -c "
import json

manifest = json.load(open('$MANIFEST'))
files = set()

for recipe_id, recipe in manifest['recipes'].items():
    for ade, sources in recipe.get('sources', {}).items():
        for f in sources.get('files', []):
            files.add(f['src'])
        cm = sources.get('config_merge')
        if cm:
            files.add(cm['source'])
        for t in sources.get('transforms', []):
            files.add(t['src'])

for f in sorted(files):
    print(f)
")

FILE_COUNT=0
MISSING=0
while IFS= read -r src; do
    full_path="$REPO_ROOT/$src"
    if [[ -f "$full_path" ]]; then
        # Create directory structure in staging
        mkdir -p "$STAGING/$(dirname "$src")"
        cp "$full_path" "$STAGING/$src"
        FILE_COUNT=$((FILE_COUNT + 1))
    else
        echo -e "  ${YELLOW}⚠ Missing: $src${NC}"
        MISSING=$((MISSING + 1))
    fi
done <<< "$SRC_FILES"

echo "  Collected $FILE_COUNT files ($MISSING missing)"

if [[ $MISSING -gt 0 ]]; then
    echo -e "${YELLOW}Warning: Some source files are missing. The installer may not work correctly.${NC}"
fi

echo -e "${GREEN}2.${NC} Creating tarball..."

# Create tarball from staging
TARBALL="$STAGING.tar.gz"
tar czf "$TARBALL" -C "$STAGING" .
TARBALL_SIZE=$(wc -c < "$TARBALL" | tr -d ' ')
echo "  Tarball size: ${TARBALL_SIZE} bytes"

echo -e "${GREEN}3.${NC} Base64 encoding..."

PAYLOAD=$(base64 < "$TARBALL")
PAYLOAD_SIZE=${#PAYLOAD}
echo "  Encoded size: ${PAYLOAD_SIZE} bytes"

echo -e "${GREEN}4.${NC} Generating snyk-studio-install.sh..."

# Read template up to __PAYLOAD__ marker, then append encoded payload
awk '/^__PAYLOAD__$/{found=1; print; exit} {print}' "$TEMPLATE" > "$OUTPUT"
echo "$PAYLOAD" >> "$OUTPUT"

chmod +x "$OUTPUT"

OUTPUT_SIZE=$(wc -c < "$OUTPUT" | tr -d ' ')
echo "  Output: $OUTPUT"
echo "  Size: ${OUTPUT_SIZE} bytes"

echo ""
echo "──────────────────────────────────────────"
echo -e "${GREEN}Build complete!${NC}"
echo ""
echo "Distribution script: $OUTPUT"
echo ""
echo "Test with:"
echo "  $OUTPUT --list"
echo "  $OUTPUT --dry-run"
echo "  $OUTPUT --ade cursor --dry-run"
echo ""
