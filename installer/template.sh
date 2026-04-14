#!/bin/bash
#
# Snyk Studio Recipes Installer
# ==============================
#
# Self-contained installer for Snyk security recipes.
# Installs skills, hooks, rules, commands, and MCP configs
# into Cursor and/or Claude Code global directories.
#
# Usage:
#   ./snyk-studio-install.sh [options]
#
# Options:
#   --profile <name>      Installation profile (default, minimal)
#   --ade <cursor|claude>  Target specific ADE (auto-detect if omitted)
#   --dry-run             Show what would be installed without making changes
#   --uninstall           Remove Snyk recipes from detected ADEs
#   --verify              Verify installed files and merged configs match manifest
#   --list                List available recipes and profiles
#   -y, --yes             Skip confirmation prompts
#   -h, --help            Show this help message
#

set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Defaults ────────────────────────────────────────────────────────
PROFILE="default"
TARGET_ADE=""
DRY_RUN=false
UNINSTALL=false
VERIFY_MODE=false
LIST_MODE=false
AUTO_YES=false
TMPDIR_BASE=""

# ── Argument parsing ────────────────────────────────────────────────
usage() {
    sed -n '/^# Usage:/,/^#$/p' "$0" | sed 's/^# \?//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --profile)    PROFILE="$2"; shift 2 ;;
        --ade)        TARGET_ADE="$2"; shift 2 ;;
        --dry-run)    DRY_RUN=true; shift ;;
        --uninstall)  UNINSTALL=true; shift ;;
        --verify)     VERIFY_MODE=true; shift ;;
        --list)       LIST_MODE=true; shift ;;
        -y|--yes)     AUTO_YES=true; shift ;;
        -h|--help)    usage ;;
        *)            echo -e "${RED}Unknown option: $1${NC}"; usage ;;
    esac
done

# ── Cleanup ─────────────────────────────────────────────────────────
cleanup() {
    if [[ -n "$TMPDIR_BASE" && -d "$TMPDIR_BASE" ]]; then
        rm -rf "$TMPDIR_BASE"
    fi
}
trap cleanup EXIT

# ── Banner ──────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
echo "  ╔════════════════════════════════════════════════════════╗"
echo "  ║        SNYK STUDIO RECIPES INSTALLER                  ║"
echo "  ╚════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Payload extraction ──────────────────────────────────────────────
TMPDIR_BASE=$(mktemp -d 2>/dev/null || mktemp -d -t 'snyk-installer')
PAYLOAD_DIR="$TMPDIR_BASE/payload"
mkdir -p "$PAYLOAD_DIR"

# Find the payload marker and extract
ARCHIVE_LINE=$(awk '/^__PAYLOAD__$/{print NR + 1; exit 0;}' "$0")
if [[ -z "$ARCHIVE_LINE" ]]; then
    echo -e "${RED}Error: No embedded payload found. This script may be corrupted.${NC}"
    exit 1
fi

tail -n +"$ARCHIVE_LINE" "$0" | base64 -d | tar xz -C "$PAYLOAD_DIR" 2>/dev/null
if [[ $? -ne 0 ]]; then
    echo -e "${RED}Error: Failed to extract payload. This script may be corrupted.${NC}"
    exit 1
fi

MANIFEST="$PAYLOAD_DIR/manifest.json"
MERGE_SCRIPT="$PAYLOAD_DIR/lib/merge_json.py"
TRANSFORM_SCRIPT="$PAYLOAD_DIR/lib/transform.py"

if [[ ! -f "$MANIFEST" ]]; then
    echo -e "${RED}Error: manifest.json not found in payload.${NC}"
    exit 1
fi

# ── Prerequisites check ────────────────────────────────────────────
check_prerequisites() {
    local warnings=0

    # Python 3
    if command -v python3 &>/dev/null; then
        local py_version
        py_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        echo -e "  ${GREEN}✓${NC} Python $py_version"
    else
        echo -e "  ${RED}✗ Python 3 not found${NC}"
        echo "    Install Python 3.8+ from https://python.org"
        exit 1
    fi

    # Snyk CLI
    if command -v snyk &>/dev/null; then
        local snyk_ver
        snyk_ver=$(snyk --version 2>&1 | head -1)
        echo -e "  ${GREEN}✓${NC} Snyk CLI $snyk_ver"
    else
        echo -e "  ${YELLOW}⚠ Snyk CLI not found${NC}"
        echo "    Install with: npm install -g snyk"
        warnings=$((warnings + 1))
    fi

    if [[ $warnings -gt 0 && "$AUTO_YES" != "true" ]]; then
        echo ""
        read -p "  Continue with warnings? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# ── ADE detection ───────────────────────────────────────────────────
detect_ades() {
    local detected=()

    # Check for Cursor
    if [[ -d "$HOME/.cursor" ]] || pgrep -qi "cursor" 2>/dev/null; then
        detected+=("cursor")
    fi

    # Check for Claude Code
    if [[ -d "$HOME/.claude" ]] || command -v claude &>/dev/null; then
        detected+=("claude")
    fi

    echo "${detected[@]}"
}

get_target_ades() {
    if [[ -n "$TARGET_ADE" ]]; then
        echo "$TARGET_ADE"
        return
    fi

    local detected
    detected=$(detect_ades)

    if [[ -z "$detected" ]]; then
        echo -e "  ${YELLOW}⚠ No supported ADE detected${NC}"
        echo ""
        echo "  Which ADE(s) would you like to install for?"
        echo "  1) Cursor"
        echo "  2) Claude Code"
        echo "  3) Both"
        echo ""
        read -p "  Choose (1/2/3): " -n 1 -r
        echo
        case $REPLY in
            1) echo "cursor" ;;
            2) echo "claude" ;;
            3) echo "cursor claude" ;;
            *) echo -e "${RED}Invalid choice${NC}"; exit 1 ;;
        esac
    else
        echo "$detected"
    fi
}

# ── Manifest loading (resolve profile) ──────────────────────────────
resolve_recipes() {
    python3 -c "
import json, sys

manifest = json.load(open('$MANIFEST'))
profile = '$PROFILE'

# Get profile recipe list
profiles = manifest.get('profiles', {})
if profile not in profiles:
    print(f'Unknown profile: {profile}', file=sys.stderr)
    print(f'Available: {list(profiles.keys())}', file=sys.stderr)
    sys.exit(1)

profile_recipes = profiles[profile]['recipes']

# Resolve wildcard
all_recipes = list(manifest['recipes'].keys())
if '*' in profile_recipes:
    active = set(all_recipes)
else:
    active = set(profile_recipes)

# Filter to enabled recipes only (manifest \"enabled\" flag)
result = []
for r in all_recipes:
    if r in active and manifest['recipes'][r].get('enabled', True):
        result.append(r)

print(' '.join(result))
"
}

# ── List mode ───────────────────────────────────────────────────────
list_recipes() {
    python3 -c "
import json

manifest = json.load(open('$MANIFEST'))

print('  Available Recipes:')
print('  ' + '─' * 54)
for rid, recipe in manifest['recipes'].items():
    status = '✓' if recipe.get('enabled', True) else '✗'
    rtype = recipe['type']
    desc = recipe['description']
    ades = ', '.join(recipe.get('sources', {}).keys())
    print(f'  {status} {rid:<35} [{rtype:<7}] ({ades})')
    print(f'    {desc}')

print()
print('  Profiles:')
print('  ' + '─' * 54)
for pid, pdata in manifest.get('profiles', {}).items():
    recipes = pdata['recipes']
    if '*' in recipes:
        label = 'all recipes'
    else:
        label = f\"{len(recipes)} recipes\"
    print(f'  • {pid:<15} {label}')
"
}

# ── Get install home for ADE ────────────────────────────────────────
get_ade_home() {
    local ade=$1
    case $ade in
        cursor) echo "$HOME/.cursor" ;;
        claude) echo "$HOME/.claude" ;;
        *)      echo "" ;;
    esac
}

# ── Installation plan display ───────────────────────────────────────
show_plan() {
    local ades=$1
    local recipes=$2

    echo -e "  ${BOLD}Installation Plan${NC}"
    echo "  ────────────────────────────────────────────────────"
    echo -e "  Profile:  ${CYAN}$PROFILE${NC}"
    echo -e "  ADEs:     ${CYAN}$ades${NC}"
    echo ""

    for ade in $ades; do
        local ade_home
        ade_home=$(get_ade_home "$ade")
        echo -e "  ${BOLD}$ade${NC} → $ade_home/"

        for recipe_id in $recipes; do
            # Check if this recipe has sources for this ADE
            local has_sources
            has_sources=$(python3 -c "
import json
m = json.load(open('$MANIFEST'))
r = m['recipes'].get('$recipe_id', {})
s = r.get('sources', {}).get('$ade', {})
files = s.get('files', [])
cm = s.get('config_merge')
transforms = s.get('transforms', [])
if files or cm or transforms:
    print('yes')
" 2>/dev/null)

            if [[ "$has_sources" == "yes" ]]; then
                local recipe_desc
                recipe_desc=$(python3 -c "
import json
m = json.load(open('$MANIFEST'))
print(m['recipes']['$recipe_id']['description'])
")
                echo -e "    • ${GREEN}$recipe_id${NC}: $recipe_desc"
            fi
        done
        echo ""
    done
}

# ── File copy (idempotent) ──────────────────────────────────────────
copy_file() {
    local src=$1
    local dest=$2

    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "    ${DIM}[dry-run] copy: $dest${NC}"
        return
    fi

    mkdir -p "$(dirname "$dest")"

    # Skip if identical
    if [[ -f "$dest" ]] && cmp -s "$src" "$dest"; then
        echo -e "    ${DIM}unchanged: $dest${NC}"
        return
    fi

    cp "$src" "$dest"
    echo -e "    ${GREEN}installed:${NC} $dest"
}

# ── Apply transform ─────────────────────────────────────────────────
apply_transform() {
    local transform_type=$1
    local src=$2
    local dest=$3

    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "    ${DIM}[dry-run] transform ($transform_type): $dest${NC}"
        return
    fi

    mkdir -p "$(dirname "$dest")"
    python3 "$TRANSFORM_SCRIPT" "$transform_type" "$src" "$dest"
    echo -e "    ${GREEN}transformed:${NC} $dest"
}

# ── Merge config ────────────────────────────────────────────────────
merge_config() {
    local strategy=$1
    local target=$2
    local source=$3

    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "    ${DIM}[dry-run] merge ($strategy): $target${NC}"
        return
    fi

    mkdir -p "$(dirname "$target")"
    python3 "$MERGE_SCRIPT" "$strategy" "$target" "$source"
    echo -e "    ${GREEN}merged:${NC} $target"
}

# ── Recipe installation ─────────────────────────────────────────────
install_recipe() {
    local recipe_id=$1
    local ade=$2
    local ade_home
    ade_home=$(get_ade_home "$ade")

    # Get recipe sources for this ADE
    local recipe_json
    recipe_json=$(python3 -c "
import json
m = json.load(open('$MANIFEST'))
r = m['recipes'].get('$recipe_id', {})
s = r.get('sources', {}).get('$ade', {})
print(json.dumps(s))
")

    if [[ "$recipe_json" == "{}" || "$recipe_json" == "null" ]]; then
        return
    fi

    echo -e "  ${BOLD}[$ade] $recipe_id${NC}"

    # Copy files
    local file_count
    file_count=$(python3 -c "
import json
s = json.loads('$(echo "$recipe_json" | sed "s/'/\\\\'/g")')
print(len(s.get('files', [])))
")

    if [[ "$file_count" -gt 0 ]]; then
        python3 -c "
import json
s = json.loads('''$recipe_json''')
for f in s.get('files', []):
    print(f['src'] + '|' + f['dest'])
" | while IFS='|' read -r src dest; do
            local full_src="$PAYLOAD_DIR/$src"
            local full_dest

            # All dest paths are relative to $HOME (e.g. .cursor/hooks/foo.py, .mcp.json)
            full_dest="$HOME/$dest"

            copy_file "$full_src" "$full_dest"
        done
    fi

    # Apply transforms (these override the simple file copy)
    local transform_count
    transform_count=$(python3 -c "
import json
s = json.loads('''$recipe_json''')
print(len(s.get('transforms', [])))
")

    if [[ "$transform_count" -gt 0 ]]; then
        python3 -c "
import json
s = json.loads('''$recipe_json''')
for t in s.get('transforms', []):
    print(t['type'] + '|' + t['src'] + '|' + t['dest'])
" | while IFS='|' read -r ttype src dest; do
            local full_src="$PAYLOAD_DIR/$src"
            local full_dest="$HOME/$dest"
            apply_transform "$ttype" "$full_src" "$full_dest"
        done
    fi

    # Merge configs
    local has_merge
    has_merge=$(python3 -c "
import json
s = json.loads('''$recipe_json''')
cm = s.get('config_merge')
if cm:
    print(cm['strategy'] + '|' + cm['target'] + '|' + cm['source'])
")

    if [[ -n "$has_merge" ]]; then
        IFS='|' read -r strategy target source <<< "$has_merge"
        local full_target="$HOME/$target"
        local full_source="$PAYLOAD_DIR/$source"
        merge_config "$strategy" "$full_target" "$full_source"
    fi

    # chmod +x on .py files
    if [[ "$DRY_RUN" != "true" ]]; then
        find "$ade_home" -name "*.py" -path "*/snyk*" -exec chmod +x {} \; 2>/dev/null || true
        find "$ade_home" -name "*.py" -path "*/hooks/*" -exec chmod +x {} \; 2>/dev/null || true
    fi
}

# ── Verify config ──────────────────────────────────────────────────
verify_config() {
    local strategy=$1
    local target=$2
    local source=$3

    python3 "$MERGE_SCRIPT" "$strategy" "$target" "$source" 2>/dev/null
    return $?
}

# ── Recipe verification ───────────────────────────────────────────
verify_recipe() {
    local recipe_id=$1
    local ade=$2
    local ade_home
    ade_home=$(get_ade_home "$ade")
    local failed=0

    # Get recipe sources for this ADE
    local recipe_json
    recipe_json=$(python3 -c "
import json
m = json.load(open('$MANIFEST'))
r = m['recipes'].get('$recipe_id', {})
s = r.get('sources', {}).get('$ade', {})
print(json.dumps(s))
")

    if [[ "$recipe_json" == "{}" || "$recipe_json" == "null" ]]; then
        return 0
    fi

    echo -e "  ${BOLD}[$ade] $recipe_id${NC}"

    # Check files exist
    python3 -c "
import json
s = json.loads('''$recipe_json''')
for f in s.get('files', []):
    print(f['dest'])
" | while IFS= read -r dest; do
        local full_dest="$HOME/$dest"
        if [[ -f "$full_dest" ]]; then
            echo -e "    ${GREEN}✓${NC} $dest"
        else
            echo -e "    ${RED}✗ missing:${NC} $dest"
            failed=1
        fi
    done

    # Check config merge
    local has_merge
    has_merge=$(python3 -c "
import json
s = json.loads('''$recipe_json''')
cm = s.get('config_merge')
if cm:
    print(cm['strategy'] + '|' + cm['target'] + '|' + cm['source'])
")

    if [[ -n "$has_merge" ]]; then
        IFS='|' read -r strategy target source <<< "$has_merge"
        local verify_strategy="verify_${strategy#merge_}"
        local full_target="$HOME/$target"
        local full_source="$PAYLOAD_DIR/$source"

        if verify_config "$verify_strategy" "$full_target" "$full_source"; then
            echo -e "    ${GREEN}✓${NC} hooks registered in $target"
        else
            echo -e "    ${RED}✗ hooks missing from $target${NC}"
            failed=1
        fi
    fi

    return $failed
}

# ── Unmerge config ──────────────────────────────────────────────────
unmerge_config() {
    local strategy=$1
    local target=$2
    local source=$3

    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "    ${DIM}[dry-run] unmerge ($strategy): $target${NC}"
        return
    fi

    mkdir -p "$(dirname "$target")"
    python3 "$MERGE_SCRIPT" "$strategy" "$target" "$source"
    echo -e "    ${GREEN}unmerged:${NC} $target"
}

# ── Remove file ────────────────────────────────────────────────────
remove_file() {
    local file=$1

    if [[ ! -f "$file" ]]; then
        return
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "    ${DIM}[dry-run] remove: $file${NC}"
    else
        rm -f "$file"
        echo -e "    ${GREEN}removed:${NC} $file"
    fi
}

# ── Remove Python __pycache__ dirs under a path (hook imports leave these) ──
remove_pycache_under() {
    local root=$1
    [[ -n "$root" && -d "$root" ]] || return

    while IFS= read -r -d '' d; do
        if [[ "$DRY_RUN" == "true" ]]; then
            echo -e "    ${DIM}[dry-run] remove: $d${NC}"
        else
            rm -rf "$d"
            echo -e "    ${GREEN}removed:${NC} $d/"
        fi
    done < <(find "$root" -maxdepth 1 -type d -name '__pycache__' -print0 2>/dev/null)
}

# ── Remove empty parent dirs up to a stop point ────────────────────
remove_empty_parents() {
    local dir=$1
    local stop=$2

    while [[ "$dir" != "$stop" && -d "$dir" ]]; do
        if [[ -z "$(ls -A "$dir" 2>/dev/null)" ]]; then
            if [[ "$DRY_RUN" == "true" ]]; then
                echo -e "    ${DIM}[dry-run] rmdir: $dir/${NC}"
            else
                rmdir "$dir"
                echo -e "    ${GREEN}removed:${NC} $dir/"
            fi
            dir=$(dirname "$dir")
        else
            break
        fi
    done
}

# ── Uninstall ───────────────────────────────────────────────────────
uninstall() {
    local ades=$1
    echo -e "  ${BOLD}Uninstalling Snyk recipes...${NC}"
    echo ""

    # Resolve which recipes are in the manifest (all, not just a profile)
    local all_recipes
    all_recipes=$(python3 -c "
import json
m = json.load(open('$MANIFEST'))
print(' '.join(m['recipes'].keys()))
")

    for ade in $ades; do
        local ade_home
        ade_home=$(get_ade_home "$ade")
        echo -e "  ${BOLD}$ade${NC} ($ade_home/):"

        for recipe_id in $all_recipes; do
            # Get recipe sources for this ADE
            local recipe_json
            recipe_json=$(python3 -c "
import json
m = json.load(open('$MANIFEST'))
r = m['recipes'].get('$recipe_id', {})
s = r.get('sources', {}).get('$ade', {})
print(json.dumps(s))
")

            if [[ "$recipe_json" == "{}" || "$recipe_json" == "null" ]]; then
                continue
            fi

            echo -e "  ${BOLD}[$ade] $recipe_id${NC}"

            # Remove files listed in manifest
            python3 -c "
import json
s = json.loads('''$recipe_json''')
for f in s.get('files', []):
    print(f['dest'])
for t in s.get('transforms', []):
    print(t['dest'])
" | while IFS= read -r dest; do
                local full_dest
                if [[ "$dest" == ".mcp.json" ]]; then
                    full_dest="$HOME/$dest"
                else
                    full_dest="$HOME/$dest"
                fi
                remove_file "$full_dest"

                # Python leaves __pycache__ next to imported modules; remove so parents can rmdir
                remove_pycache_under "$(dirname "$full_dest")"

                # Clean up empty parent directories up to ADE home
                remove_empty_parents "$(dirname "$full_dest")" "$ade_home"
            done

            # Unmerge configs
            local has_merge
            has_merge=$(python3 -c "
import json
s = json.loads('''$recipe_json''')
cm = s.get('config_merge')
if cm:
    print(cm['strategy'] + '|' + cm['target'] + '|' + cm['source'])
")

            if [[ -n "$has_merge" ]]; then
                IFS='|' read -r strategy target source <<< "$has_merge"
                local unstrategy="un${strategy}"
                local full_target="$HOME/$target"
                local full_source="$PAYLOAD_DIR/$source"
                unmerge_config "$unstrategy" "$full_target" "$full_source"
            fi
        done

        echo ""
    done
}

# ── Main ────────────────────────────────────────────────────────────

# List mode
if [[ "$LIST_MODE" == "true" ]]; then
    list_recipes
    exit 0
fi

# Prerequisites
echo -e "  ${BOLD}Checking prerequisites...${NC}"
check_prerequisites
echo ""

# Detect ADEs
ADES=$(get_target_ades)
if [[ -z "$ADES" ]]; then
    echo -e "${RED}No ADE selected. Exiting.${NC}"
    exit 1
fi

# Uninstall mode
if [[ "$UNINSTALL" == "true" ]]; then
    uninstall "$ADES"
    echo -e "${GREEN}  Uninstall complete.${NC}"
    exit 0
fi

# Verify mode (standalone)
if [[ "$VERIFY_MODE" == "true" ]]; then
    RECIPES=$(resolve_recipes)
    if [[ -z "$RECIPES" ]]; then
        echo -e "${YELLOW}No recipes to verify.${NC}"
        exit 0
    fi
    echo -e "  ${BOLD}Verifying installation...${NC}"
    echo ""
    VERIFY_FAILED=0
    for ade in $ADES; do
        for recipe_id in $RECIPES; do
            verify_recipe "$recipe_id" "$ade" || VERIFY_FAILED=1
        done
    done
    echo ""
    if [[ "$VERIFY_FAILED" -eq 1 ]]; then
        echo -e "  ${RED}${BOLD}Verification failed.${NC} Re-run the installer to repair."
        exit 1
    else
        echo -e "  ${GREEN}${BOLD}All checks passed.${NC}"
        exit 0
    fi
fi

# Resolve active recipes
RECIPES=$(resolve_recipes)
if [[ -z "$RECIPES" ]]; then
    echo -e "${YELLOW}No recipes selected for installation.${NC}"
    exit 0
fi

# Show plan
show_plan "$ADES" "$RECIPES"

# Confirm
if [[ "$AUTO_YES" != "true" && "$DRY_RUN" != "true" ]]; then
    read -p "  Proceed with installation? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "  Installation cancelled."
        exit 0
    fi
    echo ""
fi

# Install
INSTALL_COUNT=0
for ade in $ADES; do
    for recipe_id in $RECIPES; do
        install_recipe "$recipe_id" "$ade"
        INSTALL_COUNT=$((INSTALL_COUNT + 1))
    done
done

# ── Post-install verification ──────────────────────────────────────
if [[ "$DRY_RUN" != "true" ]]; then
    echo ""
    echo -e "  ${BOLD}Verifying installation...${NC}"
    VERIFY_FAILED=0
    for ade in $ADES; do
        for recipe_id in $RECIPES; do
            verify_recipe "$recipe_id" "$ade" || VERIFY_FAILED=1
        done
    done
fi

# ── Summary ─────────────────────────────────────────────────────────
echo ""
if [[ "$VERIFY_FAILED" -eq 1 ]]; then
    echo -e "${YELLOW}${BOLD}"
    echo "  ╔════════════════════════════════════════════════════════╗"
    echo "  ║   INSTALLATION COMPLETE (with warnings)               ║"
    echo "  ╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${YELLOW}Some checks failed. Run with --verify to see details.${NC}"
else
    echo -e "${GREEN}${BOLD}"
    echo "  ╔════════════════════════════════════════════════════════╗"
    echo "  ║        INSTALLATION COMPLETE                          ║"
    echo "  ╚════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
fi

if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "  ${YELLOW}(Dry run — no changes were made)${NC}"
    echo ""
fi

echo "  Recipes processed: $INSTALL_COUNT"
echo "  ADEs configured: $ADES"
echo ""
echo "  Next steps:"
echo "    1. Open your ADE and verify Snyk recipes are active"
echo "    2. Run 'snyk auth' if not yet authenticated"
echo "    3. Try /snyk-fix in a project with dependencies"
echo ""
echo "  To verify or diagnose:"
echo "    ./snyk-studio-install.sh --verify"
echo ""
echo "  To uninstall:"
echo "    ./snyk-studio-install.sh --uninstall"
echo ""

exit 0

# Payload marker — do not remove this line
__PAYLOAD__
