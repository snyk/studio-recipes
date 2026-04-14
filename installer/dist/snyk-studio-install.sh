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
#   --disable-upgrades    Skip Snyk CLI install/upgrade checks
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
DISABLE_UPGRADES=false
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
        --disable-upgrades) DISABLE_UPGRADES=true; shift ;;
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
    local has_npm=false
    if command -v npm &>/dev/null; then
        has_npm=true
    fi

    if command -v snyk &>/dev/null; then
        local snyk_ver
        snyk_ver=$(snyk --version 2>&1 | head -1)

        # Check for newer version (graceful — skip if offline, npm unavailable, or upgrades disabled)
        if [[ "$DISABLE_UPGRADES" == "true" ]]; then
            echo -e "  ${GREEN}✓${NC} Snyk CLI $snyk_ver (upgrade check skipped)"
        elif [[ "$has_npm" == "true" ]]; then
            local latest_ver
            latest_ver=$(npm view snyk version 2>/dev/null)
            if [[ -n "$latest_ver" && "$snyk_ver" != "$latest_ver" ]]; then
                echo -e "  ${YELLOW}⚠ Snyk CLI $snyk_ver installed (latest: $latest_ver)${NC}"
                local do_upgrade="n"
                if [[ "$AUTO_YES" == "true" ]]; then
                    do_upgrade="y"
                else
                    read -p "    Upgrade to $latest_ver? (y/n) " -n 1 -r do_upgrade
                    echo
                fi
                if [[ "$do_upgrade" =~ ^[Yy]$ ]]; then
                    echo "    Installing snyk@latest..."
                    if npm install -g snyk@latest 2>&1 | tail -1; then
                        snyk_ver=$(snyk --version 2>&1 | head -1)
                        echo -e "  ${GREEN}✓${NC} Snyk CLI $snyk_ver"
                    else
                        echo -e "  ${YELLOW}⚠ Upgrade failed, continuing with $snyk_ver${NC}"
                        warnings=$((warnings + 1))
                    fi
                else
                    echo -e "  ${GREEN}✓${NC} Snyk CLI $snyk_ver (update available: $latest_ver)"
                fi
            else
                echo -e "  ${GREEN}✓${NC} Snyk CLI $snyk_ver"
            fi
        else
            echo -e "  ${GREEN}✓${NC} Snyk CLI $snyk_ver"
        fi
    else
        # Snyk CLI not found — offer to install (unless upgrades disabled)
        if [[ "$DISABLE_UPGRADES" == "true" ]]; then
            echo -e "  ${YELLOW}⚠ Snyk CLI not found (install/upgrade disabled)${NC}"
            warnings=$((warnings + 1))
        elif [[ "$has_npm" == "true" ]]; then
            echo -e "  ${YELLOW}⚠ Snyk CLI not found${NC}"
            local do_install="n"
            if [[ "$AUTO_YES" == "true" ]]; then
                do_install="y"
            else
                read -p "    Install Snyk CLI now via npm? (y/n) " -n 1 -r do_install
                echo
            fi
            if [[ "$do_install" =~ ^[Yy]$ ]]; then
                echo "    Installing snyk@latest..."
                if npm install -g snyk@latest 2>&1 | tail -1; then
                    local snyk_ver
                    snyk_ver=$(snyk --version 2>&1 | head -1)
                    echo -e "  ${GREEN}✓${NC} Snyk CLI $snyk_ver"
                else
                    echo -e "  ${RED}✗ Snyk CLI installation failed${NC}"
                    echo "    Try manually: npm install -g snyk"
                    warnings=$((warnings + 1))
                fi
            else
                echo -e "  ${YELLOW}⚠ Snyk CLI not installed${NC}"
                echo "    Install later with: npm install -g snyk"
                warnings=$((warnings + 1))
            fi
        else
            echo -e "  ${YELLOW}⚠ Snyk CLI not found (npm not available for auto-install)${NC}"
            echo "    Install Node.js/npm first, then run: npm install -g snyk"
            warnings=$((warnings + 1))
        fi
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
echo "    2. Try /snyk-fix in a project with dependencies"
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
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
