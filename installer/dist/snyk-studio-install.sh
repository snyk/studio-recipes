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
