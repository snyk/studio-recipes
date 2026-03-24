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

    # Snyk auth
    if command -v snyk &>/dev/null; then
        if snyk whoami &>/dev/null 2>&1; then
            echo -e "  ${GREEN}✓${NC} Snyk authenticated"
        else
            echo -e "  ${YELLOW}⚠ Snyk not authenticated${NC}"
            echo "    Run: snyk auth"
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

# ── Summary ─────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔════════════════════════════════════════════════════════╗"
echo "  ║        INSTALLATION COMPLETE                          ║"
echo "  ╚════════════════════════════════════════════════════════╝"
echo -e "${NC}"

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
echo "  To uninstall:"
echo "    ./snyk-studio-install.sh --uninstall"
echo ""

exit 0

# Payload marker — do not remove this line
__PAYLOAD__
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
