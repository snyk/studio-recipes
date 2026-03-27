#!/bin/bash
#
# Snyk Studio Recipes Installer
# ==============================
#
# Self-contained installer for Snyk security recipes.
# Installs skills, hooks, rules, commands, and MCP configs
# into Cursor, Claude Code, and/or GitHub Copilot global directories.
#
# Usage:
#   ./snyk-studio-install.sh [options]
#
# Options:
#   --profile <name>      Installation profile (default, minimal)
#   --ade <name>          Target specific ADE: cursor, claude, copilot (auto-detect if omitted)
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

    # Check for GitHub Copilot (VS Code extension or CLI)
    if [[ -d "$HOME/.copilot" ]] || command -v github-copilot-cli &>/dev/null || \
       [[ -d "$HOME/.vscode/extensions" ]] && ls "$HOME/.vscode/extensions" 2>/dev/null | grep -qi "github.copilot"; then
        detected+=("copilot")
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
        echo "  3) GitHub Copilot"
        echo "  4) All"
        echo ""
        read -p "  Choose (1/2/3/4): " -n 1 -r
        echo
        case $REPLY in
            1) echo "cursor" ;;
            2) echo "claude" ;;
            3) echo "copilot" ;;
            4) echo "cursor claude copilot" ;;
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
        cursor)  echo "$HOME/.cursor" ;;
        claude)  echo "$HOME/.claude" ;;
        copilot) echo "$HOME/.copilot" ;;
        *)       echo "" ;;
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
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
