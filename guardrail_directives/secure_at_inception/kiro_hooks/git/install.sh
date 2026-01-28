#!/bin/bash
#
# Snyk Security Hook Installer
# ============================
#
# Installs the pre-commit hook that blocks commits introducing new vulnerabilities.
#
# Usage:
#   ./kiro_hooks/git/install.sh
#
# Requirements:
#   - Python 3.8+
#   - Snyk CLI (npm install -g snyk)
#   - Git repository
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo "")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     SNYK SECURITY PRE-COMMIT HOOK INSTALLER                ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if we're in a git repository
if [ -z "$REPO_ROOT" ]; then
    echo -e "${RED}✗ Error: Not in a git repository${NC}"
    echo "  Please run this script from within a git repository"
    exit 1
fi

echo -e "${GREEN}✓${NC} Git repository found: $REPO_ROOT"

# Check for Python 3
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    echo -e "${GREEN}✓${NC} Python 3 found: $PYTHON_VERSION"
else
    echo -e "${RED}✗ Error: Python 3 is required${NC}"
    echo "  Please install Python 3.8 or later"
    exit 1
fi

# Check for Snyk CLI
if command -v snyk &> /dev/null; then
    SNYK_VERSION=$(snyk --version 2>&1)
    echo -e "${GREEN}✓${NC} Snyk CLI found: $SNYK_VERSION"
else
    echo -e "${RED}✗ Error: Snyk CLI not found${NC}"
    echo "  The hook requires the Snyk CLI to be installed globally."
    echo ""
    echo "  Install with: npm install -g snyk"
    echo "  Then authenticate: snyk auth"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if Snyk is authenticated
if command -v snyk &> /dev/null; then
    if snyk auth check &> /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Snyk authenticated"
    else
        echo -e "${YELLOW}⚠ Warning: Snyk not authenticated${NC}"
        echo "  Run 'snyk auth' to authenticate before using the hook"
    fi
fi

# Create .git/hooks directory if it doesn't exist
HOOKS_DIR="$REPO_ROOT/.git/hooks"
mkdir -p "$HOOKS_DIR"

# Check for existing pre-commit hook
PRE_COMMIT_HOOK="$HOOKS_DIR/pre-commit"
if [ -f "$PRE_COMMIT_HOOK" ]; then
    echo -e "${YELLOW}⚠ Existing pre-commit hook found${NC}"
    
    # Check if it's our hook
    if grep -q "SNYK SECURITY PRE-COMMIT HOOK" "$PRE_COMMIT_HOOK" 2>/dev/null; then
        echo "  This is an existing Snyk hook. Updating..."
    else
        echo "  Backing up existing hook to: pre-commit.backup"
        cp "$PRE_COMMIT_HOOK" "$PRE_COMMIT_HOOK.backup"
        
        echo ""
        echo "  Options:"
        echo "  1. Replace existing hook (recommended)"
        echo "  2. Chain hooks (run both)"
        echo "  3. Cancel installation"
        echo ""
        read -p "  Choose option (1/2/3): " -n 1 -r
        echo
        
        case $REPLY in
            1)
                echo "  Replacing existing hook..."
                ;;
            2)
                echo "  Creating chained hook..."
                # Create a wrapper that runs both
                cat > "$PRE_COMMIT_HOOK" << 'CHAIN_EOF'
#!/bin/bash
# Chained pre-commit hook

# Run original hook
if [ -f "$(dirname "$0")/pre-commit.backup" ]; then
    "$(dirname "$0")/pre-commit.backup"
    ORIGINAL_EXIT=$?
    if [ $ORIGINAL_EXIT -ne 0 ]; then
        exit $ORIGINAL_EXIT
    fi
fi

# Run Snyk hook
exec python3 "$(git rev-parse --show-toplevel)/kiro_hooks/git/pre-commit"
CHAIN_EOF
                chmod +x "$PRE_COMMIT_HOOK"
                echo -e "${GREEN}✓${NC} Chained hook installed"
                exit 0
                ;;
            *)
                echo "  Installation cancelled"
                exit 0
                ;;
        esac
    fi
fi

# Install the hook (symlink or copy)
echo ""
echo "Installing pre-commit hook..."

# Option 1: Symlink (preferred - updates automatically)
HOOK_SOURCE="$SCRIPT_DIR/pre-commit"

if [ -f "$HOOK_SOURCE" ]; then
    # Create symlink
    ln -sf "$HOOK_SOURCE" "$PRE_COMMIT_HOOK"
    echo -e "${GREEN}✓${NC} Symlink created: $PRE_COMMIT_HOOK -> $HOOK_SOURCE"
else
    echo -e "${RED}✗ Error: Hook source not found: $HOOK_SOURCE${NC}"
    exit 1
fi

# Make sure it's executable
chmod +x "$HOOK_SOURCE"
chmod +x "$PRE_COMMIT_HOOK"

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     INSTALLATION COMPLETE                                  ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "The Snyk security pre-commit hook is now active."
echo ""
echo "Snyk CLI configuration:"
if [ "$SNYK_METHOD" = "global" ]; then
    echo -e "  • Method: ${GREEN}global${NC} (using 'snyk' command)"
elif [ "$SNYK_METHOD" = "npx" ]; then
    echo -e "  • Method: ${CYAN}npx${NC} (using 'npx snyk' command)"
else
    echo -e "  • Method: ${YELLOW}auto${NC} (will detect at runtime)"
fi
echo "  • Config: $CONFIG_FILE"
echo ""
echo "What happens on commit:"
echo "  • Code changes are scanned for NEW vulnerabilities (SAST)"
echo "  • Package changes are checked for security regressions (SCA)"
echo "  • Commit is blocked if new issues are introduced"
echo ""
echo "Configuration (environment variables):"
echo "  • SNYK_HOOK_DEBUG=1  - Enable verbose output"
echo "  • SNYK_HOOK_QUICK=1  - Skip old version comparison (faster)"
echo ""
echo "To change Snyk method later, edit: $CONFIG_FILE"
echo "  { \"snyk\": { \"method\": \"global\" | \"npx\" | \"auto\" } }"
echo ""
echo "To bypass the hook (use sparingly):"
echo "  git commit --no-verify"
echo ""
echo "To uninstall:"
echo "  rm $PRE_COMMIT_HOOK"
echo ""

