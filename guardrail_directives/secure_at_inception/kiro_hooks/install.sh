#!/bin/bash
#
# Snyk Security Hook Installer (Distribution Version)
# ====================================================
#
# Installs both git pre-commit hook and Kiro background scanner.
# This version copies files instead of symlinking for distribution.
#
# Usage:
#   ./install_distribution.sh
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

# Run Snyk hook (copied version)
exec python3 "$(dirname "$0")/pre-commit.snyk"
CHAIN_EOF
                chmod +x "$PRE_COMMIT_HOOK"
                
                # Copy Snyk hook to a different name for chaining
                cp "$SCRIPT_DIR/git/pre-commit" "$HOOKS_DIR/pre-commit.snyk"
                chmod +x "$HOOKS_DIR/pre-commit.snyk"
                
                # Copy lib files
                mkdir -p "$HOOKS_DIR/lib"
                cp "$SCRIPT_DIR/git/lib/"*.py "$HOOKS_DIR/lib/"
                chmod +x "$HOOKS_DIR/lib/"*.py
                
                echo -e "${GREEN}✓${NC} Chained hook installed"
                
                # Skip normal installation
                CHAINED=true
                ;;
            *)
                echo "  Installation cancelled"
                exit 0
                ;;
        esac
    fi
fi

# Install the hook (copy instead of symlink for distribution)
if [ "$CHAINED" != "true" ]; then
    echo ""
    echo "Installing pre-commit hook..."
    
    HOOK_SOURCE="$SCRIPT_DIR/git/pre-commit"
    
    if [ -f "$HOOK_SOURCE" ]; then
        # Copy the hook file
        cp "$HOOK_SOURCE" "$PRE_COMMIT_HOOK"
        chmod +x "$PRE_COMMIT_HOOK"
        echo -e "${GREEN}✓${NC} Pre-commit hook copied to: $PRE_COMMIT_HOOK"
        
        # Copy the lib directory
        mkdir -p "$HOOKS_DIR/lib"
        cp "$SCRIPT_DIR/git/lib/"*.py "$HOOKS_DIR/lib/"
        chmod +x "$HOOKS_DIR/lib/"*.py
        echo -e "${GREEN}✓${NC} Hook libraries copied to: $HOOKS_DIR/lib/"
    else
        echo -e "${RED}✗ Error: Hook source not found: $HOOK_SOURCE${NC}"
        exit 1
    fi
fi

# Install Kiro hooks
echo ""
echo "Installing Kiro background scanner..."

if [ ! -d "$REPO_ROOT/.kiro" ]; then
    echo -e "${YELLOW}⚠ .kiro directory not found${NC}"
    echo "  This doesn't appear to be a Kiro workspace"
    read -p "Create .kiro/hooks/ directory? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        mkdir -p "$REPO_ROOT/.kiro/hooks"
    else
        echo -e "${YELLOW}⚠ Skipping Kiro hooks installation${NC}"
        echo ""
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║     GIT HOOKS INSTALLATION COMPLETE                        ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
        exit 0
    fi
fi

# Copy Kiro background scanner
mkdir -p "$REPO_ROOT/.kiro/hooks"
cp "$SCRIPT_DIR/kiro/background_scanner.py" "$REPO_ROOT/.kiro/hooks/kiro_background_scanner.py"
chmod +x "$REPO_ROOT/.kiro/hooks/kiro_background_scanner.py"

# Create the Kiro hook configuration
cat > "$REPO_ROOT/.kiro/hooks/background-security-scan.kiro.hook" << 'EOF'
{
  "enabled": true,
  "name": "Background Security Scanner",
  "description": "Automatically runs background security scans when code files are saved for faster pre-commit hooks",
  "version": "1",
  "when": {
    "type": "fileEdited",
    "patterns": [
      "*.js",
      "*.ts",
      "*.tsx",
      "*.jsx",
      "*.py",
      "*.java",
      "*.kt",
      "*.go",
      "*.rb",
      "*.php",
      "*.cs",
      "*.swift",
      "*.c",
      "*.cpp",
      "*.h",
      "*.hpp",
      "package.json",
      "package-lock.json",
      "yarn.lock",
      "requirements.txt",
      "Pipfile",
      "pyproject.toml",
      "pom.xml",
      "build.gradle",
      "Gemfile",
      "composer.json"
    ]
  },
  "then": {
    "type": "askAgent",
    "prompt": "DO NOT OPEN A NEW PROMPT WINDOW. \nMAKE SURE TO: Run background security scan silently: python3 .kiro/hooks/kiro_background_scanner.py\nRun the background scan ON THE FILE THAT WAS JUST EDITED THAT TRIGGERED THIS SCANNER""
  }
}
EOF

echo -e "${GREEN}✓${NC} Kiro hooks installed to: $REPO_ROOT/.kiro/hooks/"

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     INSTALLATION COMPLETE                                  ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "The Snyk security hooks are now active."
echo ""
echo "What happens:"
echo "  • Git: Pre-commit hook scans for NEW vulnerabilities (SAST/SCA)"
echo "  • Kiro: Background scanner caches results on file save"
echo "  • Commits are blocked if new issues are introduced"
echo ""
echo "Configuration (environment variables):"
echo "  • SNYK_HOOK_DEBUG=1  - Enable verbose output"
echo "  • SNYK_HOOK_QUICK=1  - Skip old version comparison (faster)"
echo ""
echo "To bypass the hook (use sparingly):"
echo "  git commit --no-verify"
echo ""
echo "To uninstall:"
echo "  rm $PRE_COMMIT_HOOK"
echo "  rm -rf $REPO_ROOT/.kiro/hooks/"
echo ""
