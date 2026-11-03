#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT="both"
SKILLS_ONLY=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --agent)
      if [ "$#" -lt 2 ]; then echo "Missing --agent value (claude, codex, both)" >&2; exit 1; fi
      AGENT="$2"; shift 2 ;;
    --skills-only) SKILLS_ONLY=true; shift ;;
    -h|--help)
      echo "Usage: bash install.sh [--agent claude|codex|both] [--skills-only]"
      echo "Default: install both skills, dependencies, and CLI link."
      echo "--skills-only: install skills without npm, sudo, or runtime changes."
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done
case "$AGENT" in
  claude|codex|both) ;;
  *) echo "Unknown agent: $AGENT (expected claude, codex, both)" >&2; exit 1 ;;
esac

echo ""
echo "  ⊕ Claude Intercept — Installer"
echo ""

# ── Check Node.js ─────────────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  echo "  ✗ Node.js not found. Install from https://nodejs.org (v22.15+)"
  exit 1
fi

NODE_VER=$(node -e "console.log(process.versions.node.split('.')[0])")
NODE_MINOR=$(node -e "console.log(process.versions.node.split('.')[1])")
if [ "$NODE_VER" -lt 22 ] || { [ "$NODE_VER" -eq 22 ] && [ "$NODE_MINOR" -lt 15 ]; }; then
  echo "  ✗ Node.js v22.15+ required (found $(node --version))"
  echo "    Requires built-in node:sqlite (available from v22.5). Install from https://nodejs.org"
  exit 1
fi
echo "  ✓ Node.js $(node --version)"

if [ "$SKILLS_ONLY" = true ]; then
  node "$SCRIPT_DIR/scripts/install-skills.js" "$AGENT"
  exit 0
fi

# ── Install exactly the reviewed dependency tree ─────────────────────────────
echo "  → Installing dependencies…"
cd "$SCRIPT_DIR"

if npm ci --ignore-scripts; then
  echo "  ✓ Dependencies installed"
else
  echo "  ✗ Dependency installation failed. Check package-lock.json and npm output." >&2
  exit 1
fi

# ── Make CLI executable ───────────────────────────────────────────────────────
chmod +x "$SCRIPT_DIR/src/cli.js"
echo "  ✓ CLI ready"

# ── Install agent skills with the real checkout path ─────────────────────────
node "$SCRIPT_DIR/scripts/install-skills.js" "$AGENT"

# ── Ensure private runtime dirs exist (excluded from git) ─────────────────────
if [ -L "$SCRIPT_DIR/captures" ] || [ -L "$SCRIPT_DIR/certs" ]; then
  echo "  ✗ Refusing symlinked captures or certs directory." >&2
  exit 1
fi
mkdir -p "$SCRIPT_DIR/captures" "$SCRIPT_DIR/certs"
chmod 700 "$SCRIPT_DIR/captures" "$SCRIPT_DIR/certs"

# ── Optional: link CLI to PATH ────────────────────────────────────────────────
LINK_PATH="/usr/local/bin/claude-intercept"
if [ -e "$LINK_PATH" ] || [ -L "$LINK_PATH" ]; then
  if [ -L "$LINK_PATH" ] && [ "$(readlink "$LINK_PATH")" = "$SCRIPT_DIR/src/cli.js" ]; then
    echo "  ✓ Linked: claude-intercept available globally"
  else
    echo "  ! Skipped global link — $LINK_PATH already exists"
  fi
elif ln -s "$SCRIPT_DIR/src/cli.js" "$LINK_PATH" 2>/dev/null; then
  echo "  ✓ Linked: claude-intercept available globally"
else
  echo "  ! Skipped global link — run with: node $SCRIPT_DIR/src/cli.js"
fi

echo ""
echo "  ✓ Installation complete!"
echo ""
echo "  Quick start:"
echo "    claude-intercept start"
echo ""
if [ "$AGENT" != codex ]; then
  echo "  Claude Code: /intercept"
fi
if [ "$AGENT" != claude ]; then
  echo '  Codex: $intercept (restart Codex if it is not listed yet)'
fi
echo ""
