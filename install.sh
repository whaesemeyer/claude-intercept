#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DEST_DIR="$HOME/.claude/skills/intercept"
SKILL_DEST="$SKILL_DEST_DIR/SKILL.md"

echo ""
echo "  ⊕ Claude Intercept — Installer"
echo ""

# ── Check Node.js ─────────────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  echo "  ✗ Node.js not found. Install from https://nodejs.org (v22.5+)"
  exit 1
fi

NODE_VER=$(node -e "console.log(process.versions.node.split('.')[0])")
NODE_MINOR=$(node -e "console.log(process.versions.node.split('.')[1])")
if [ "$NODE_VER" -lt 22 ] || { [ "$NODE_VER" -eq 22 ] && [ "$NODE_MINOR" -lt 5 ]; }; then
  echo "  ✗ Node.js v22.5+ required (found $(node --version))"
  echo "    Requires built-in node:sqlite (available from v22.5). Install from https://nodejs.org"
  exit 1
fi
echo "  ✓ Node.js $(node --version)"

# ── Install npm dependencies ──────────────────────────────────────────────────
echo "  → Installing dependencies…"
cd "$SCRIPT_DIR"

if npm install --silent; then
  echo "  ✓ Dependencies installed"
else
  echo "  ! npm install failed, trying with verbose output:"
  npm install
fi

# ── Make CLI executable ───────────────────────────────────────────────────────
chmod +x "$SCRIPT_DIR/src/cli.js"
echo "  ✓ CLI ready"

# ── Install Claude Code skill (templated with real install path) ──────────────
mkdir -p "$SKILL_DEST_DIR"
# Substitute the actual install path so /intercept works from any location
sed "s|~/claude_intercept|${SCRIPT_DIR}|g" "$SCRIPT_DIR/skill.md" > "$SKILL_DEST"
echo "  ✓ Skill installed → $SKILL_DEST"
echo "    Use /intercept in Claude Code to invoke it"

# ── Ensure runtime dirs exist (excluded from git) ─────────────────────────────
mkdir -p "$SCRIPT_DIR/captures" "$SCRIPT_DIR/certs"

# ── Optional: link CLI to PATH ────────────────────────────────────────────────
LINK_PATH="/usr/local/bin/claude-intercept"
if ln -sf "$SCRIPT_DIR/src/cli.js" "$LINK_PATH" 2>/dev/null; then
  echo "  ✓ Linked: claude-intercept available globally"
elif sudo ln -sf "$SCRIPT_DIR/src/cli.js" "$LINK_PATH" 2>/dev/null; then
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
echo "  Or from Claude Code:"
echo "    /intercept"
echo ""
