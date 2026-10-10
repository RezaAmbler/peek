#!/usr/bin/env bash
# PostToolUse hook: auto-format (Prettier) and lint-fix (ESLint) frontend source
# files after Claude edits them. Reads the hook JSON payload from stdin, extracts
# the edited file path, and only acts on files under frontend/src using the
# project-local binaries. Always exits 0 so it never blocks the edit.
set -euo pipefail

input="$(cat)"
file="$(printf '%s' "$input" | python3 -c 'import sys,json
try:
    print(json.load(sys.stdin).get("tool_input",{}).get("file_path",""))
except Exception:
    print("")' 2>/dev/null || true)"

[ -n "$file" ] || exit 0
[ -f "$file" ] || exit 0

# Only handle frontend source files.
case "$file" in
  *"/frontend/src/"*) ;;
  *) exit 0 ;;
esac
case "$file" in
  *.ts|*.tsx|*.css|*.json) ;;
  *) exit 0 ;;
esac

fe="${file%%/frontend/src/*}/frontend"

if [ -x "$fe/node_modules/.bin/prettier" ]; then
  "$fe/node_modules/.bin/prettier" --write "$file" >/dev/null 2>&1 || true
fi

case "$file" in
  *.ts|*.tsx)
    if [ -x "$fe/node_modules/.bin/eslint" ]; then
      "$fe/node_modules/.bin/eslint" --fix "$file" >/dev/null 2>&1 || true
    fi
    ;;
esac

exit 0
