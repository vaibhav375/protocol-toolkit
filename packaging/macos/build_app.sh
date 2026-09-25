#!/usr/bin/env bash
# Build "Protocol Toolkit.app" (and a zip of it) into packaging/macos/dist.
# Needs: pip install pyinstaller pywebview fastapi uvicorn websockets aioquic hpack brotli certifi
set -euo pipefail
cd "$(dirname "$0")"

if [ "${SKIP_UI_BUILD:-0}" != "1" ] && command -v npm >/dev/null; then
  (cd ../../web && npm ci --no-audit --no-fund && npm run build)
fi
[ -f AppIcon.icns ] || python3 make_icon.py

python3 -m PyInstaller --noconfirm --clean --distpath dist --workpath build ProtocolToolkit.spec
ditto -c -k --keepParent "dist/Protocol Toolkit.app" "dist/Protocol-Toolkit-macOS.zip"
echo "Built: $(pwd)/dist/Protocol Toolkit.app"
