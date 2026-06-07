#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PCTL_BIN="/usr/local/bin/pctl"
SUDO=""
if [[ ! -w "$(dirname "$PCTL_BIN")" ]]; then
  SUDO="sudo"
fi

#echo "[core-api] running tests..."
#docker compose --profile test run --rm --remove-orphans pctl-tests

echo "[core-api] rebuilding local services..."
docker compose up -d --build --remove-orphans mysql core-api adminer

echo "[core-api] installing pctl launcher to $PCTL_BIN"
$SUDO tee "$PCTL_BIN" >/dev/null <<LAUNCHER
#!/usr/bin/env bash
set -euo pipefail
exec python3 "$ROOT_DIR/wrapper/pctl.py" "\$@"
LAUNCHER
$SUDO chmod 0755 "$PCTL_BIN"

echo "[core-api] done"
echo "[core-api] health: http://127.0.0.1:8080/health"
echo "[core-api] adminer: http://127.0.0.1:8088"
echo "[core-api] pctl: $PCTL_BIN"
