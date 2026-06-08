#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PCTL_BIN="/usr/local/bin/pctl"
INSTALL_PCTL=1
SUDO=""
IMPORT_MODE="${PCTL_IMPORT_SSH_CONFIG_MODE:-off}"
IMPORT_MARKER="${PCTL_IMPORT_SSH_CONFIG_MARKER:-### START FLINT ###}"
export PCTL_IMPORT_SSH_CONFIG_MARKER="$IMPORT_MARKER"
if [[ ! -w "$(dirname "$PCTL_BIN")" ]]; then
  if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    SUDO="sudo"
  else
    INSTALL_PCTL=0
  fi
fi

#echo "[core-api] running tests..."
#docker compose --profile test run --rm --remove-orphans pctl-tests

echo "[core-api] rebuilding local services..."
echo "[core-api] ssh import mode: $IMPORT_MODE"
echo "[core-api] ssh import marker: $IMPORT_MARKER"
docker compose up -d --build --remove-orphans mysql core-api web adminer

if [[ "$INSTALL_PCTL" -eq 1 ]]; then
  echo "[core-api] installing pctl launcher to $PCTL_BIN"
  $SUDO tee "$PCTL_BIN" >/dev/null <<LAUNCHER
#!/usr/bin/env bash
set -euo pipefail
exec python3 "$ROOT_DIR/wrapper/pctl.py" "\$@"
LAUNCHER
  $SUDO chmod 0755 "$PCTL_BIN"
else
  echo "[core-api] skipping pctl install: no write access to $(dirname "$PCTL_BIN") and passwordless sudo is unavailable"
fi

echo "[core-api] done"
echo "[core-api] health: http://127.0.0.1:8080/health"
echo "[core-api] web: http://127.0.0.1:8081"
echo "[core-api] adminer: http://127.0.0.1:8088"
echo "[core-api] pctl: $PCTL_BIN"
echo "[core-api] import once: PCTL_IMPORT_SSH_CONFIG_MODE=once bash ./scripts/up.sh"
echo "[core-api] import always: PCTL_IMPORT_SSH_CONFIG_MODE=always bash ./scripts/up.sh"
