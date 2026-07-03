#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

HOST="${DRAFTPAPER_HOST:-127.0.0.1}"
PORT="${DRAFTPAPER_PORT:-4888}"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
else
  PYTHON_BIN="${PYTHON_BIN:-python3}"
fi

export DRAFTPAPER_SEARCH_PROVIDERS="${DRAFTPAPER_SEARCH_PROVIDERS:-semantic_scholar,arxiv}"
export DRAFTPAPER_SEARCH_TIMEOUT_SECONDS="${DRAFTPAPER_SEARCH_TIMEOUT_SECONDS:-6}"
export DRAFTPAPER_SEARCH_MAX_QUERIES="${DRAFTPAPER_SEARCH_MAX_QUERIES:-4}"

port_listener_pids() {
  lsof -nP -tiTCP:"${PORT}" -sTCP:LISTEN 2>/dev/null || true
}

process_cwd() {
  local pid="$1"
  lsof -a -p "${pid}" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -n 1 || true
}

stop_existing_project_listener() {
  local pid
  for pid in $(port_listener_pids); do
    if [ "${pid}" = "$$" ]; then
      continue
    fi
    local cwd
    local real_cwd
    cwd="$(process_cwd "${pid}")"
    real_cwd="$(cd "${cwd}" 2>/dev/null && pwd -P || true)"
    if [ "${real_cwd}" = "${ROOT_DIR}" ]; then
      echo "Stopping existing DraftpaperLoop listener on port ${PORT}: pid=${pid}"
      kill "${pid}" 2>/dev/null || true
    else
      echo "Refusing to start: port ${PORT} is occupied by pid=${pid}, cwd=${cwd}" >&2
      exit 1
    fi
  done

  local deadline=$((SECONDS + 8))
  while [ "${SECONDS}" -lt "${deadline}" ]; do
    if [ -z "$(port_listener_pids)" ]; then
      return
    fi
    sleep 0.25
  done

  for pid in $(port_listener_pids); do
    if [ "${pid}" != "$$" ]; then
      echo "Force stopping DraftpaperLoop listener on port ${PORT}: pid=${pid}"
      kill -9 "${pid}" 2>/dev/null || true
    fi
  done
}

stop_existing_project_listener

exec "$PYTHON_BIN" "$ROOT_DIR/scripts/serviceconsole_app.py" --host "$HOST" --port "$PORT"
