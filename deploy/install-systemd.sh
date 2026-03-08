#!/usr/bin/env bash
set -euo pipefail

APP_USER="${APP_USER:-ubuntu}"
APP_GROUP="${APP_GROUP:-$APP_USER}"
REPO_DIR="${REPO_DIR:-/home/${APP_USER}/barrybot}"
PORT="${PORT:-5001}"

export APP_USER APP_GROUP REPO_DIR PORT

render() {
  local src="$1"
  local dest="$2"
  python3 - "${src}" <<'PY' | sudo tee "${dest}" > /dev/null
from pathlib import Path
from string import Template
import os
import sys

src = Path(sys.argv[1]).read_text()
print(Template(src).safe_substitute(os.environ), end="")
PY
}

render "${REPO_DIR}/deploy/systemd/agentsec-backend.service.tmpl" "/etc/systemd/system/agentsec-backend.service"
render "${REPO_DIR}/deploy/systemd/barrybot-autopull.service.tmpl" "/etc/systemd/system/barrybot-autopull.service"
sudo install -m 0644 "${REPO_DIR}/deploy/systemd/barrybot-autopull.timer" "/etc/systemd/system/barrybot-autopull.timer"
sudo systemctl daemon-reload
