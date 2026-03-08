#!/usr/bin/env bash
set -euo pipefail

APP_USER="${APP_USER:-ubuntu}"
APP_GROUP="${APP_GROUP:-$APP_USER}"
REPO_DIR="${REPO_DIR:-/home/${APP_USER}/barrybot}"
REPO_URL="${REPO_URL:-https://github.com/barryqy/barrybot.git}"
BRANCH="${BRANCH:-main}"

export APP_USER APP_GROUP REPO_DIR

sudo apt-get update -qq
sudo apt-get install -y -qq git curl python3 python3-pip python3-venv

if [ ! -d "${REPO_DIR}/.git" ]; then
  sudo mkdir -p "$(dirname "${REPO_DIR}")"
  sudo chown -R "${APP_USER}:${APP_GROUP}" "$(dirname "${REPO_DIR}")"
  sudo -u "${APP_USER}" git clone --branch "${BRANCH}" "${REPO_URL}" "${REPO_DIR}"
else
  sudo -u "${APP_USER}" git -C "${REPO_DIR}" pull --ff-only origin "${BRANCH}"
fi

if [ -f "/home/${APP_USER}/agentsec/.env" ] && [ ! -f "${REPO_DIR}/.env" ]; then
  sudo cp "/home/${APP_USER}/agentsec/.env" "${REPO_DIR}/.env"
  sudo chown "${APP_USER}:${APP_GROUP}" "${REPO_DIR}/.env"
fi

sudo python3 -m venv "${REPO_DIR}/venv"
sudo "${REPO_DIR}/venv/bin/pip" install -q --upgrade pip
sudo "${REPO_DIR}/venv/bin/pip" install -q -r "${REPO_DIR}/backend/requirements.txt"

sudo "${REPO_DIR}/deploy/install-systemd.sh"
sudo systemctl enable agentsec-backend
sudo systemctl restart agentsec-backend
sudo systemctl enable --now barrybot-autopull.timer

sleep 3
curl -fsS http://127.0.0.1:5001/api/health
