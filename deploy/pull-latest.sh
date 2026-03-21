#!/usr/bin/env bash
set -euo pipefail

APP_USER="${APP_USER:-ubuntu}"
APP_GROUP="${APP_GROUP:-$APP_USER}"
REPO_DIR="${REPO_DIR:-/home/${APP_USER}/barrybot}"
BRANCH="${BRANCH:-main}"
MIDDLEWARE_DIR="${LANGCHAIN_MIDDLEWARE_DIR:-/home/${APP_USER}/code/ai-defense-langchain-middleware-personal}"

if [ ! -d "${REPO_DIR}/.git" ]; then
  echo "Repo not found at ${REPO_DIR}" >&2
  exit 1
fi

export APP_USER APP_GROUP REPO_DIR

CURRENT_HEAD="$(git -C "${REPO_DIR}" -c safe.directory="${REPO_DIR}" rev-parse HEAD)"
git -C "${REPO_DIR}" -c safe.directory="${REPO_DIR}" fetch origin "${BRANCH}"
REMOTE_HEAD="$(git -C "${REPO_DIR}" -c safe.directory="${REPO_DIR}" rev-parse FETCH_HEAD)"

if [ "${CURRENT_HEAD}" = "${REMOTE_HEAD}" ]; then
  echo "No update needed."
  exit 0
fi

git -C "${REPO_DIR}" -c safe.directory="${REPO_DIR}" pull --ff-only origin "${BRANCH}"
python3 -m venv "${REPO_DIR}/venv"
"${REPO_DIR}/venv/bin/pip" install -q --upgrade pip
"${REPO_DIR}/venv/bin/pip" install -q -r "${REPO_DIR}/backend/requirements.txt"

if [ -x "${MIDDLEWARE_DIR}/.venv/bin/python" ]; then
  "${MIDDLEWARE_DIR}/.venv/bin/python" -m pip install -q --upgrade pip
  "${MIDDLEWARE_DIR}/.venv/bin/python" -m pip install -q cisco-aidefense-sdk==2.1.0
fi

"${REPO_DIR}/deploy/install-systemd.sh"
systemctl restart agentsec-backend
sleep 3
curl -fsS http://127.0.0.1:5001/api/health >/dev/null
