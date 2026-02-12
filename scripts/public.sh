#!/usr/bin/env bash
set -euo pipefail

# One entrypoint for common public VM operations (run from your laptop).
#
# Usage:
#   DEPLOY_TARGET="ubuntu@158.180.52.90" \
#   SSH_OPTS="-i /path/to/key -o IdentitiesOnly=yes" \
#   bash scripts/public.sh <command> [args...]
#
# Commands:
#   deploy                 Ship repo + update stack (calls scripts/deploy-public.sh)
#   doctor                 Run VM doctor (scripts/vm-doctor-public.sh) on the VM
#   status                 Run VM status (scripts/vm-status-public.sh) on the VM
#   logs [svc...]          Tail logs (scripts/vm-logs-public.sh) on the VM
#   backup                 Create a backup on the VM (scripts/backup-public.sh)
#   update                 Rebuild/restart public stack on the VM (no shipping)
#   update-tools           Update VM Docker CLI plugins (compose + buildx)
#   upgrade                Update tools + update stack + run smoke (interactive sudo if needed)
#   install-systemd        Install systemd units (stack autostart + daily backups) on the VM
#   tunnel                 Open SSH tunnels for Grafana/Prometheus/Alertmanager/Jaeger
#   smoke [url]            Smoke test public HTTPS (defaults to https://$PUBLIC_DOMAIN)
#   init                   Create a local .public.env from .public.env.example (for convenience)
#   ssh                    Open an interactive SSH session to the VM
#
# Env:
#   DEPLOY_TARGET (required for VM commands)
#   DEPLOY_DIR (default: ~/Security_platform)
#   SSH_OPTS (ssh args)
#
# For "update":
#   UPDATE_DOCKER_PLUGINS=1   (best-effort; requires passwordless sudo on the VM)
#   RUN_SMOKE=1               (runs scripts/smoke-public.sh after update)
#
# For "smoke":
#   PUBLIC_DOMAIN=api.example.com   (or pass explicit URL)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Optional local convenience env file. This lets you avoid re-typing DEPLOY_TARGET/SSH_OPTS.
# The file is NOT shipped to the VM (ship script excludes it by default if you add it).
# Example: ${REPO_ROOT}/.public.env
#   DEPLOY_TARGET="ubuntu@158.180.52.90"
#   DEPLOY_DIR="~/Security_platform"
#   SSH_OPTS="-i /path/to/key -o IdentitiesOnly=yes"
#   PUBLIC_DOMAIN="api.example.com"
orig_deploy_target_set="${DEPLOY_TARGET+x}"
orig_deploy_target="${DEPLOY_TARGET-}"
orig_deploy_dir_set="${DEPLOY_DIR+x}"
orig_deploy_dir="${DEPLOY_DIR-}"
orig_ssh_opts_set="${SSH_OPTS+x}"
orig_ssh_opts="${SSH_OPTS-}"

PUBLIC_ENV_FILE="${PUBLIC_ENV_FILE:-${REPO_ROOT}/.public.env}"
if [[ -f "$PUBLIC_ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$PUBLIC_ENV_FILE"
fi

# Env vars passed inline when invoking the script should override the env file.
if [[ -n "$orig_deploy_target_set" ]]; then DEPLOY_TARGET="$orig_deploy_target"; fi
if [[ -n "$orig_deploy_dir_set" ]]; then DEPLOY_DIR="$orig_deploy_dir"; fi
if [[ -n "$orig_ssh_opts_set" ]]; then SSH_OPTS="$orig_ssh_opts"; fi

DEPLOY_TARGET="${DEPLOY_TARGET:-}"
DEPLOY_DIR="${DEPLOY_DIR:-~/Security_platform}"
SSH_OPTS="${SSH_OPTS:-}"

cmd="${1:-}"
shift || true

usage() {
  cat <<'EOF' >&2
Usage:
  DEPLOY_TARGET="ubuntu@<VM_IP>" SSH_OPTS="..." bash scripts/public.sh <command> [args...]

Commands:
  init
  deploy
  doctor
  status
  logs [svc...]
  backup
  update
  update-tools
  upgrade
  install-systemd
  tunnel
  smoke [url]
  ssh

Tip:
  Create .public.env in the repo root to avoid re-typing DEPLOY_TARGET/SSH_OPTS.
EOF
}

require_target() {
  if [[ -z "${DEPLOY_TARGET//[[:space:]]/}" ]]; then
    echo "ERROR: DEPLOY_TARGET is required (e.g., ubuntu@158.180.52.90)." >&2
    echo "Fix options:" >&2
    echo "  1) Create ${PUBLIC_ENV_FILE} (see: ${REPO_ROOT}/.public.env.example)" >&2
    echo "  2) Or run inline, e.g.:" >&2
    echo "     DEPLOY_TARGET=\"ubuntu@158.180.52.90\" SSH_OPTS=\"-i /path/to/key -o IdentitiesOnly=yes\" bash scripts/public.sh doctor" >&2
    exit 1
  fi
}

ssh_cmd=(ssh)
if [[ -n "$SSH_OPTS" ]]; then
  # shellcheck disable=SC2206
  ssh_cmd+=($SSH_OPTS)
fi

ssh_tty_cmd=("${ssh_cmd[@]}" -tt)

remote() {
  local remote_cmd="$1"
  require_target
  "${ssh_cmd[@]}" "$DEPLOY_TARGET" "set -euo pipefail; cd ${DEPLOY_DIR}; ${remote_cmd}"
}

remote_tty() {
  local remote_cmd="$1"
  require_target
  "${ssh_tty_cmd[@]}" "$DEPLOY_TARGET" "set -euo pipefail; cd ${DEPLOY_DIR}; ${remote_cmd}"
}

case "$cmd" in
  init)
    if [[ -f "${REPO_ROOT}/.public.env" ]]; then
      echo "OK: ${REPO_ROOT}/.public.env already exists."
      exit 0
    fi
    if [[ -f "${REPO_ROOT}/.public.env.example" ]]; then
      cp "${REPO_ROOT}/.public.env.example" "${REPO_ROOT}/.public.env"
      echo "Created: ${REPO_ROOT}/.public.env"
      echo "Edit it, then run: bash scripts/public.sh doctor"
      exit 0
    fi
    echo "ERROR: Missing ${REPO_ROOT}/.public.env.example" >&2
    exit 1
    ;;

  deploy)
    DEPLOY_TARGET="$DEPLOY_TARGET" DEPLOY_DIR="$DEPLOY_DIR" SSH_OPTS="$SSH_OPTS" \
      bash "${REPO_ROOT}/scripts/deploy-public.sh"
    ;;

  doctor)
    remote "bash scripts/vm-doctor-public.sh"
    ;;

  status)
    remote "bash scripts/vm-status-public.sh"
    ;;

  logs)
    # shellcheck disable=SC2145
    remote "bash scripts/vm-logs-public.sh $*"
    ;;

  backup)
    retention="${BACKUP_RETENTION_DAYS:-14}"
    remote "BACKUP_RETENTION_DAYS=${retention} bash scripts/backup-public.sh"
    ;;

  update)
    update_plugins="${UPDATE_DOCKER_PLUGINS:-0}"
    run_smoke="${RUN_SMOKE:-0}"
    if [[ "$update_plugins" == "1" ]]; then
      set +e
      remote "sudo -n bash scripts/update-docker-cli-plugins.sh" >/dev/null 2>&1
      rc=$?
      set -e
      if [[ "$rc" != "0" ]]; then
        echo "NOTE: docker CLI plugin update needs sudo on the VM; re-running with an interactive TTY." >&2
        remote_tty "sudo bash scripts/update-docker-cli-plugins.sh"
      fi
      remote "RUN_SMOKE=${run_smoke} bash scripts/vm-update-public.sh"
    else
      remote "RUN_SMOKE=${run_smoke} bash scripts/vm-update-public.sh"
    fi
    ;;

  update-tools)
    set +e
    remote "sudo -n bash scripts/update-docker-cli-plugins.sh" >/dev/null 2>&1
    rc=$?
    set -e
    if [[ "$rc" == "0" ]]; then
      echo "OK: Docker CLI plugins updated (non-interactive sudo)."
      exit 0
    fi
    echo "NOTE: docker CLI plugin update needs sudo on the VM; running with an interactive TTY." >&2
    remote_tty "sudo bash scripts/update-docker-cli-plugins.sh"
    ;;

  upgrade)
    remote_tty "UPDATE_DOCKER_PLUGINS=1 RUN_SMOKE=1 bash scripts/vm-update-public.sh"
    ;;

  install-systemd)
    retention="${BACKUP_RETENTION_DAYS:-14}"
    disable_caddy="${DISABLE_CADDY:-1}"
    stack_name="${STACK_SERVICE_NAME:-security-platform-public}"
    backup_name="${BACKUP_SERVICE_NAME:-security-platform-public-backup}"
    remote_tty "SERVICE_NAME=${stack_name} DISABLE_CADDY=${disable_caddy} sudo bash scripts/install-systemd-public.sh; SERVICE_NAME=${backup_name} BACKUP_RETENTION_DAYS=${retention} sudo bash scripts/install-systemd-backup-public.sh"
    ;;

  tunnel)
    require_target
    DEPLOY_TARGET="$DEPLOY_TARGET" SSH_OPTS="$SSH_OPTS" bash "${REPO_ROOT}/scripts/tunnel-observability.sh" "$DEPLOY_TARGET"
    ;;

  smoke)
    url="${1:-}"
    if [[ -z "${url//[[:space:]]/}" ]]; then
      if [[ -n "${PUBLIC_DOMAIN:-}" ]]; then
        url="https://${PUBLIC_DOMAIN}"
      else
        # Best-effort read from local env file
        if [[ -f "${REPO_ROOT}/deploy/docker/.env" ]]; then
          domain="$(grep -E "^[[:space:]]*PUBLIC_DOMAIN=" "${REPO_ROOT}/deploy/docker/.env" | tail -n 1 | sed -E 's/^[[:space:]]*PUBLIC_DOMAIN=//' | tr -d '\r' | sed -E 's/^\"|\"$//g')"
          if [[ -n "${domain//[[:space:]]/}" ]]; then
            url="https://${domain}"
          fi
        fi
      fi
    fi
    if [[ -z "${url//[[:space:]]/}" ]]; then
      echo "ERROR: Provide a URL (or set PUBLIC_DOMAIN)." >&2
      echo "Example: bash scripts/public.sh smoke https://api.example.com" >&2
      exit 1
    fi
    bash "${REPO_ROOT}/scripts/smoke-public.sh" "$url"
    ;;

  ssh)
    require_target
    exec "${ssh_cmd[@]}" "$DEPLOY_TARGET"
    ;;

  ""|-h|--help|help)
    usage
    exit 0
    ;;

  *)
    echo "ERROR: Unknown command: $cmd" >&2
    usage
    exit 1
    ;;
esac
