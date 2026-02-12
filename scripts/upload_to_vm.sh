chmod 600 /Users/Apple/Downloads/ssh-key-2026-01-14.key

cd /Users/Apple/Desktop/Security_platform
DEPLOY_TARGET="ubuntu@158.180.52.90" \
DEPLOY_DIR="~/Security_platform" \
SSH_OPTS="-i /Users/Apple/Downloads/ssh-key-2026-01-14.key -o IdentitiesOnly=yes" \
bash /Users/Apple/Desktop/Security_platform/scripts/ship-to-server.sh
