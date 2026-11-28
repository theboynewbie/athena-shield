#!/bin/sh
set -e
DATA_DIR="${DATA_DIR:-/data}"
if [ "$(id -u)" = "0" ]; then
    mkdir -p "$DATA_DIR"
    chown -R athena:athena "$DATA_DIR"
    exec su-exec athena:athena /app/athena-shield "$@"
fi
exec /app/athena-shield "$@"
