#!/bin/sh
# Entrypoint for the PEEK Celery worker / beat image.
#
# The image is started as root only long enough to hand the shared data volume
# to the unprivileged "peek" user, then drops privileges for good. Scanners that
# need raw sockets (nmap -sS/-sU, masscan) get them from file capabilities set
# in the image, not from root or sudo.
#
# Set PEEK_WORKER_RUN_AS_ROOT=1 to keep the old behaviour (worker runs as root).
set -eu

RUN_USER=peek
DATA_DIR="${PEEK_DATA_DIR:-/app/data}"

if [ "$(id -u)" != "0" ]; then
    # Already unprivileged (e.g. `user:` set in compose): nothing to drop.
    exec "$@"
fi

if [ "${PEEK_WORKER_RUN_AS_ROOT:-0}" = "1" ]; then
    echo "peek-entrypoint: PEEK_WORKER_RUN_AS_ROOT=1 - running as root" >&2
    exec "$@"
fi

mkdir -p "$DATA_DIR"

# The API container (root) creates the SQLite database in the shared volume.
# On a brand-new install it may not exist yet; wait briefly so its ownership
# can be fixed before the worker needs to write to it.
if [ "${PEEK_WAIT_FOR_DB:-1}" = "1" ]; then
    waited=0
    while [ "$waited" -lt "${PEEK_WAIT_FOR_DB_SECONDS:-30}" ]; do
        if ls "$DATA_DIR"/*.db >/dev/null 2>&1; then
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done
fi

# Existing deployments have root-owned files here; root (the API container)
# can still read and write them after the change of owner.
chown -R "$RUN_USER:$RUN_USER" "$DATA_DIR" 2>/dev/null || \
    echo "peek-entrypoint: warning: could not chown $DATA_DIR" >&2

exec setpriv --reuid "$RUN_USER" --regid "$RUN_USER" --init-groups "$@"
