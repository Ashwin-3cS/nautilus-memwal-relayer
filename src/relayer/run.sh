#!/bin/sh
set -e

export LD_LIBRARY_PATH=/lib:$LD_LIBRARY_PATH

# VSOCK ports for outbound proxies (enclave → host → internet)
SUI_PROXY_VSOCK_PORT=8101
WALRUS_PUBLISHER_PROXY_VSOCK_PORT=8102
WALRUS_AGGREGATOR_PROXY_VSOCK_PORT=8103
POSTGRES_PROXY_VSOCK_PORT=8104
REDIS_PROXY_VSOCK_PORT=8105
OPENAI_PROXY_VSOCK_PORT=8106
SEAL_BASE_VSOCK_PORT=8107

DEFAULT_WALRUS_PUBLISHER_URL="https://publisher.walrus-mainnet.walrus.space"
DEFAULT_WALRUS_AGGREGATOR_URL="https://aggregator.walrus-mainnet.walrus.space"
DEFAULT_OPENAI_API_BASE="https://api.openai.com/v1"

extract_url_host() {
    printf '%s' "$1" | sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://(\[[^]]+\]|[^/:]+).*#\1#'
}

extract_url_port() {
    url="$1"
    explicit_port=$(printf '%s' "$url" | sed -nE 's#^[a-zA-Z][a-zA-Z0-9+.-]*://[^/:]+:([0-9]+).*$#\1#p')
    if [ -n "$explicit_port" ]; then
        printf '%s' "$explicit_port"
        return
    fi

    scheme=$(printf '%s' "$url" | sed -nE 's#^([a-zA-Z][a-zA-Z0-9+.-]*)://.*#\1#p')
    case "$scheme" in
        https) printf '443' ;;
        http) printf '80' ;;
        *) printf '443' ;;
    esac
}

setup_outbound_proxy() {
    name="$1"
    url="$2"
    loopback_ip="$3"
    vsock_port="$4"

    host=$(extract_url_host "$url")
    port=$(extract_url_port "$url")

    if [ -z "$host" ] || [ -z "$port" ]; then
        echo "Skipping outbound proxy for $name: could not parse URL '$url'"
        return
    fi

    busybox ip addr add "${loopback_ip}/32" dev lo 2>/dev/null || true
    echo "${loopback_ip} ${host}" >> /etc/hosts

    echo "Outbound proxy ready: ${host}:${port} -> ${loopback_ip}:${port} -> VSOCK:${vsock_port}"
    socat TCP-LISTEN:${port},bind=${loopback_ip},reuseaddr,fork VSOCK-CONNECT:3:${vsock_port} &
}

# ── Networking ──────────────────────────────────────────────────────────────
busybox ip addr add 127.0.0.1/32 dev lo
busybox ip link set dev lo up
echo "127.0.0.1   localhost" > /etc/hosts

# ── Enclave mode ─────────────────────────────────────────────────────────────
export ENCLAVE_MODE=true
echo "Enclave mode enabled"

# ── Receive config from parent via VSOCK port 7000 ──────────────────────────
# Parent sends newline-separated KEY=VALUE pairs, then closes the connection.
echo "Waiting for config on VSOCK port 7000..."
CONFIG=$(socat VSOCK-LISTEN:7000,reuseaddr - 2>/dev/null)

while IFS= read -r line; do
    case "$line" in
        *=*)
            key="${line%%=*}"
            val="${line#*=}"
            export "${key}=${val}"
            echo "Config loaded: ${key}=<set>"
            ;;
    esac
done << EOF
$CONFIG
EOF

# Apply defaults for optional env vars
export WALRUS_PUBLISHER_URL="${WALRUS_PUBLISHER_URL:-$DEFAULT_WALRUS_PUBLISHER_URL}"
export WALRUS_AGGREGATOR_URL="${WALRUS_AGGREGATOR_URL:-$DEFAULT_WALRUS_AGGREGATOR_URL}"
export OPENAI_API_BASE="${OPENAI_API_BASE:-$DEFAULT_OPENAI_API_BASE}"
export SIDECAR_URL="${SIDECAR_URL:-http://127.0.0.1:9000}"
export SIDECAR_SCRIPTS_DIR="${SIDECAR_SCRIPTS_DIR:-/scripts}"
export PORT="${PORT:-8000}"

# ── Outbound proxies ─────────────────────────────────────────────────────────
setup_outbound_proxy "sui"              "$SUI_RPC_URL"           "127.0.0.2" "$SUI_PROXY_VSOCK_PORT"
setup_outbound_proxy "walrus-publisher" "$WALRUS_PUBLISHER_URL"  "127.0.0.3" "$WALRUS_PUBLISHER_PROXY_VSOCK_PORT"
setup_outbound_proxy "walrus-aggregator" "$WALRUS_AGGREGATOR_URL" "127.0.0.4" "$WALRUS_AGGREGATOR_PROXY_VSOCK_PORT"

# Postgres: extract host:port from DATABASE_URL (postgresql://user:pass@host:port/db)
if [ -n "$DATABASE_URL" ]; then
    PG_HOST=$(printf '%s' "$DATABASE_URL" | sed -nE 's#^[^:]+://[^@]+@([^:/]+).*#\1#p')
    PG_PORT=$(printf '%s' "$DATABASE_URL" | sed -nE 's#^[^:]+://[^@]+@[^:]+:([0-9]+).*#\1#p')
    PG_PORT="${PG_PORT:-5432}"
    if [ -n "$PG_HOST" ]; then
        LOOPBACK_IP="127.0.0.5"
        busybox ip addr add "${LOOPBACK_IP}/32" dev lo 2>/dev/null || true
        echo "${LOOPBACK_IP} ${PG_HOST}" >> /etc/hosts
        echo "Outbound proxy ready: ${PG_HOST}:${PG_PORT} -> ${LOOPBACK_IP}:${PG_PORT} -> VSOCK:${POSTGRES_PROXY_VSOCK_PORT}"
        socat TCP-LISTEN:${PG_PORT},bind=${LOOPBACK_IP},reuseaddr,fork VSOCK-CONNECT:3:${POSTGRES_PROXY_VSOCK_PORT} &
        # Rewrite DATABASE_URL to point at the loopback alias
        export DATABASE_URL=$(printf '%s' "$DATABASE_URL" | sed "s|${PG_HOST}|${LOOPBACK_IP}|")
    fi
fi

# Redis: extract host:port from REDIS_URL (redis://host:port)
if [ -n "$REDIS_URL" ]; then
    REDIS_HOST=$(extract_url_host "$REDIS_URL")
    REDIS_PORT=$(printf '%s' "$REDIS_URL" | sed -nE 's#^[^:]+://[^:]+:([0-9]+).*#\1#p')
    REDIS_PORT="${REDIS_PORT:-6379}"
    if [ -n "$REDIS_HOST" ]; then
        LOOPBACK_IP="127.0.0.6"
        busybox ip addr add "${LOOPBACK_IP}/32" dev lo 2>/dev/null || true
        echo "${LOOPBACK_IP} ${REDIS_HOST}" >> /etc/hosts
        echo "Outbound proxy ready: ${REDIS_HOST}:${REDIS_PORT} -> ${LOOPBACK_IP}:${REDIS_PORT} -> VSOCK:${REDIS_PROXY_VSOCK_PORT}"
        socat TCP-LISTEN:${REDIS_PORT},bind=${LOOPBACK_IP},reuseaddr,fork VSOCK-CONNECT:3:${REDIS_PROXY_VSOCK_PORT} &
        export REDIS_URL=$(printf '%s' "$REDIS_URL" | sed "s|${REDIS_HOST}|${LOOPBACK_IP}|")
    fi
fi

setup_outbound_proxy "openai" "$OPENAI_API_BASE" "127.0.0.7" "$OPENAI_PROXY_VSOCK_PORT"

# SEAL key servers (comma-separated HTTPS URLs in SEAL_KEY_SERVER_URLS)
if [ -n "$SEAL_KEY_SERVER_URLS" ]; then
    SEAL_IDX=0
    # shellcheck disable=SC2039
    IFS=','
    for SEAL_URL in $SEAL_KEY_SERVER_URLS; do
        IFS=','  # reset IFS inside loop
        VSOCK_PORT=$((SEAL_BASE_VSOCK_PORT + SEAL_IDX))
        LOOPBACK_IP="127.0.$((8 + SEAL_IDX)).1"
        SEAL_HOST=$(extract_url_host "$SEAL_URL")
        SEAL_PORT=$(extract_url_port "$SEAL_URL")
        busybox ip addr add "${LOOPBACK_IP}/32" dev lo 2>/dev/null || true
        echo "${LOOPBACK_IP} ${SEAL_HOST}" >> /etc/hosts
        echo "Outbound proxy ready (SEAL ${SEAL_IDX}): ${SEAL_HOST}:${SEAL_PORT} -> ${LOOPBACK_IP}:${SEAL_PORT} -> VSOCK:${VSOCK_PORT}"
        socat TCP-LISTEN:${SEAL_PORT},bind=${LOOPBACK_IP},reuseaddr,fork VSOCK-CONNECT:3:${VSOCK_PORT} &
        SEAL_IDX=$((SEAL_IDX + 1))
    done
    unset IFS
fi

# ── TS sidecar ───────────────────────────────────────────────────────────────
echo "Starting TS sidecar..."
export SIDECAR_PORT=9000

cd /scripts && /usr/local/bin/node ./node_modules/.bin/tsx sidecar-server.ts > /tmp/sidecar.log 2>&1 &
SIDECAR_PID=$!
cd /

# Wait for sidecar health (max 15s)
SIDECAR_READY=0
for i in $(seq 1 30); do
    if wget -q -O- http://127.0.0.1:9000/health >/dev/null 2>&1; then
        SIDECAR_READY=1
        break
    fi
    sleep 0.5
done

if [ "$SIDECAR_READY" -eq 0 ]; then
    echo "ERROR: TS sidecar failed to start within 15s" >&2
    cat /tmp/sidecar.log >&2
    exit 1
fi
echo "TS sidecar ready (PID $SIDECAR_PID)"

# Forward sidecar logs to host via VSOCK port 5001
(tail -f /tmp/sidecar.log 2>/dev/null | socat - VSOCK-CONNECT:3:5001 2>/dev/null) &

# ── Expose relay server via VSOCK ────────────────────────────────────────────
# memwal_server listens on TCP 8000 (loopback); expose on VSOCK port 4000
socat VSOCK-LISTEN:4000,reuseaddr,fork TCP:localhost:8000 &

# ── Start Rust relay server ───────────────────────────────────────────────────
echo "Starting memwal relay server..."
/memwal_server > /tmp/server.log 2>&1 &
SERVER_PID=$!

echo "memwal relay server started: PID $SERVER_PID"

# Forward server logs to host via VSOCK port 5000
(tail -f /tmp/server.log 2>/dev/null | socat - VSOCK-CONNECT:3:5000 2>/dev/null) &

# ── Graceful shutdown ────────────────────────────────────────────────────────
trap 'kill $SIDECAR_PID $SERVER_PID 2>/dev/null; exit 0' TERM INT

wait $SERVER_PID
