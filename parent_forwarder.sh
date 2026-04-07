#!/bin/bash
# Run this on the EC2 HOST to bridge VSOCK traffic to TCP.
# The enclave exposes the memwal-relayer on VSOCK port 4000.
# This script makes it available at localhost:4000 on the host.
#
# All configuration (including VSOCK port assignments) is read from .env.runtime.
# Copy .env.example to .env.runtime, fill in real values, then run this script.

set -e

ENV_FILE="${1:-.env.runtime}"
if [ ! -f "$ENV_FILE" ]; then
    echo "ERROR: $ENV_FILE not found. Copy .env.example to .env.runtime and fill in values."
    exit 1
fi

# Source env file (skip comments and blank lines)
set -a
# shellcheck disable=SC1090
while IFS= read -r line; do
    case "$line" in
        '#'*|'') continue ;;
        *) eval "export $line" 2>/dev/null || true ;;
    esac
done < "$ENV_FILE"
set +a

# VSOCK port assignments — all read from env (set in .env.runtime)
: "${SUI_PROXY_VSOCK_PORT:?SUI_PROXY_VSOCK_PORT not set in $ENV_FILE}"
: "${WALRUS_PUBLISHER_PROXY_VSOCK_PORT:?WALRUS_PUBLISHER_PROXY_VSOCK_PORT not set in $ENV_FILE}"
: "${WALRUS_AGGREGATOR_PROXY_VSOCK_PORT:?WALRUS_AGGREGATOR_PROXY_VSOCK_PORT not set in $ENV_FILE}"
: "${POSTGRES_PROXY_VSOCK_PORT:?POSTGRES_PROXY_VSOCK_PORT not set in $ENV_FILE}"
: "${REDIS_PROXY_VSOCK_PORT:?REDIS_PROXY_VSOCK_PORT not set in $ENV_FILE}"
: "${OPENAI_PROXY_VSOCK_PORT:?OPENAI_PROXY_VSOCK_PORT not set in $ENV_FILE}"
: "${SEAL_BASE_VSOCK_PORT:?SEAL_BASE_VSOCK_PORT not set in $ENV_FILE}"
# All URLs and secrets come from .env.runtime — no defaults here.

extract_url_host() {
    printf '%s' "$1" | sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://(\[[^]]+\]|[^/:]+).*#\1#'
}

extract_url_port() {
    local url="$1"
    local explicit_port
    explicit_port=$(printf '%s' "$url" | sed -nE 's#^[a-zA-Z][a-zA-Z0-9+.-]*://[^/:]+:([0-9]+).*$#\1#p')
    if [ -n "$explicit_port" ]; then
        printf '%s' "$explicit_port"
        return
    fi

    local scheme
    scheme=$(printf '%s' "$url" | sed -nE 's#^([a-zA-Z][a-zA-Z0-9+.-]*)://.*#\1#p')
    case "$scheme" in
        https) printf '443' ;;
        http) printf '80' ;;
        *) printf '443' ;;
    esac
}

start_outbound_proxy() {
    local name="$1"
    local url="$2"
    local vsock_port="$3"
    local host
    local port

    host=$(extract_url_host "$url")
    port=$(extract_url_port "$url")

    if [ -z "$host" ] || [ -z "$port" ]; then
        echo "Skipping $name outbound proxy: could not parse URL '$url'"
        return
    fi

    echo "Forwarding enclave VSOCK:${vsock_port} -> ${host}:${port}"
    socat VSOCK-LISTEN:${vsock_port},reuseaddr,fork TCP:${host}:${port} &
}

ENCLAVE_CID=$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveCID')
if [ -z "$ENCLAVE_CID" ] || [ "$ENCLAVE_CID" = "null" ]; then
    echo "No running enclave found. Start one first with: make run"
    exit 1
fi

echo "Enclave CID: $ENCLAVE_CID"

# Forward relayer: host:4000 → enclave VSOCK:4000
echo "Forwarding localhost:4000 → enclave VSOCK:4000"
socat TCP-LISTEN:4000,reuseaddr,fork VSOCK-CONNECT:${ENCLAVE_CID}:4000 &

# Collect enclave logs: enclave VSOCK:5000 → enclave.log
echo "Collecting enclave logs → enclave.log"
socat VSOCK-LISTEN:5000,reuseaddr,fork OPEN:enclave.log,creat,append &

# Collect sidecar logs: enclave VSOCK:5001 → sidecar.log
echo "Collecting sidecar logs → sidecar.log"
socat VSOCK-LISTEN:5001,reuseaddr,fork OPEN:sidecar.log,creat,append &

start_outbound_proxy "Sui" "$SUI_RPC_URL" "$SUI_PROXY_VSOCK_PORT"
start_outbound_proxy "Walrus publisher" "$WALRUS_PUBLISHER_URL" "$WALRUS_PUBLISHER_PROXY_VSOCK_PORT"
start_outbound_proxy "Walrus aggregator" "$WALRUS_AGGREGATOR_URL" "$WALRUS_AGGREGATOR_PROXY_VSOCK_PORT"

# Postgres: extract host:port from DATABASE_URL (postgresql://user:pass@host:port/db)
if [ -n "$DATABASE_URL" ]; then
    PG_HOST=$(printf '%s' "$DATABASE_URL" | sed -nE 's#^[^:]+://[^@]+@([^:/]+).*#\1#p')
    PG_PORT=$(printf '%s' "$DATABASE_URL" | sed -nE 's#^[^:]+://[^@]+@[^:]+:([0-9]+).*#\1#p')
    PG_PORT="${PG_PORT:-5432}"
    if [ -n "$PG_HOST" ]; then
        echo "Forwarding enclave VSOCK:${POSTGRES_PROXY_VSOCK_PORT} -> ${PG_HOST}:${PG_PORT}"
        socat VSOCK-LISTEN:${POSTGRES_PROXY_VSOCK_PORT},reuseaddr,fork TCP:${PG_HOST}:${PG_PORT} &
    fi
fi

# Redis: extract host:port from REDIS_URL (redis://host:port)
if [ -n "$REDIS_URL" ]; then
    REDIS_HOST=$(extract_url_host "$REDIS_URL")
    REDIS_PORT=$(printf '%s' "$REDIS_URL" | sed -nE 's#^[^:]+://[^:]+:([0-9]+).*#\1#p')
    REDIS_PORT="${REDIS_PORT:-6379}"
    if [ -n "$REDIS_HOST" ]; then
        echo "Forwarding enclave VSOCK:${REDIS_PROXY_VSOCK_PORT} -> ${REDIS_HOST}:${REDIS_PORT}"
        socat VSOCK-LISTEN:${REDIS_PROXY_VSOCK_PORT},reuseaddr,fork TCP:${REDIS_HOST}:${REDIS_PORT} &
    fi
fi

start_outbound_proxy "OpenAI" "$OPENAI_API_BASE" "$OPENAI_PROXY_VSOCK_PORT"

# SEAL key servers (comma-separated URLs)
if [ -n "$SEAL_KEY_SERVER_URLS" ]; then
    SEAL_IDX=0
    IFS=',' read -ra SEAL_URLS <<< "$SEAL_KEY_SERVER_URLS"
    for SEAL_URL in "${SEAL_URLS[@]}"; do
        VSOCK_PORT=$((SEAL_BASE_VSOCK_PORT + SEAL_IDX))
        start_outbound_proxy "SEAL key server ${SEAL_IDX}" "$SEAL_URL" "$VSOCK_PORT"
        SEAL_IDX=$((SEAL_IDX + 1))
    done
fi

echo ""
echo "Forwarding active. Test with:"
echo "  curl http://localhost:4000/health"
echo "  curl http://localhost:4000/get_attestation"
echo ""
echo "Logs: tail -f enclave.log sidecar.log"

wait
