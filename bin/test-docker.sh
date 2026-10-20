#!/usr/bin/env bash
# Build the Docker image, start a throwaway container and smoke the dataset
# API: listing is public; create/delete require an authorized user (issue #6).
# A fresh container seeds a root admin from MLIPE_ADMIN_USER/MLIPE_ADMIN_PASS.
set -euo pipefail

IMAGE="concon-test"
CONTAINER="concon-smoke-test"
PORT=3001
ADMIN_USER="admin"
ADMIN_PASS="smoke-$(date +%s)"
BASE="http://localhost:$PORT"

cleanup() {
    echo "Cleaning up..."
    docker rm -f "$CONTAINER" 2>/dev/null || true
    docker rmi "$IMAGE" 2>/dev/null || true
}
trap cleanup EXIT

cd "$(dirname "$0")/.."

echo "==> Building Docker image..."
docker build -t "$IMAGE" .

echo "==> Starting container on port $PORT..."
docker run -d --name "$CONTAINER" -p "$PORT:3000" \
    -e MLIPE_ADMIN_USER="$ADMIN_USER" -e MLIPE_ADMIN_PASS="$ADMIN_PASS" "$IMAGE"

echo "==> Waiting for server to start..."
for i in $(seq 1 10); do
    if curl -sf "$BASE/_health" >/dev/null 2>&1; then
        break
    fi
    if [ "$i" -eq 10 ]; then
        echo "FAIL: Server did not start within 10 seconds"
        docker logs "$CONTAINER"
        exit 1
    fi
    sleep 1
done

# status <expected> <curl args...> — assert the HTTP status of a request.
status() {
    local expected="$1"; shift
    local got
    got=$(curl -s -o /dev/null -w "%{http_code}" "$@")
    [ "$got" -eq "$expected" ] || { echo "FAIL: expected $expected, got $got for: $*"; exit 1; }
}

echo "==> GET /_health..."
status 200 "$BASE/_health"

echo "==> GET /_api/datasets (public, empty)..."
body=$(curl -sf "$BASE/_api/datasets")
[ "$body" = '{"datasets":[]}' ] || { echo "FAIL: expected empty datasets, got $body"; exit 1; }

echo "==> POST /_api/datasets without credentials is rejected..."
status 401 -X POST "$BASE/_api/datasets" \
    -H 'Content-Type: application/json' -d '{"name":"smoke-test"}'

echo "==> POST /_api/datasets with an invalid name is rejected..."
status 400 -u "$ADMIN_USER:$ADMIN_PASS" -X POST "$BASE/_api/datasets" \
    -H 'Content-Type: application/json' -d '{"name":"../escape"}'

echo "==> POST /_api/datasets as root admin..."
status 201 -u "$ADMIN_USER:$ADMIN_PASS" -X POST "$BASE/_api/datasets" \
    -H 'Content-Type: application/json' -d '{"name":"smoke-test"}'

echo "==> GET /_api/datasets (after create)..."
body=$(curl -sf "$BASE/_api/datasets")
echo "$body" | grep -q "root/smoke-test" || { echo "FAIL: dataset not found in $body"; exit 1; }

echo "==> SPARQL query on the public dataset..."
body=$(curl -sf "$BASE/_ds/smoke-test/_sparql?query=SELECT%20*%20WHERE%20%7B%20%3Fs%20%3Fp%20%3Fo%20%7D")
echo "$body" | grep -q '"bindings"' || { echo "FAIL: unexpected SPARQL response: $body"; exit 1; }

echo "==> DELETE /_api/datasets without credentials is rejected..."
status 401 -X DELETE "$BASE/_api/datasets/root/smoke-test"

echo "==> DELETE /_api/datasets as root admin..."
status 204 -u "$ADMIN_USER:$ADMIN_PASS" -X DELETE "$BASE/_api/datasets/root/smoke-test"

echo "==> GET /_api/datasets (after delete)..."
body=$(curl -sf "$BASE/_api/datasets")
[ "$body" = '{"datasets":[]}' ] || { echo "FAIL: expected empty datasets, got $body"; exit 1; }

echo "==> All Docker smoke tests passed."
