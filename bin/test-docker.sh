#!/usr/bin/env bash
set -euo pipefail

IMAGE="mlipe-test"
CONTAINER="mlipe-smoke-test"
PORT=3001

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
docker run -d --name "$CONTAINER" -p "$PORT:3000" "$IMAGE"

echo "==> Waiting for server to start..."
for i in $(seq 1 10); do
    if curl -sf "http://localhost:$PORT/health" >/dev/null 2>&1; then
        break
    fi
    if [ "$i" -eq 10 ]; then
        echo "FAIL: Server did not start within 10 seconds"
        docker logs "$CONTAINER"
        exit 1
    fi
    sleep 1
done

echo "==> Testing GET /health..."
status=$(curl -sf -o /dev/null -w "%{http_code}" "http://localhost:$PORT/health")
[ "$status" -eq 200 ] || { echo "FAIL: /health returned $status"; exit 1; }

echo "==> Testing GET /datasets (empty)..."
body=$(curl -sf "http://localhost:$PORT/datasets")
[ "$body" = '{"datasets":[]}' ] || { echo "FAIL: expected empty datasets, got $body"; exit 1; }

echo "==> Testing POST /datasets..."
status=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "http://localhost:$PORT/datasets" \
    -H 'Content-Type: application/json' -d '{"name":"smoke-test"}')
[ "$status" -eq 201 ] || { echo "FAIL: POST /datasets returned $status"; exit 1; }

echo "==> Testing GET /datasets (after create)..."
body=$(curl -sf "http://localhost:$PORT/datasets")
echo "$body" | grep -q "smoke-test" || { echo "FAIL: dataset not found in $body"; exit 1; }

echo "==> Testing SPARQL query..."
body=$(curl -sf "http://localhost:$PORT/datasets/smoke-test/sparql?query=SELECT%20*%20WHERE%20%7B%20%3Fs%20%3Fp%20%3Fo%20%7D")
echo "$body" | grep -q '"bindings"' || { echo "FAIL: unexpected SPARQL response: $body"; exit 1; }

echo "==> Testing DELETE /datasets..."
status=$(curl -sf -o /dev/null -w "%{http_code}" -X DELETE "http://localhost:$PORT/datasets/smoke-test")
[ "$status" -eq 204 ] || { echo "FAIL: DELETE returned $status"; exit 1; }

echo "==> All Docker smoke tests passed."
