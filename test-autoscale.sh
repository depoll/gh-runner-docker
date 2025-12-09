#!/bin/bash

# Test script to verify the autoscaling setup
# Run this after starting the controller to ensure everything is working

set -e

WEBHOOK_URL="${WEBHOOK_URL:-http://localhost:8080}"
WEBHOOK_SECRET="${WEBHOOK_SECRET:-}"

echo "=== GitHub Actions Autoscaling Runner Test ==="
echo ""

# Test 1: Health check
echo "1. Testing health endpoint..."
HEALTH_RESPONSE=$(curl -s "${WEBHOOK_URL}/health" 2>/dev/null)
if [ $? -eq 0 ] && echo "$HEALTH_RESPONSE" | grep -q '"status"'; then
    echo "   ✅ Health check passed"
    echo "   Response: $HEALTH_RESPONSE"
else
    echo "   ❌ Health check failed - is the controller running?"
    exit 1
fi
echo ""

# Test 2: Webhook endpoint exists
echo "2. Testing webhook endpoint..."
WEBHOOK_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${WEBHOOK_URL}/webhook" \
    -H "Content-Type: application/json" \
    -H "X-GitHub-Event: ping" \
    -d '{"zen": "test"}' 2>/dev/null)

if [ "$WEBHOOK_RESPONSE" = "200" ] || [ "$WEBHOOK_RESPONSE" = "401" ]; then
    echo "   ✅ Webhook endpoint responding (HTTP $WEBHOOK_RESPONSE)"
else
    echo "   ❌ Webhook endpoint not responding correctly (HTTP $WEBHOOK_RESPONSE)"
fi
echo ""

# Test 3: Docker socket access
echo "3. Testing Docker socket access..."
DOCKER_TEST=$(docker ps --format "{{.Names}}" 2>/dev/null | head -1)
if [ $? -eq 0 ]; then
    echo "   ✅ Docker socket accessible"
else
    echo "   ❌ Docker socket not accessible - check volume mount"
fi
echo ""

# Test 4: Simulate workflow_job webhook (without signature)
echo "4. Simulating workflow_job queued event (no signature)..."
SIMULATE_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${WEBHOOK_URL}/webhook" \
    -H "Content-Type: application/json" \
    -H "X-GitHub-Event: workflow_job" \
    -d '{
        "action": "queued",
        "workflow_job": {
            "id": 99999999,
            "name": "test-job",
            "labels": ["self-hosted", "linux"]
        }
    }' 2>/dev/null)

if [ "$SIMULATE_RESPONSE" = "401" ]; then
    echo "   ✅ Webhook properly rejects unsigned requests"
elif [ "$SIMULATE_RESPONSE" = "200" ]; then
    echo "   ⚠️  Warning: Webhook accepted unsigned request (WEBHOOK_SECRET not set)"
else
    echo "   ❓ Unexpected response (HTTP $SIMULATE_RESPONSE)"
fi
echo ""

echo "=== Test Summary ==="
echo ""
echo "If all tests passed, your autoscaling setup is ready!"
echo ""
echo "Next steps:"
echo "1. Configure a webhook in your GitHub repository/organization"
echo "2. Set the Payload URL to: ${WEBHOOK_URL}/webhook"
echo "3. Set Content type to: application/json"
echo "4. Set the Secret to match your WEBHOOK_SECRET"
echo "5. Select 'Workflow jobs' as the event trigger"
echo ""
echo "Monitor the controller logs with:"
echo "  docker-compose -f docker-compose.autoscale.yml logs -f controller"
