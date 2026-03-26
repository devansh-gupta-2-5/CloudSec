#!/bin/bash

# Configuration
GATEWAY_URL="http://127.0.0.1:8081"
TEST_USER="attacker_$(date +%s)"
TEST_PASS="ValidPass123"
WRONG_PASS="WrongPass456"


echo " CloudSec Automated Attack Simulation"


# Step 1: Register the user
echo "[*] Step 1: Registering a new test user ($TEST_USER)..."
curl -s -o /dev/null -w "Registration HTTP Status: %{http_code}\n" -X POST "$GATEWAY_URL/register" \
     -H "Content-Type: application/json" \
     -d "{\"username\": \"$TEST_USER\", \"password\": \"$TEST_PASS\"}"

echo ""
echo "[*] Step 2: Simulating brute-force attack (10 invalid login attempts)..."

# Step 2: Loop 10 invalid login attempts
for i in {1..10}; do
    echo -n "Attempt $i: "
    curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" -X POST "$GATEWAY_URL/login" \
         -H "Content-Type: application/json" \
         -d "{\"username\": \"$TEST_USER\", \"password\": \"$WRONG_PASS\"}"
    sleep 0.5
done

echo ""
echo "Simulation complete."
echo "Please verify the resulting entries in logs/threats.log and logs/mitigation.log."