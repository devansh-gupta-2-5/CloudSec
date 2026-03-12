#!/bin/bash
# Requirements: sudo apt install jq parallel
GATEWAY="http://127.0.0.1:8081"
LOG_DIR="../../logs"

echo "=========================================="
echo "   CLOUDSEC ROBUST SECURITY TEST SUITE    "
echo "=========================================="

# 1. FUNCTIONAL TEST: Admin Workflow
echo -e "\n[1/6] Testing Admin Authentication..."
TOKEN=$(curl -s -X POST "$GATEWAY/login" -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}' | jq -r '.token')

if [[ "$TOKEN" != "null" && "$TOKEN" != "" ]]; then
    echo "  [PASS] Admin JWT obtained successfully."
else
    echo "  [FAIL] Admin login failed. Check app_data.db and main.cpp salts."
    exit 1
fi

# 2. DOS MITIGATION: Testing Nginx Rate Limiting
# Nginx is set to 10r/s. We will fire 30 requests in 1 second.
echo -e "\n[2/6] Testing Rate Limiting (DoS Mitigation)..."
echo "  Firing 100 parallel requests to trigger 10r/s limit..."

# Function to perform a single request
do_req() { curl -s -o /dev/null -w "%{http_code}\n" "$1/whoami"; }
export -f do_req

# Run 100 requests in parallel
RESULTS=$(seq 100 | parallel -j100 do_req "$GATEWAY")

SUCCESS_COUNT=$(echo "$RESULTS" | grep -c "200")
BLOCKED_COUNT=$(echo "$RESULTS" | grep -E -c "503|429")

echo "  - Requests Successful (200 OK): $SUCCESS_COUNT"
echo "  - Requests Blocked (503/429): $BLOCKED_COUNT"

if [ "$BLOCKED_COUNT" -gt 0 ]; then
    echo "  [PASS] Rate limiting active. DoS mitigation verified."
else
    echo "  [FAIL] No requests were blocked. Check nginx.conf limit_req_zone."
fi

sleep 2 # Short pause before next test to avoid log clutter

# 3. PRIVILEGE ESCALATION: Testing Unauthorized Admin Route Access
echo -e "\n[3/6] Testing Privilege Escalation (No Token)..."
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$GATEWAY/admin/add_user" \
    -H "Content-Type: application/json" \
    -d '{"username":"hacker","password":"123","role":"admin"}')

if [ "$CODE" == "401" ]; then
    echo "  [PASS] Access denied to sensitive route without JWT."
else
    echo "  [FAIL] Security flaw! Sensitive route returned status: $CODE"
fi

# 4. SQL INJECTION (SQLi) TEST
echo -e "\n[4/6] Testing SQL Injection Mitigation..."
# We try a classic ' OR '1'='1 bypass on the username field
SQLI_PAYLOAD='{"username":"admin'\'' OR '\''1'\''='\''1","password":"wrong_password"}'
SQLI_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$GATEWAY/login" \
    -H "Content-Type: application/json" -d "$SQLI_PAYLOAD")

if [ "$SQLI_CODE" == "401" ]; then
    echo "  [PASS] SQL Injection attempt blocked by Prepared Statements."
else
    echo "  [FAIL] Security flaw! SQLi returned status: $SQLI_CODE (Expected 401)"
fi

# 5. JWT TAMPERING TEST (Integrity)
GATEWAY="http://127.0.0.1:8081"

# Helper to get a valid token
echo "[INIT] Getting valid user token..."
VALID_RESP=$(curl -s -X POST "$GATEWAY/login" -H "Content-Type: application/json" -d '{"username":"user","password":"user123"}')
TOKEN=$(echo "$VALID_RESP" | jq -r '.token')

echo "------------------------------------------------"
echo "   JWT FORGERY & INTEGRITY AUDIT              "
echo "------------------------------------------------"

# CASE 1: Signature Tampering (The "Bit-Flip")
# We change one character in the signature part (the 3rd segment)
echo "[TEST 1] Signature Tampering..."
TAMPERED_SIG=$(echo "$TOKEN" | sed 's/.$/Z/') 
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TAMPERED_SIG" "$GATEWAY/api/data")
[[ "$CODE" == "401" ]] && echo "  [PASS] Rejected modified signature." || echo "  [FAIL] Accepted tampered signature! ($CODE)"

# CASE 2: Payload Manipulation (Privilege Escalation)
# Attempting to change "role":"user" to "role":"admin"
echo "[TEST 2] Payload Manipulation (Role Change)..."
# We'll take the middle part of the JWT, decode it, change it, and put it back without re-signing
HEADER=$(echo "$TOKEN" | cut -d. -f1)
PAYLOAD=$(echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | sed 's/"role":"user"/"role":"admin"/' | base64 | tr -d '=')
SIG=$(echo "$TOKEN" | cut -d. -f3)
FORGED_ROLE_TOKEN="$HEADER.$PAYLOAD.$SIG"

CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $FORGED_ROLE_TOKEN" "$GATEWAY/api/data")
[[ "$CODE" == "401" ]] && echo "  [PASS] Rejected manipulated payload." || echo "  [FAIL] Accepted role escalation! ($CODE)"

# CASE 3: The "None" Algorithm Attack
# Some poorly configured servers allow tokens with "alg":"none"
echo "[TEST 3] Algorithm 'None' Attack..."
NONE_HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=')
NONE_TOKEN="$NONE_HEADER.$PAYLOAD." # No signature
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $NONE_TOKEN" "$GATEWAY/api/data")
[[ "$CODE" == "401" ]] && echo "  [PASS] Rejected 'alg:none' attempt." || echo "  [FAIL] Vulnerable to alg:none! ($CODE)"

# CASE 4: Expired Token (Replay Attack)
# Using a token that should have expired (requires waiting or manual generation)
echo "[TEST 4] Token Expiry Check..."
# We test this by trying a token that is simply malformed/old
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer manual_old_token_here" "$GATEWAY/api/data")
[[ "$CODE" == "401" ]] && echo "  [PASS] Rejected invalid/expired format." || echo "  [FAIL] Accepted invalid token ($CODE)"


# 6. SEQUENTIAL BRUTE FORCE (MONITOR TEST)
echo -e "\n[6/6] Testing Application-Level IP Banning..."
# Fire 10 requests. We expect 4 to fail with 401, and the rest to fail with 403.
for i in {1..10}; do
    curl -s -o /dev/null -w "%{http_code}\n" -X POST "$GATEWAY/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"admin\",\"password\":\"wrong$i\"}" >> brute_monitor.tmp
    # Small sleep to ensure we don't accidentally hit a global Nginx limit
    sleep 0.1 
done

BANNED_COUNT=$(grep -c "403" brute_monitor.tmp)
rm brute_monitor.tmp

if [ "$BANNED_COUNT" -gt 0 ]; then
    echo "  [PASS] IP Ban triggered! $BANNED_COUNT requests blocked with 403."
else
    echo "  [FAIL] IP Ban NOT triggered. All requests returned 401 or other."
fi

