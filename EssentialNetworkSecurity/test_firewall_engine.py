from app.firewall_engine import ip_matches

# Test 1: Exact IP address
assert ip_matches(
    "192.168.56.101", "192.168.56.101"
) is True

# Test 2: IP belongs to a subnet
assert ip_matches(
    "192.168.56.101", "192.168.56.0/24"
) is True

# Test 3: IP does not belong to a subnet
assert ip_matches(
    "192.168.57.101", "192.168.56.0/24"
) is False

# Test 4: ANY matches every valid IP
assert ip_matches(
    "192.168.56.101", "ANY"
) is True

# Test 5: Invalid IP address
assert ip_matches(
    "invalid-ip", "192.168.56.0/24"
) is False

print("All 5 IP matching tests passed!")