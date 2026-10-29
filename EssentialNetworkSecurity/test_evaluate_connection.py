from app.firewall_engine import evaluate_connection

rules = [
    {
        "priority": 1,
        "source_ip": "192.168.56.101",
        "destination_ip": "ANY",
        "protocol": "TCP",
        "port": 22,
        "action": "DENY",
        "enabled": True
    },
    {
        "priority": 2,
        "source_ip": "192.168.56.0/24",
        "destination_ip": "ANY",
        "protocol": "TCP",
        "port": 80,
        "action": "ALLOW",
        "enabled": True
    }
]

# Test 1: SSH connection should be denied
ssh_connection = {
    "source_ip": "192.168.56.101",
    "destination_ip": "192.168.56.10",
    "protocol": "TCP",
    "destination_port": 22
}

result1 = evaluate_connection(ssh_connection, rules)
print("Test 1 - SSH:", result1)

assert result1["action"] == "DENY"
assert result1["matched_rule"] == 1

# Test 2: HTTP connection should be allowed
http_connection = {
    "source_ip": "192.168.56.101",
    "destination_ip": "192.168.56.10",
    "protocol": "TCP",
    "destination_port": 80
}

result2 = evaluate_connection(http_connection, rules)
print("Test 2 - HTTP:", result2)

assert result2["action"] == "ALLOW"
assert result2["matched_rule"] == 2

# Test 3: Unmatched connection uses default DENY
other_connection = {
    "source_ip": "10.0.0.5",
    "destination_ip": "192.168.56.10",
    "protocol": "TCP",
    "destination_port": 443
}

result3 = evaluate_connection(other_connection, rules)
print("Test 3 - HTTPS:", result3)

assert result3["action"] == "DENY"
assert result3["matched_rule"] is None

print("All 3 firewall evaluation tests passed!")