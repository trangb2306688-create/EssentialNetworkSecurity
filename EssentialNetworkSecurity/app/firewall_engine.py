import ipaddress


def ip_matches(ip_value, rule_value):
    """Check whether an IP matches an IP address or subnet rule."""
    if rule_value == "ANY":
        return True

    try:
        ip = ipaddress.ip_address(ip_value)

        if "/" in rule_value:
            network = ipaddress.ip_network(rule_value, strict=False)
            return ip in network

        return ip == ipaddress.ip_address(rule_value)

    except ValueError:
        return False

def evaluate_connection(connection, rules, default_action="DENY"):
    """
    Evaluate a simulated connection against enabled firewall rules.
    The first matching rule determines the decision.
    """
    for rule in sorted(rules, key=lambda item: item["priority"]):
        if not rule.get("enabled", True):
            continue

        source_matches = ip_matches(
            connection["source_ip"],
            rule["source_ip"]
        )

        destination_matches = ip_matches(
            connection["destination_ip"],
            rule["destination_ip"]
        )

        protocol_matches = (
            rule["protocol"].upper() == "ANY"
            or connection["protocol"].upper()
            == rule["protocol"].upper()
        )

        port_matches = (
            str(rule["port"]).upper() == "ANY"
            or int(connection["destination_port"]) == int(rule["port"])
        )

        if (
            source_matches
            and destination_matches
            and protocol_matches
            and port_matches
        ):
            action = rule["action"].upper()

            return {
                "action": action,
                "matched_rule": rule["priority"],
                "message": f"Connection {action} by rule "
                           f"{rule['priority']}"
            }

    return {
        "action": default_action.upper(),
        "matched_rule": None,
        "message": f"No rule matched. Default action: "
                   f"{default_action.upper()}"
    }