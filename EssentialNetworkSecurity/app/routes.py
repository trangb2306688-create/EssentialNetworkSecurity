
import ipaddress

from flask import (
    render_template,
    request,
    redirect,
    url_for,
    flash,
)

from app.database import get_db_connection

from app.firewall_engine import evaluate_connection

INITIAL_RULES = [
    {
        "priority": 1,
        "source_ip": "192.168.56.101",
        "destination_ip": "ANY",
        "protocol": "TCP",
        "port": "22",
        "action": "DENY",
        "enabled": 1,
    },
    {
        "priority": 2,
        "source_ip": "192.168.56.0/24",
        "destination_ip": "ANY",
        "protocol": "TCP",
        "port": "80",
        "action": "ALLOW",
        "enabled": 1,
    },
    {
        "priority": 3,
        "source_ip": "ANY",
        "destination_ip": "ANY",
        "protocol": "ANY",
        "port": "ANY",
        "action": "DENY",
        "enabled": 1,
    },
]


def validate_ip_or_subnet(value):
    if value.upper() == "ANY":
        return True

    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def write_audit_log(connection, operation, rule_id, details):
    connection.execute(
        """
        INSERT INTO audit_logs (operation, rule_id, details)
        VALUES (?, ?, ?)
        """,
        (operation, rule_id, details),
    )


def seed_initial_rules():
    connection = get_db_connection()

    count = connection.execute(
        "SELECT COUNT(*) FROM firewall_rules"
    ).fetchone()[0]

    if count == 0:
        connection.executemany(
            """
            INSERT INTO firewall_rules (
                priority, source_ip, destination_ip,
                protocol, port, action, enabled
            )
            VALUES (
                :priority, :source_ip, :destination_ip,
                :protocol, :port, :action, :enabled
            )
            """,
            INITIAL_RULES,
        )
        connection.commit()

    connection.close()


def register_routes(app):
    seed_initial_rules()

    @app.route("/", methods=["GET", "POST"])
    def index():
        if request.method == "POST":
            source_ip = request.form.get(
                "source_ip", ""
            ).strip()

            destination_ip = request.form.get(
                "destination_ip", ""
            ).strip()

            protocol = request.form.get(
                "protocol", ""
            ).strip().upper()

            port_value = request.form.get(
                "port", ""
            ).strip()

            action = request.form.get(
                "action", ""
            ).strip().upper()

            if not validate_ip_or_subnet(source_ip):
                flash("Invalid source IP address or subnet.", "error")
                return redirect(url_for("index"))

            if not validate_ip_or_subnet(destination_ip):
                flash(
                    "Invalid destination IP address or subnet.",
                    "error",
                )
                return redirect(url_for("index"))

            if protocol not in ["TCP", "UDP", "ICMP", "ANY"]:
                flash("Invalid protocol.", "error")
                return redirect(url_for("index"))

            if action not in ["ALLOW", "DENY"]:
                flash("Invalid firewall action.", "error")
                return redirect(url_for("index"))

            if protocol == "ICMP":
                if port_value.upper() != "ANY":
                    flash(
                        "For ICMP rules, port must be ANY.",
                        "error",
                    )
                    return redirect(url_for("index"))
                port = "ANY"
            elif port_value.upper() == "ANY":
                port = "ANY"
            else:
                try:
                    port = int(port_value)
                    if not 1 <= port <= 65535:
                        raise ValueError
                    port = str(port)
                except ValueError:
                    flash(
                        "Port must be ANY or a number "
                        "from 1 to 65535.",
                        "error",
                    )
                    return redirect(url_for("index"))

            connection = get_db_connection()

            next_priority = connection.execute(
                """
                SELECT COALESCE(MAX(priority), 0) + 1
                FROM firewall_rules
                """
            ).fetchone()[0]

            connection.execute(
                """
                INSERT INTO firewall_rules (
                    priority, source_ip, destination_ip,
                    protocol, port, action, enabled
                )
                VALUES (?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    next_priority,
                    source_ip.upper()
                    if source_ip.upper() == "ANY"
                    else source_ip,
                    destination_ip.upper()
                    if destination_ip.upper() == "ANY"
                    else destination_ip,
                    protocol,
                    port,
                    action,
                ),
            )

            
            new_rule = connection.execute(
                "SELECT last_insert_rowid()"
            ).fetchone()

            write_audit_log(
                connection,
                "ADD",
                new_rule[0],
                (
                    f"Added rule: source={source_ip}, "
                    f"destination={destination_ip}, "
                    f"protocol={protocol}, port={port}, "
                    f"action={action}"
                ),
            )


            connection.commit()
            connection.close()

            flash("Firewall rule added successfully.", "success")
            return redirect(url_for("index"))

        connection = get_db_connection()

        rules = connection.execute(
            """
            SELECT * FROM firewall_rules
            ORDER BY priority ASC, id ASC
            """
        ).fetchall()

        connection.close()

        allow_count = sum(
            1 for rule in rules
            if rule["action"] == "ALLOW" and rule["enabled"]
        )

        deny_count = sum(
            1 for rule in rules
            if rule["action"] == "DENY" and rule["enabled"]
        )

        return render_template(
            "index.html",
            rules=rules,
            total_rules=len(rules),
            allow_count=allow_count,
            deny_count=deny_count,
        )

    @app.route("/toggle/<int:rule_id>", methods=["POST"])
    def toggle_rule(rule_id):
        connection = get_db_connection()

        rule = connection.execute(
            "SELECT * FROM firewall_rules WHERE id = ?",
            (rule_id,),
        ).fetchone()

        if rule is None:
            connection.close()
            flash("Firewall rule not found.", "error")
            return redirect(url_for("index"))

        new_status = 0 if rule["enabled"] else 1


        operation = "ENABLE" if new_status else "DISABLE"

        write_audit_log(
            connection,
            operation,
            rule_id,
            f"Rule status changed to {'enabled' if new_status else 'disabled'}.",
        )

        connection.execute(
            "UPDATE firewall_rules SET enabled = ? WHERE id = ?",
            (new_status, rule_id),
        )

        connection.commit()
        connection.close()

        flash("Firewall rule status updated.", "success")
        return redirect(url_for("index"))

    @app.route("/delete/<int:rule_id>", methods=["POST"])
    def delete_rule(rule_id):
        connection = get_db_connection()

        rule = connection.execute(
            "SELECT * FROM firewall_rules WHERE id = ?",
            (rule_id,),
        ).fetchone()

        if rule is None:
            connection.close()
            flash("Firewall rule not found.", "error")
            return redirect(url_for("index"))


        write_audit_log(
            connection,
            "DELETE",
            rule_id,
            (
                f"Deleted rule: source={rule['source_ip']}, "
                f"destination={rule['destination_ip']}, "
                f"protocol={rule['protocol']}, "
                f"port={rule['port']}, action={rule['action']}"
            ),
        )

        connection.execute(
            "DELETE FROM firewall_rules WHERE id = ?",
            (rule_id,),
        )

        connection.commit()
        connection.close()

        flash("Firewall rule deleted successfully.", "success")
        return redirect(url_for("index"))

    
    @app.route("/edit/<int:rule_id>", methods=["GET", "POST"])
    def edit_rule(rule_id):
        connection = get_db_connection()

        rule = connection.execute(
            "SELECT * FROM firewall_rules WHERE id = ?",
            (rule_id,),
        ).fetchone()

        if rule is None:
            connection.close()
            flash("Firewall rule not found.", "error")
            return redirect(url_for("index"))

        if request.method == "POST":
            source_ip = request.form.get(
                "source_ip", ""
            ).strip()

            destination_ip = request.form.get(
                "destination_ip", ""
            ).strip()

            protocol = request.form.get(
                "protocol", ""
            ).strip().upper()

            port_value = request.form.get(
                "port", ""
            ).strip()

            action = request.form.get(
                "action", ""
            ).strip().upper()

            # Validate IP addresses and subnets
            if (
                not source_ip
                or not validate_ip_or_subnet(source_ip)
            ):
                flash("Invalid source IP address or subnet.", "error")
            elif (
                not destination_ip
                or not validate_ip_or_subnet(destination_ip)
            ):
                flash(
                    "Invalid destination IP address or subnet.",
                    "error",
                )
            elif protocol not in ["TCP", "UDP", "ICMP", "ANY"]:
                flash("Invalid protocol.", "error")
            elif action not in ["ALLOW", "DENY"]:
                flash("Invalid firewall action.", "error")
            else:
                if protocol == "ICMP":
                    if port_value.upper() != "ANY":
                        flash(
                            "For ICMP rules, port must be ANY.",
                            "error",
                        )
                        connection.close()
                        return redirect(
                            url_for("edit_rule", rule_id=rule_id)
                        )
                    port = "ANY"

                elif port_value.upper() == "ANY":
                    port = "ANY"

                else:
                    try:
                        port_number = int(port_value)
                        if not 1 <= port_number <= 65535:
                            raise ValueError
                        port = str(port_number)
                    except ValueError:
                        flash(
                            "Port must be ANY or a number "
                            "from 1 to 65535.",
                            "error",
                        )
                        connection.close()
                        return redirect(
                            url_for("edit_rule", rule_id=rule_id)
                        )

                connection.execute(
                    """
                    UPDATE firewall_rules
                    SET source_ip = ?,
                        destination_ip = ?,
                        protocol = ?,
                        port = ?,
                        action = ?
                    WHERE id = ?
                    """,
                    (
                        source_ip.upper()
                        if source_ip.upper() == "ANY"
                        else source_ip,
                        destination_ip.upper()
                        if destination_ip.upper() == "ANY"
                        else destination_ip,
                        protocol,
                        port,
                        action,
                        rule_id,
                    ),
                )


                write_audit_log(
                    connection,
                    "EDIT",
                    rule_id,
                    (
                        f"Updated rule: source={source_ip}, "
                        f"destination={destination_ip}, "
                        f"protocol={protocol}, port={port}, "
                        f"action={action}"
                    ),
                )

                connection.commit()
                connection.close()

                flash("Firewall rule updated successfully.", "success")
                return redirect(url_for("index"))

        connection.close()

        return render_template("edit_rule.html", rule=rule)

    
    @app.route("/simulate", methods=["GET", "POST"])
    def simulate():
        result = None
        form_data = {
            "source_ip": "",
            "destination_ip": "",
            "protocol": "TCP",
            "destination_port": "80",
        }

        if request.method == "POST":
            form_data = {
                "source_ip": request.form.get(
                    "source_ip", ""
                ).strip(),
                "destination_ip": request.form.get(
                    "destination_ip", ""
                ).strip(),
                "protocol": request.form.get(
                    "protocol", ""
                ).strip().upper(),
                "destination_port": request.form.get(
                    "destination_port", ""
                ).strip(),
            }

            if not validate_ip_or_subnet(form_data["source_ip"]):
                flash("Invalid source IP address.", "error")
                return render_template(
                    "simulate.html",
                    result=None,
                    form_data=form_data,
                )

            if not validate_ip_or_subnet(
                form_data["destination_ip"]
            ):
                flash("Invalid destination IP address.", "error")
                return render_template(
                    "simulate.html",
                    result=None,
                    form_data=form_data,
                )

            if form_data["protocol"] not in ["TCP", "UDP", "ICMP"]:
                flash("Select a valid protocol.", "error")
                return render_template(
                    "simulate.html",
                    result=None,
                    form_data=form_data,
                )

            try:
                destination_port = int(
                    form_data["destination_port"]
                )
                if not 1 <= destination_port <= 65535:
                    raise ValueError
            except ValueError:
                flash(
                    "Destination port must be between 1 and 65535.",
                    "error",
                )
                return render_template(
                    "simulate.html",
                    result=None,
                    form_data=form_data,
                )

            connection = get_db_connection()
            database_rules = connection.execute(
                """
                SELECT * FROM firewall_rules
                ORDER BY priority ASC, id ASC
                """
            ).fetchall()
            connection.close()

            rules = [
                {
                    "priority": rule["priority"],
                    "source_ip": rule["source_ip"],
                    "destination_ip": rule["destination_ip"],
                    "protocol": rule["protocol"],
                    "port": rule["port"],
                    "action": rule["action"],
                    "enabled": bool(rule["enabled"]),
                }
                for rule in database_rules
            ]

            simulated_connection = {
                "source_ip": form_data["source_ip"],
                "destination_ip": form_data["destination_ip"],
                "protocol": form_data["protocol"],
                "destination_port": destination_port,
            }

            result = evaluate_connection(
                simulated_connection,
                rules,
                default_action="DENY",
            )


            if result["action"] == "DENY":
                connection = get_db_connection()

                connection.execute(
                    """
                    INSERT INTO blocked_traffic (
                        source_ip,
                        destination_ip,
                        protocol,
                        destination_port,
                        matched_rule,
                        reason
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        form_data["source_ip"],
                        form_data["destination_ip"],
                        form_data["protocol"],
                        destination_port,
                        result["matched_rule"],
                        result["message"],
                    ),
                )

                connection.commit()
                connection.close()

        return render_template(
            "simulate.html",
            result=result,
            form_data=form_data,
        )

    
    @app.route("/blocked-traffic")
    def blocked_traffic():
        connection = get_db_connection()

        blocked_records = connection.execute(
            """
            SELECT *
            FROM blocked_traffic
            ORDER BY id DESC
            """
        ).fetchall()

        connection.close()

        return render_template(
            "blocked_traffic.html",
            blocked_records=blocked_records,
        )

    @app.route("/audit-logs")
    def audit_logs():
        connection = get_db_connection()

        logs = connection.execute(
            """
            SELECT id, timestamp, operation, rule_id, details
            FROM audit_logs
            ORDER BY id DESC
            """
        ).fetchall()

        connection.close()

        return render_template("audit_logs.html", logs=logs)

