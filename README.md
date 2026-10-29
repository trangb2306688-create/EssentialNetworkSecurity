# Firewall Rule Management and Network Access Control Dashboard

## 1. Project Description

This project is a web-based dashboard for managing firewall rules and simulating network access decisions.

Users can create, edit, enable, disable, and delete firewall rules. The application checks simulated connections and returns an ALLOW or DENY decision.

The system also records rule changes in the Audit Log and denied connection attempts in Blocked Traffic History.

**Note:** This application simulates firewall decisions. It does not modify the operating system firewall.

## 2. Technologies

- Python
- Flask
- SQLite
- HTML5
- CSS3
- JavaScript
- Python `ipaddress` module

## 3. Project Structure

- `app/`: Application modules and database
- `app/templates/`: HTML templates
- `app/static/`: CSS files
- `run.py`: Application entry point
- `test_firewall_engine.py`: Firewall engine tests
- `test_evaluate_connection.py`: Connection evaluation tests

## 4. Requirements

- Python 3
- Flask

Install the required package:

```bash
pip install -r requirements.txt
```

## 5. Run the Application

Open a terminal in the project directory and run:

```bash
python run.py
```

Open the following address in a web browser:

http://127.0.0.1:5000

## 6. Testing

Run the test scripts with Python:

```bash
python test_firewall_engine.py
python test_evaluate_connection.py
```

## 7. Disclaimer

This project is intended for educational purposes. It simulates firewall rule evaluation and does not configure the actual operating system firewall.
