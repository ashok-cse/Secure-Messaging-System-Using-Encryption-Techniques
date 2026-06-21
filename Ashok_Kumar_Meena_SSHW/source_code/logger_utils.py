"""
logger_utils.py
---------------
A very small logging system built on top of the SQLite "logs" table.

Every security relevant event is recorded with:
  * timestamp   - when it happened (UTC, ISO format)
  * event_type  - a short category string, e.g. LOGIN_SUCCESS
  * username    - who was involved (may be None)
  * details     - a human readable description

We deliberately keep the log messages free of secrets: no passwords, no
shared secrets and no plaintext message content are ever logged.
"""

from datetime import datetime, timezone

import database


# Event type constants. Using constants avoids typos and keeps the logs
# consistent and easy to filter.
LOGIN_SUCCESS = "LOGIN_SUCCESS"
LOGIN_FAILURE = "LOGIN_FAILURE"
REGISTER = "REGISTER"
ENCRYPT = "ENCRYPT"
DECRYPT_SUCCESS = "DECRYPT_SUCCESS"
DECRYPT_FAILURE = "DECRYPT_FAILURE"
INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
ATTACK_SIMULATION = "ATTACK_SIMULATION"
LOGOUT = "LOGOUT"


def _now():
    """Return the current UTC time as a readable ISO string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log_event(event_type, username, details):
    """Write one event to the log table."""
    database.insert_log(_now(), event_type, username, details)


def display_logs(limit=100):
    """Print the most recent logs in a readable table-like format."""
    logs = database.get_logs(limit=limit)
    if not logs:
        print("\nNo log entries yet.\n")
        return

    print("\n================= SECURITY LOGS (newest first) =================")
    print(f"{'TIMESTAMP':<21} {'EVENT':<18} {'USER':<12} DETAILS")
    print("-" * 75)
    for row in logs:
        username = row["username"] if row["username"] else "-"
        print(
            f"{row['timestamp']:<21} {row['event_type']:<18} "
            f"{username:<12} {row['details']}"
        )
    print("=" * 63 + "\n")
