"""
database.py
-----------
SQLite database layer for the Secure Messaging System.

This module is intentionally small and beginner-friendly. It is responsible
for:
  * Creating the database file and tables (init_db).
  * Inserting and fetching users.
  * Inserting and fetching encrypted messages.
  * Inserting and fetching security logs.

We NEVER store plaintext passwords or plaintext messages here. We only store:
  * For users: a random salt and a PBKDF2 password hash.
  * For messages: base64 encoded ciphertext, nonce, salt and an HMAC tag.
"""

import sqlite3
from pathlib import Path

# The database file lives next to this source file so the app always finds it.
DB_PATH = Path(__file__).resolve().parent / "secure_messages.db"


def get_connection():
    """Open a new SQLite connection.

    We use sqlite3.Row so that rows can be accessed by column name, which
    makes the rest of the code much easier to read (row["username"]).
    """
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    """Create all tables if they do not already exist.

    This is safe to call every time the program starts, so the database is
    always ready and initialises automatically.
    """
    connection = get_connection()
    cursor = connection.cursor()

    # ---- users table ----------------------------------------------------
    # We store only the salt and the derived password hash (never the
    # plaintext password).
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            salt          TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at    TEXT NOT NULL
        )
        """
    )

    # ---- messages table -------------------------------------------------
    # Everything binary (ciphertext, nonce, salt, hmac) is stored base64
    # encoded as TEXT. The "tampered" column is a small flag we set to 1
    # when the attack simulation modifies a message.
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            sender     TEXT NOT NULL,
            receiver   TEXT NOT NULL,
            timestamp  TEXT NOT NULL,
            nonce      TEXT NOT NULL,
            salt       TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            hmac       TEXT NOT NULL,
            tampered   INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    # ---- logs table -----------------------------------------------------
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT NOT NULL,
            event_type TEXT NOT NULL,
            username   TEXT,
            details    TEXT
        )
        """
    )

    connection.commit()
    connection.close()


# ---------------------------------------------------------------------------
# User helpers
# ---------------------------------------------------------------------------

def insert_user(username, salt, password_hash, created_at):
    """Insert a new user. Returns True on success, False if the username
    already exists (UNIQUE constraint)."""
    connection = get_connection()
    try:
        connection.execute(
            "INSERT INTO users (username, salt, password_hash, created_at) "
            "VALUES (?, ?, ?, ?)",
            (username, salt, password_hash, created_at),
        )
        connection.commit()
        return True
    except sqlite3.IntegrityError:
        # Raised when the username is already taken.
        return False
    finally:
        connection.close()


def get_user(username):
    """Return the user row for a username, or None if not found."""
    connection = get_connection()
    row = connection.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    connection.close()
    return row


def user_exists(username):
    """Convenience helper used when validating a message receiver."""
    return get_user(username) is not None


# ---------------------------------------------------------------------------
# Message helpers
# ---------------------------------------------------------------------------

def insert_message(sender, receiver, timestamp, nonce, salt, ciphertext, hmac):
    """Store one encrypted message. Returns the new message id."""
    connection = get_connection()
    cursor = connection.execute(
        """
        INSERT INTO messages
            (sender, receiver, timestamp, nonce, salt, ciphertext, hmac, tampered)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0)
        """,
        (sender, receiver, timestamp, nonce, salt, ciphertext, hmac),
    )
    connection.commit()
    message_id = cursor.lastrowid
    connection.close()
    return message_id


def get_messages_for_user(receiver):
    """Return all messages addressed to a given receiver (newest last)."""
    connection = get_connection()
    rows = connection.execute(
        "SELECT * FROM messages WHERE receiver = ? ORDER BY id ASC",
        (receiver,),
    ).fetchall()
    connection.close()
    return rows


def get_latest_message_for_user(receiver):
    """Return the most recent message for a receiver, or None."""
    connection = get_connection()
    row = connection.execute(
        "SELECT * FROM messages WHERE receiver = ? ORDER BY id DESC LIMIT 1",
        (receiver,),
    ).fetchone()
    connection.close()
    return row


def update_message_fields(message_id, ciphertext, hmac, tampered):
    """Overwrite the ciphertext / hmac / tampered flag of a message.

    Used by the attack simulation to persist a tampered message so the
    receiver can later try (and fail) to open it.
    """
    connection = get_connection()
    connection.execute(
        "UPDATE messages SET ciphertext = ?, hmac = ?, tampered = ? WHERE id = ?",
        (ciphertext, hmac, tampered, message_id),
    )
    connection.commit()
    connection.close()


# ---------------------------------------------------------------------------
# Log helpers
# ---------------------------------------------------------------------------

def insert_log(timestamp, event_type, username, details):
    """Append a single security log entry."""
    connection = get_connection()
    connection.execute(
        "INSERT INTO logs (timestamp, event_type, username, details) "
        "VALUES (?, ?, ?, ?)",
        (timestamp, event_type, username, details),
    )
    connection.commit()
    connection.close()


def get_logs(limit=100):
    """Return the most recent log entries (newest first)."""
    connection = get_connection()
    rows = connection.execute(
        "SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    connection.close()
    return rows
