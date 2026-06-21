"""
auth.py
-------
User authentication: registration, login and password handling.

Passwords are protected with PBKDF2-HMAC-SHA256 and a random per-user salt.
We never store or log the plaintext password. The database only ever sees the
salt and the derived hash.
"""

import hashlib
import secrets
from datetime import datetime, timezone

import database
import logger_utils

# PBKDF2 parameters for password hashing. These are independent from the
# message-encryption parameters in crypto_utils.
PBKDF2_ITERATIONS = 200_000
HASH_LENGTH = 32
SALT_LENGTH = 16


def hash_password(password, salt):
    """Hash a password with PBKDF2-HMAC-SHA256.

    `salt` is raw bytes. Returns the hash as a hex string so it can be stored
    as text and compared easily.
    """
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=HASH_LENGTH
    )
    return derived.hex()


def verify_password(password, salt, stored_hash):
    """Return True if `password` matches the stored hash.

    `salt` is raw bytes, `stored_hash` is the hex string from the database.
    A constant-time comparison is used to avoid timing attacks.
    """
    calculated = hash_password(password, salt)
    return secrets.compare_digest(calculated, stored_hash)


def register_user(username, password):
    """Register a new user.

    Returns (True, message) on success, or (False, message) if the username
    already exists or the input is invalid.
    """
    username = (username or "").strip()
    if not username:
        return False, "Username cannot be empty."
    if not password:
        return False, "Password cannot be empty."

    # Reject duplicate usernames early for a friendly message (the database
    # also enforces this with a UNIQUE constraint as a safety net).
    if database.user_exists(username):
        logger_utils.log_event(
            logger_utils.REGISTER, username, "Registration failed: username exists"
        )
        return False, "Username already exists. Please choose another."

    # Generate a fresh random salt for this user and derive the hash.
    salt = secrets.token_bytes(SALT_LENGTH)
    password_hash = hash_password(password, salt)
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # Store the salt as hex text alongside the hash.
    ok = database.insert_user(username, salt.hex(), password_hash, created_at)
    if not ok:
        return False, "Username already exists. Please choose another."

    logger_utils.log_event(
        logger_utils.REGISTER, username, "New user registered"
    )
    return True, "Registration successful."


def login_user(username, password):
    """Attempt to log a user in.

    Returns (True, message) on success or (False, message) on failure.
    Every attempt is logged (success or failure).
    """
    username = (username or "").strip()
    user = database.get_user(username)

    # Important: give the same generic error whether the user is missing or
    # the password is wrong, so we do not reveal which usernames exist.
    if user is None:
        logger_utils.log_event(
            logger_utils.LOGIN_FAILURE, username, "Login failed: no such user"
        )
        return False, "Invalid username or password."

    salt = bytes.fromhex(user["salt"])
    if verify_password(password, salt, user["password_hash"]):
        logger_utils.log_event(
            logger_utils.LOGIN_SUCCESS, username, "Login successful"
        )
        return True, "Login successful."

    logger_utils.log_event(
        logger_utils.LOGIN_FAILURE, username, "Login failed: wrong password"
    )
    return False, "Invalid username or password."
