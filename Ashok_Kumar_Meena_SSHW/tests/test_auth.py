"""
test_auth.py
------------
Tests for password hashing and the register / login flow.

We point the database at a temporary file so the tests never touch the real
secure_messages.db.
"""

import secrets

import pytest

import auth
import database


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Use a fresh temporary database for every test."""
    test_db = tmp_path / "test.db"
    monkeypatch.setattr(database, "DB_PATH", test_db)
    database.init_db()
    yield


def test_hash_password_is_deterministic_with_same_salt():
    salt = secrets.token_bytes(16)
    h1 = auth.hash_password("Password123!", salt)
    h2 = auth.hash_password("Password123!", salt)
    assert h1 == h2  # same password + same salt -> same hash


def test_hash_password_differs_with_different_salt():
    h1 = auth.hash_password("Password123!", secrets.token_bytes(16))
    h2 = auth.hash_password("Password123!", secrets.token_bytes(16))
    assert h1 != h2  # random salt makes hashes differ


def test_verify_password_correct_and_wrong():
    salt = secrets.token_bytes(16)
    stored = auth.hash_password("Password123!", salt)
    assert auth.verify_password("Password123!", salt, stored) is True
    assert auth.verify_password("wrong-password", salt, stored) is False


def test_register_and_login_success():
    ok, _ = auth.register_user("alice", "Password123!")
    assert ok is True

    ok, _ = auth.login_user("alice", "Password123!")
    assert ok is True


def test_register_duplicate_username_fails():
    auth.register_user("bob", "Password123!")
    ok, message = auth.register_user("bob", "AnotherPass1!")
    assert ok is False
    assert "exists" in message.lower()


def test_login_wrong_password_fails():
    auth.register_user("carol", "Password123!")
    ok, _ = auth.login_user("carol", "not-the-password")
    assert ok is False


def test_login_unknown_user_fails():
    ok, _ = auth.login_user("nobody", "whatever")
    assert ok is False


def test_plaintext_password_is_never_stored():
    auth.register_user("dave", "SuperSecret1!")
    user = database.get_user("dave")
    assert "SuperSecret1!" not in user["password_hash"]
    assert "SuperSecret1!" not in user["salt"]
