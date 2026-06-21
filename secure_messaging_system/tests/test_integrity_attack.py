"""
test_integrity_attack.py
------------------------
Tests for HMAC integrity verification and the tampering attack simulation.
"""

import pytest

import attack_simulation
import crypto_utils
import database
import demo_data


SHARED_SECRET = "river-blue-42"


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Fresh temporary database with demo data for every test."""
    test_db = tmp_path / "test.db"
    monkeypatch.setattr(database, "DB_PATH", test_db)
    database.init_db()
    demo_data.main()  # creates alice/bob and one demo message to bob
    yield


def _mac_key_for(message):
    key_material = crypto_utils.derive_key_from_shared_secret(
        SHARED_SECRET, crypto_utils.from_b64(message["salt"])
    )
    _aes_key, mac_key = crypto_utils.split_keys(key_material)
    return mac_key


def _mac_data_for(message):
    return crypto_utils.build_mac_data(
        message["sender"], message["receiver"], message["timestamp"],
        message["nonce"], message["salt"], message["ciphertext"],
    )


def test_hmac_verifies_for_untampered_message():
    message = database.get_latest_message_for_user("bob")
    mac_key = _mac_key_for(message)
    assert crypto_utils.verify_hmac(mac_key, _mac_data_for(message), message["hmac"])


def test_tampering_ciphertext_is_detected_by_hmac():
    ok, _ = attack_simulation.tamper_latest_message("bob", target="ciphertext")
    assert ok is True

    message = database.get_latest_message_for_user("bob")
    assert message["tampered"] == 1

    mac_key = _mac_key_for(message)
    # HMAC over the (now changed) ciphertext no longer matches the stored tag.
    assert not crypto_utils.verify_hmac(
        mac_key, _mac_data_for(message), message["hmac"]
    )


def test_tampering_hmac_is_detected():
    ok, _ = attack_simulation.tamper_latest_message("bob", target="hmac")
    assert ok is True

    message = database.get_latest_message_for_user("bob")
    mac_key = _mac_key_for(message)
    assert not crypto_utils.verify_hmac(
        mac_key, _mac_data_for(message), message["hmac"]
    )


def test_tampered_ciphertext_fails_to_decrypt():
    attack_simulation.tamper_latest_message("bob", target="ciphertext")
    message = database.get_latest_message_for_user("bob")
    aad = crypto_utils.build_aad(
        message["sender"], message["receiver"], message["timestamp"]
    )
    with pytest.raises(Exception):
        crypto_utils.decrypt_message(
            message["ciphertext"], message["nonce"], message["salt"],
            SHARED_SECRET, aad,
        )


def test_attack_on_empty_inbox_reports_nothing_to_attack():
    ok, message = attack_simulation.tamper_latest_message("alice")
    assert ok is False
    assert "no messages" in message.lower()
