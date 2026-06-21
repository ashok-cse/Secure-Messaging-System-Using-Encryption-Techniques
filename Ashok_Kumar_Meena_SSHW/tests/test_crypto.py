"""
test_crypto.py
--------------
Tests for AES-GCM encryption / decryption and key derivation.
"""

import pytest

import crypto_utils


SHARED_SECRET = "river-blue-42"
AAD = crypto_utils.build_aad("alice", "bob", "2026-06-21 10:00:00")


def test_encrypt_then_decrypt_roundtrip():
    plaintext = "Hello Bob, this is a secret!"
    enc = crypto_utils.encrypt_message(plaintext, SHARED_SECRET, AAD)
    result = crypto_utils.decrypt_message(
        enc["ciphertext"], enc["nonce"], enc["salt"], SHARED_SECRET, AAD
    )
    assert result == plaintext


def test_ciphertext_is_not_plaintext():
    plaintext = "do not leak me"
    enc = crypto_utils.encrypt_message(plaintext, SHARED_SECRET, AAD)
    assert plaintext not in enc["ciphertext"]


def test_each_message_uses_fresh_nonce_and_salt():
    enc1 = crypto_utils.encrypt_message("same text", SHARED_SECRET, AAD)
    enc2 = crypto_utils.encrypt_message("same text", SHARED_SECRET, AAD)
    # Random nonce + salt per message means ciphertexts differ even for the
    # same plaintext and secret.
    assert enc1["nonce"] != enc2["nonce"]
    assert enc1["salt"] != enc2["salt"]
    assert enc1["ciphertext"] != enc2["ciphertext"]


def test_wrong_secret_fails_to_decrypt():
    enc = crypto_utils.encrypt_message("top secret", SHARED_SECRET, AAD)
    with pytest.raises(Exception):
        crypto_utils.decrypt_message(
            enc["ciphertext"], enc["nonce"], enc["salt"], "wrong-secret", AAD
        )


def test_wrong_aad_fails_to_decrypt():
    enc = crypto_utils.encrypt_message("bound to context", SHARED_SECRET, AAD)
    other_aad = crypto_utils.build_aad("eve", "bob", "2026-06-21 10:00:00")
    with pytest.raises(Exception):
        crypto_utils.decrypt_message(
            enc["ciphertext"], enc["nonce"], enc["salt"], SHARED_SECRET, other_aad
        )


def test_key_derivation_splits_into_two_distinct_keys():
    salt = b"0123456789abcdef"
    key_material = crypto_utils.derive_key_from_shared_secret(SHARED_SECRET, salt)
    aes_key, mac_key = crypto_utils.split_keys(key_material)
    assert len(aes_key) == 32
    assert len(mac_key) == 32
    assert aes_key != mac_key
