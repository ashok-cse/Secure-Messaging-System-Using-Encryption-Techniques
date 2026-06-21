"""
crypto_utils.py
---------------
All cryptography for the Secure Messaging System lives here.

Design summary:
  * Key derivation : PBKDF2-HMAC-SHA256 turns the user-entered shared chat
                     secret + a random salt into strong binary keys.
                     We derive 64 bytes and split them:
                        bytes  0..31  -> AES encryption key
                        bytes 32..63  -> HMAC key
  * Encryption     : AES-GCM with a fresh random 12-byte nonce per message.
  * Integrity      : HMAC-SHA256 over the important message fields.

No keys are ever hardcoded. The shared secret is never stored or logged.
Binary values are base64 encoded so they can be saved as text in SQLite.
"""

import base64
import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# PBKDF2 parameters. 200k iterations is a reasonable, well-known default
# that is strong but still fast enough for an interactive CLI demo.
PBKDF2_ITERATIONS = 200_000
DERIVED_KEY_LENGTH = 64  # 32 bytes for AES + 32 bytes for HMAC
AES_KEY_LENGTH = 32      # AES-256
NONCE_LENGTH = 12        # Recommended nonce size for AES-GCM
SALT_LENGTH = 16


# ---------------------------------------------------------------------------
# Small base64 helpers (binary <-> text for database storage)
# ---------------------------------------------------------------------------

def to_b64(raw_bytes):
    """Encode raw bytes as a base64 text string."""
    return base64.b64encode(raw_bytes).decode("utf-8")


def from_b64(text):
    """Decode a base64 text string back into raw bytes."""
    return base64.b64decode(text.encode("utf-8"))


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_key_from_shared_secret(shared_secret, salt):
    """Derive 64 bytes of key material from a shared secret and salt.

    Returns the raw 64-byte value. Callers split it into:
        key_material[:32] -> AES key
        key_material[32:] -> HMAC key

    Using PBKDF2-HMAC-SHA256 makes it expensive to brute-force the shared
    secret, and the random per-message salt means the same secret produces
    different keys for every message.
    """
    if isinstance(shared_secret, str):
        shared_secret = shared_secret.encode("utf-8")
    return hashlib.pbkdf2_hmac(
        "sha256", shared_secret, salt, PBKDF2_ITERATIONS, dklen=DERIVED_KEY_LENGTH
    )


def split_keys(key_material):
    """Split derived key material into (aes_key, mac_key)."""
    return key_material[:AES_KEY_LENGTH], key_material[AES_KEY_LENGTH:]


# ---------------------------------------------------------------------------
# AES-GCM encryption / decryption
# ---------------------------------------------------------------------------

def encrypt_message(plaintext, shared_secret, aad):
    """Encrypt a plaintext string with AES-GCM.

    A fresh random salt and nonce are generated for every message, so keys
    and ciphertexts are never reused.

    Parameters
    ----------
    plaintext : str  - the message to protect
    shared_secret : str - the secret both users agreed on
    aad : bytes - additional authenticated data (e.g. sender|receiver|time).
                  It is authenticated by GCM but not encrypted.

    Returns a dict of base64 text values ready to store in the database:
        {"ciphertext": ..., "nonce": ..., "salt": ...}
    """
    salt = secrets.token_bytes(SALT_LENGTH)
    nonce = secrets.token_bytes(NONCE_LENGTH)

    key_material = derive_key_from_shared_secret(shared_secret, salt)
    aes_key, _mac_key = split_keys(key_material)

    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)

    return {
        "ciphertext": to_b64(ciphertext),
        "nonce": to_b64(nonce),
        "salt": to_b64(salt),
    }


def decrypt_message(ciphertext, nonce, salt, shared_secret, aad):
    """Decrypt an AES-GCM message.

    All of ciphertext, nonce and salt are base64 text strings (as stored in
    the database). Raises an exception if the shared secret is wrong or the
    ciphertext was modified (GCM authentication failure).

    Returns the decrypted plaintext string.
    """
    salt_bytes = from_b64(salt)
    nonce_bytes = from_b64(nonce)
    ciphertext_bytes = from_b64(ciphertext)

    key_material = derive_key_from_shared_secret(shared_secret, salt_bytes)
    aes_key, _mac_key = split_keys(key_material)

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce_bytes, ciphertext_bytes, aad)
    return plaintext.decode("utf-8")


# ---------------------------------------------------------------------------
# HMAC message integrity
# ---------------------------------------------------------------------------

def create_hmac(mac_key, data):
    """Create an HMAC-SHA256 tag for `data`, returned as base64 text.

    `data` may be str or bytes; `mac_key` is raw bytes.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    tag = hmac.new(mac_key, data, hashlib.sha256).digest()
    return to_b64(tag)


def verify_hmac(mac_key, data, expected_hmac):
    """Return True if the HMAC of `data` matches `expected_hmac`.

    We use hmac.compare_digest for a constant-time comparison, which avoids
    leaking information through timing differences.
    """
    calculated = create_hmac(mac_key, data)
    return hmac.compare_digest(calculated, expected_hmac)


def build_mac_data(sender, receiver, timestamp, nonce, salt, ciphertext):
    """Build the canonical string that the HMAC is computed over.

    Including all of these fields means an attacker cannot change the
    sender, receiver, timestamp, nonce, salt or ciphertext without breaking
    the HMAC.
    """
    return "|".join([sender, receiver, timestamp, nonce, salt, ciphertext])


def build_aad(sender, receiver, timestamp):
    """Additional authenticated data for AES-GCM (bound to the context)."""
    return "|".join([sender, receiver, timestamp]).encode("utf-8")
