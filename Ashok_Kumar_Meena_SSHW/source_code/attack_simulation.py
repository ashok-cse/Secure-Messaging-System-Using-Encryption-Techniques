"""
attack_simulation.py
--------------------
Simulates a Man-in-the-Middle / tampering attack.

In a real attack, an adversary on the network would intercept a message and
change its contents while it is in transit. We simulate exactly that by taking
a stored message and flipping a single byte in either its ciphertext or its
HMAC tag, then saving it back to the database.

When the receiver later opens the message, the HMAC verification (and the
AES-GCM authentication) will fail, and the application will correctly report:
    "Integrity check failed. Message may have been modified."
"""

import crypto_utils
import database
import logger_utils


def _flip_one_byte_b64(b64_value):
    """Flip a single byte of a base64-encoded binary value.

    We decode to raw bytes, XOR one byte with 0x01 (a tiny change), and
    re-encode. Returns the new base64 string.
    """
    raw = bytearray(crypto_utils.from_b64(b64_value))
    if not raw:
        return b64_value
    # Flip the lowest bit of the first byte - a minimal modification that is
    # still guaranteed to be detected.
    raw[0] ^= 0x01
    return crypto_utils.to_b64(bytes(raw))


def tamper_latest_message(receiver, target="ciphertext"):
    """Tamper with the latest message addressed to `receiver`.

    Parameters
    ----------
    receiver : str   - the user whose newest message will be attacked
    target   : str   - "ciphertext" or "hmac": which field to modify

    Returns (True, message) if a message was tampered with, otherwise
    (False, message) if there was nothing to attack.
    """
    message = database.get_latest_message_for_user(receiver)
    if message is None:
        return False, f"No messages found for '{receiver}' to attack."

    if target == "hmac":
        new_ciphertext = message["ciphertext"]
        new_hmac = _flip_one_byte_b64(message["hmac"])
        what = "HMAC tag"
    else:
        new_ciphertext = _flip_one_byte_b64(message["ciphertext"])
        new_hmac = message["hmac"]
        what = "ciphertext"

    # Persist the tampered message and mark it so the demo is obvious.
    database.update_message_fields(
        message["id"], new_ciphertext, new_hmac, tampered=1
    )

    details = (
        f"MITM/tampering attack: modified {what} of message id={message['id']} "
        f"from '{message['sender']}' to '{receiver}'"
    )
    logger_utils.log_event(
        logger_utils.ATTACK_SIMULATION, receiver, details
    )

    return True, (
        f"Attack complete. The {what} of message id={message['id']} "
        f"(from '{message['sender']}') was modified.\n"
        f"Ask '{receiver}' to open their inbox to see the integrity check fail."
    )
