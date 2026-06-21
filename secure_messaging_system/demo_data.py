"""
demo_data.py
------------
Creates demo users and an example encrypted message so the application can be
demonstrated immediately without manual data entry.

Demo users:
    alice / Password123!
    bob   / Password123!

A sample message is sent from alice to bob using the shared secret below.
NOTE: the demo password and demo shared secret are hardcoded ONLY here, in the
demo helper, so the project is easy to test. The real application never
hardcodes passwords, keys or secrets.

Run with:  python demo_data.py
"""

from datetime import datetime, timezone

import auth
import crypto_utils
import database

DEMO_PASSWORD = "Password123!"
DEMO_SHARED_SECRET = "river-blue-42"   # the secret alice and bob "agreed on"


def _send_demo_message(sender, receiver, plaintext, shared_secret):
    """Encrypt and store one demo message (mirrors app.do_send_message)."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    aad = crypto_utils.build_aad(sender, receiver, timestamp)
    enc = crypto_utils.encrypt_message(plaintext, shared_secret, aad)

    mac_data = crypto_utils.build_mac_data(
        sender, receiver, timestamp, enc["nonce"], enc["salt"], enc["ciphertext"]
    )
    key_material = crypto_utils.derive_key_from_shared_secret(
        shared_secret, crypto_utils.from_b64(enc["salt"])
    )
    _aes_key, mac_key = crypto_utils.split_keys(key_material)
    message_hmac = crypto_utils.create_hmac(mac_key, mac_data)

    return database.insert_message(
        sender, receiver, timestamp,
        enc["nonce"], enc["salt"], enc["ciphertext"], message_hmac,
    )


def main():
    database.init_db()
    print("Initialising demo data...")

    for username in ("alice", "bob"):
        ok, message = auth.register_user(username, DEMO_PASSWORD)
        print(f"  user '{username}': {message}")

    # Send a demo message from alice to bob (only if bob has no inbox yet, so
    # running this repeatedly does not pile up duplicates).
    if not database.get_messages_for_user("bob"):
        message_id = _send_demo_message(
            "alice", "bob",
            "Hello Bob, this is a secret demo message from Alice!",
            DEMO_SHARED_SECRET,
        )
        print(f"  demo message id={message_id} sent from alice to bob")
    else:
        print("  demo message already exists for bob (skipped)")

    print("\nDemo data ready.")
    print(f"  Login with: alice / {DEMO_PASSWORD}  or  bob / {DEMO_PASSWORD}")
    print(f"  Shared chat secret for the demo message: {DEMO_SHARED_SECRET}")
    print("  Log in as bob and open the inbox using that secret to decrypt it.")


if __name__ == "__main__":
    main()
