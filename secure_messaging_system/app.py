"""
app.py
------
Command line interface for the Secure Messaging System.

This is the entry point that ties everything together:
  * auth.py            - registration and login
  * crypto_utils.py    - AES-GCM encryption + HMAC integrity
  * attack_simulation  - MITM / tampering demo
  * database.py        - SQLite storage
  * logger_utils.py    - security logging

Run with:  python app.py
"""

from datetime import datetime, timezone
from getpass import getpass

import attack_simulation
import auth
import crypto_utils
import database
import logger_utils


# Simple in-memory session: holds the username of the logged in user, or None.
current_user = None


def _timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _pause():
    input("\nPress Enter to continue...")


# ---------------------------------------------------------------------------
# Menu actions
# ---------------------------------------------------------------------------

def do_register():
    print("\n--- Register ---")
    username = input("Choose a username: ").strip()
    password = getpass("Choose a password: ")
    confirm = getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match. Please try again.")
        return
    ok, message = auth.register_user(username, password)
    print(message)


def do_login():
    global current_user
    print("\n--- Login ---")
    username = input("Username: ").strip()
    password = getpass("Password: ")
    ok, message = auth.login_user(username, password)
    print(message)
    if ok:
        current_user = username
        print(f"Welcome, {current_user}!")


def do_logout():
    global current_user
    if current_user:
        logger_utils.log_event(logger_utils.LOGOUT, current_user, "User logged out")
        print(f"Goodbye, {current_user}.")
        current_user = None
    else:
        print("You are not logged in.")


def do_send_message():
    if not current_user:
        print("You must be logged in to send a message.")
        return

    print("\n--- Send Encrypted Message ---")
    receiver = input("Receiver username: ").strip()
    if not database.user_exists(receiver):
        print(f"User '{receiver}' does not exist.")
        return

    # The shared chat secret is typed with getpass so it is not shown on
    # screen. It is never stored or logged.
    shared_secret = getpass("Shared chat secret (agreed with receiver): ")
    if not shared_secret:
        print("Shared secret cannot be empty.")
        return

    plaintext = input("Message: ")
    if not plaintext:
        print("Message cannot be empty.")
        return

    timestamp = _timestamp()

    # 1) Encrypt with AES-GCM. AAD binds the ciphertext to sender/receiver/time.
    aad = crypto_utils.build_aad(current_user, receiver, timestamp)
    enc = crypto_utils.encrypt_message(plaintext, shared_secret, aad)

    # 2) Create an HMAC over all the important fields for integrity.
    mac_data = crypto_utils.build_mac_data(
        current_user, receiver, timestamp,
        enc["nonce"], enc["salt"], enc["ciphertext"],
    )
    key_material = crypto_utils.derive_key_from_shared_secret(
        shared_secret, crypto_utils.from_b64(enc["salt"])
    )
    _aes_key, mac_key = crypto_utils.split_keys(key_material)
    message_hmac = crypto_utils.create_hmac(mac_key, mac_data)

    # 3) Store the encrypted message (never the plaintext or the secret).
    message_id = database.insert_message(
        current_user, receiver, timestamp,
        enc["nonce"], enc["salt"], enc["ciphertext"], message_hmac,
    )

    logger_utils.log_event(
        logger_utils.ENCRYPT, current_user,
        f"Encrypted message id={message_id} to '{receiver}'",
    )
    print(f"\nMessage encrypted and sent to '{receiver}'. (id={message_id})")
    print("Stored ciphertext (base64):", enc["ciphertext"])


def do_view_inbox():
    if not current_user:
        print("You must be logged in to view your inbox.")
        return

    print("\n--- Inbox ---")
    messages = database.get_messages_for_user(current_user)
    if not messages:
        print("Your inbox is empty.")
        return

    print(f"You have {len(messages)} message(s).")
    shared_secret = getpass("Shared chat secret to decrypt your messages: ")

    for message in messages:
        print("\n" + "-" * 50)
        flag = " (TAMPERED in DB)" if message["tampered"] else ""
        print(f"Message id={message['id']} from '{message['sender']}' "
              f"at {message['timestamp']}{flag}")

        # Rebuild the data the HMAC was computed over.
        mac_data = crypto_utils.build_mac_data(
            message["sender"], message["receiver"], message["timestamp"],
            message["nonce"], message["salt"], message["ciphertext"],
        )
        key_material = crypto_utils.derive_key_from_shared_secret(
            shared_secret, crypto_utils.from_b64(message["salt"])
        )
        _aes_key, mac_key = crypto_utils.split_keys(key_material)

        # STEP 1: verify integrity BEFORE attempting to decrypt.
        if not crypto_utils.verify_hmac(mac_key, mac_data, message["hmac"]):
            print(">> Integrity check failed. Message may have been modified.")
            logger_utils.log_event(
                logger_utils.INTEGRITY_FAILURE, current_user,
                f"HMAC verification failed for message id={message['id']}",
            )
            continue

        # STEP 2: decrypt. AES-GCM gives a second integrity guarantee.
        aad = crypto_utils.build_aad(
            message["sender"], message["receiver"], message["timestamp"]
        )
        try:
            plaintext = crypto_utils.decrypt_message(
                message["ciphertext"], message["nonce"], message["salt"],
                shared_secret, aad,
            )
        except Exception:
            # Wrong shared secret or tampered ciphertext both land here.
            print(">> Decryption failed. Wrong secret or message was modified.")
            logger_utils.log_event(
                logger_utils.DECRYPT_FAILURE, current_user,
                f"Decryption failed for message id={message['id']}",
            )
            continue

        print(f">> Decrypted message: {plaintext}")
        logger_utils.log_event(
            logger_utils.DECRYPT_SUCCESS, current_user,
            f"Decrypted message id={message['id']}",
        )


def do_attack_simulation():
    if not current_user:
        print("You must be logged in to run the attack simulation.")
        return

    print("\n--- Attack Simulation (MITM / Tampering) ---")
    print("This will modify the latest message in YOUR inbox to simulate")
    print("an attacker changing the data in transit.")
    print("  1. Tamper with the ciphertext")
    print("  2. Tamper with the HMAC tag")
    choice = input("Choose target [1/2]: ").strip()
    target = "hmac" if choice == "2" else "ciphertext"

    ok, message = attack_simulation.tamper_latest_message(current_user, target)
    print(message)
    if ok:
        print("\nNow choose option 4 (View inbox) to see the detection.")


def do_view_logs():
    print("\n--- Security Logs ---")
    logger_utils.display_logs()


# ---------------------------------------------------------------------------
# Main menu loop
# ---------------------------------------------------------------------------

MENU = """
================ SECURE MESSAGING SYSTEM ================
  Logged in as: {user}
--------------------------------------------------------
  1. Register
  2. Login
  3. Send encrypted message
  4. View inbox and decrypt messages
  5. Simulate tampering attack
  6. View security logs
  7. Logout
  8. Exit
========================================================"""


def main():
    # The database initialises automatically on startup.
    database.init_db()

    print("Welcome to the Secure Messaging System.")
    while True:
        print(MENU.format(user=current_user if current_user else "(not logged in)"))
        choice = input("Select an option [1-8]: ").strip()

        if choice == "1":
            do_register()
        elif choice == "2":
            do_login()
        elif choice == "3":
            do_send_message()
        elif choice == "4":
            do_view_inbox()
        elif choice == "5":
            do_attack_simulation()
        elif choice == "6":
            do_view_logs()
        elif choice == "7":
            do_logout()
        elif choice == "8":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please choose a number from 1 to 8.")

        _pause()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nExiting. Goodbye!")
