# User Guide — Secure Messaging System

This guide walks through every feature step by step. Follow it in order to
produce a complete demonstration (and all the screenshots listed in
`screenshots_needed.md`).

---

## 1. Setup

```bash
cd secure_messaging_system
python -m pip install -r requirements.txt
```

## 2. (Optional) Load demo data

```bash
python demo_data.py
```

This creates two users:

| Username | Password      |
|----------|---------------|
| alice    | Password123!  |
| bob      | Password123!  |

and sends one demo message from **alice** to **bob** using the shared secret
**`river-blue-42`**.

## 3. Start the application

```bash
python app.py
```

You will see the main menu:

```
  1. Register
  2. Login
  3. Send encrypted message
  4. View inbox and decrypt messages
  5. Simulate tampering attack
  6. View security logs
  7. Logout
  8. Exit
```

---

## 4. Register a new user (menu option 1)

1. Choose `1`.
2. Enter a username.
3. Enter and confirm a password (typing is hidden).
4. You should see **"Registration successful."**

## 5. Log in (menu option 2)

1. Choose `2`.
2. Enter your username and password.
3. You should see **"Login successful!"** and a welcome message.

## 6. Send an encrypted message (menu option 3)

1. Choose `3`.
2. Enter the **receiver's username** (must already exist).
3. Enter the **shared chat secret** — a secret phrase you and the receiver
   agreed on beforehand (input is hidden).
4. Type your message.
5. The app encrypts the message, computes an HMAC, stores it and prints the
   base64 ciphertext.

> The receiver must use the **same shared secret** to read the message.

## 7. Read your inbox (menu option 4)

1. Log in as the **receiver**.
2. Choose `4`.
3. Enter the **shared chat secret**.
4. For each message the app:
   - verifies the HMAC,
   - decrypts the ciphertext,
   - prints **">> Decrypted message: ..."**.

If the secret is wrong, decryption fails gracefully and the attempt is logged.

## 8. Run the attack simulation (menu option 5)

1. Log in as the user whose inbox you want to attack (e.g. **bob**).
2. Choose `5`.
3. Pick a target: `1` for ciphertext or `2` for the HMAC tag.
4. The app flips one byte of the latest message and marks it as tampered.

## 9. See the tampering detected (menu option 4 again)

1. Still logged in as the receiver, choose `4`.
2. Enter the shared secret.
3. The tampered message now shows:
   **">> Integrity check failed. Message may have been modified."**

## 10. View the security logs (menu option 6)

Choose `6` to see a table of all logged events: logins, registrations,
encryption events, decryption successes/failures, integrity failures and attack
simulations.

---

## Full demo script (quick path)

```bash
python demo_data.py          # alice, bob + demo message
python app.py
# -> 2 (login as bob / Password123!)
# -> 4 (inbox, secret: river-blue-42)   => message decrypts
# -> 5 (attack, choose 1 ciphertext)
# -> 4 (inbox, secret: river-blue-42)   => integrity check fails
# -> 6 (view logs)
# -> 8 (exit)
```

Use `python view_db.py` at any time to display the raw database contents and
prove that only ciphertext and password hashes are stored.
