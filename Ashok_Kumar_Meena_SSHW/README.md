# Secure Messaging System Using Encryption Techniques

A command-line (CLI) application written in **Python 3** that demonstrates a
secure messaging system. Users register and log in, then exchange messages that
are **encrypted with AES-GCM** and protected against tampering with
**HMAC-SHA256**. The project also includes a **Man-in-the-Middle (MITM)
tampering attack simulation**, a **brute-force login** demonstration and a
**security logging** system.

> Educational university project for a Software Security course.

---

## Features

- User **registration** and **login** with a simple CLI menu.
- Passwords stored using **PBKDF2-HMAC-SHA256** with a random per-user salt
  (never plaintext).
- Basic **session handling** (a `current_user` after login).
- **AES-GCM** symmetric encryption of messages with a fresh random nonce each
  time.
- Encryption keys are **derived from a user-entered shared secret** with PBKDF2
  — keys are **never hardcoded** and the secret is **never stored**.
- **HMAC-SHA256** integrity over sender, receiver, timestamp, nonce, salt and
  ciphertext, verified **before** decryption.
- **Tampering detection**: any modification of a stored message is detected.
- **Attack simulation** (MITM tampering) and **brute-force login** logging.
- **Security logging** of login attempts, encryption events, failed
  decryptions and attack results.

---

## Project structure

```
Ashok_Kumar_Meena_SSHW/
├── source_code/
│   ├── app.py                 # CLI entry point (the menu)
│   ├── auth.py                # registration, login, password hashing
│   ├── crypto_utils.py        # AES-GCM encryption + HMAC integrity
│   ├── database.py            # SQLite storage (users, messages, logs)
│   ├── logger_utils.py        # security logging
│   ├── attack_simulation.py   # MITM / tampering simulation
│   ├── demo_data.py           # demo users alice & bob + a demo message
│   └── requirements.txt
├── tests/
│   ├── test_auth.py
│   ├── test_crypto.py
│   └── test_integrity_attack.py
├── screenshots/               # screenshots of every feature
├── conftest.py                # lets pytest import the source_code modules
├── README.md
├── USER_GUIDE.md
└── Ashok_Kumar_Meena_SS_SE26_Report.pdf
```

The SQLite database file `secure_messages.db` is created automatically inside
`source_code/` the first time the app runs.

---

## Installation

Requires Python 3.10+.

```bash
cd source_code
python -m pip install -r requirements.txt
```

This installs the `cryptography` package (for AES-GCM) and `pytest`.

---

## How to run

```bash
cd source_code
python demo_data.py     # optional: create alice & bob (password: Password123!)
python app.py           # start the CLI
```

Use the menu to register, log in, send encrypted messages, view your inbox,
run the attack simulation and view the logs.

---

## How to test

From the project root (the folder that contains `conftest.py`):

```bash
pytest          # or: pytest -v
```

19 tests cover password hashing/verification, AES encrypt/decrypt round trips,
wrong-secret failure and HMAC tampering detection.

---

## Security design (summary)

- **Passwords**: PBKDF2-HMAC-SHA256 (200,000 iterations) with a random salt;
  only the salt and hash are stored, compared in constant time on login.
- **Messages**: AES-256-GCM with a fresh random salt and nonce per message; the
  key is derived from the shared chat secret with PBKDF2 (never hardcoded).
- **Integrity**: HMAC-SHA256 over the message fields, verified before
  decryption; AES-GCM provides a second, independent integrity check.
- **Secrets**: the shared chat secret is entered with `getpass`, used only in
  memory and never written to the database or logs.

---

## Screenshots

| Feature | Image |
|---|---|
| Registration | `screenshots/registration.png` |
| Login | `screenshots/login.png` |
| Sending an encrypted message | `screenshots/send_message.png` |
| Inbox decryption | `screenshots/inbox_decryption.png` |
| MITM tampering attack | `screenshots/mitm_attack.png` |
| Integrity check failure | `screenshots/integrity_failed.png` |
| Brute-force login logging | `screenshots/brute_force.png` |
| Security logs | `screenshots/logs.png` |

---

## Limitations

- The shared chat secret must be exchanged out-of-band (no key exchange such as
  Diffie-Hellman is implemented).
- The SQLite database file is not encrypted at rest; security relies on
  message-level encryption.
- No account lockout / rate limiting on repeated failed logins.
- Single-machine demo — the MITM attack is simulated by editing the stored
  message rather than over a real network.

See `Ashok_Kumar_Meena_SS_SE26_Report.pdf` for the full report.
