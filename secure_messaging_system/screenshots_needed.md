# Screenshots to Include in the Report

Take the following screenshots while running the application. They provide the
visual evidence required for the university report.

| # | Screenshot | How to produce it |
|---|------------|-------------------|
| 1 | **Registration** | Run `python app.py`, choose option 1, register a new user. Capture the "Registration successful." message. |
| 2 | **Login** | Choose option 2 and log in. Capture the "Login successful / Welcome" message. |
| 3 | **Sending a message** | Choose option 3, enter receiver, shared secret and message. Capture the "Message encrypted and sent" output (it also prints the base64 ciphertext). |
| 4 | **Encrypted database / message output** | Run `python view_db.py` (helper script) OR `sqlite3 secure_messages.db "SELECT id,sender,receiver,ciphertext FROM messages;"` to show that only ciphertext is stored, not plaintext. |
| 5 | **Decrypted inbox** | Log in as the receiver, choose option 4, enter the shared secret. Capture the ">> Decrypted message: ..." line. |
| 6 | **Tampering attack** | Choose option 5, pick a target (ciphertext or HMAC). Capture the "Attack complete..." message. |
| 7 | **Integrity check failure** | After the attack, choose option 4 again. Capture ">> Integrity check failed. Message may have been modified." |
| 8 | **Security logs** | Choose option 6. Capture the log table showing LOGIN, ENCRYPT, INTEGRITY_FAILURE and ATTACK_SIMULATION events. |
| 9 | **Test results** | Run `pytest -v` and capture the passing test summary. |

Tip: a clean way to capture screenshots 1-3 and 5-7 is to run the full demo
flow described in `USER_GUIDE.md`.

---

## Pre-generated screenshots

Ready-made versions of all of the above (rendered from real application output)
are already included in the [`screenshots/`](screenshots/) folder, so they can be
dropped straight into the report:

- `screenshot_registration.png`
- `screenshot_login.png`
- `screenshot_send_message.png`
- `screenshot_encrypted_db.png`
- `screenshot_decrypted_inbox.png`
- `screenshot_attack.png`
- `screenshot_integrity_failure.png`
- `screenshot_logs.png`
- `test_results.png`

You may still re-capture them yourself from your own terminal if your course
requires native screenshots.
