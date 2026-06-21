"""
view_db.py
----------
Optional helper for screenshots and demonstrations. It prints the raw contents
of the database so you can SEE that only ciphertext (never plaintext) and only
password hashes (never plain passwords) are stored.

Run with:  python view_db.py
"""

import database


def main():
    database.init_db()

    print("\n================= USERS (no plain passwords) =================")
    connection = database.get_connection()
    users = connection.execute("SELECT * FROM users").fetchall()
    for u in users:
        print(f"  {u['username']:<10} salt={u['salt'][:12]}... "
              f"hash={u['password_hash'][:16]}...")

    print("\n=============== MESSAGES (only ciphertext stored) ===============")
    messages = connection.execute("SELECT * FROM messages").fetchall()
    for m in messages:
        flag = " [TAMPERED]" if m["tampered"] else ""
        print(f"  id={m['id']} {m['sender']}->{m['receiver']}{flag}")
        print(f"     ciphertext={m['ciphertext']}")
        print(f"     hmac      ={m['hmac']}")

    connection.close()
    print()


if __name__ == "__main__":
    main()
