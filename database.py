import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "digisecure.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL,
            certificate TEXT,
            cert_serial TEXT,
            cert_fingerprint TEXT,
            key_revoked INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS file_transfers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            encrypted_filepath TEXT,
            encrypted_aes_key TEXT NOT NULL,
            aes_iv TEXT NOT NULL,
            md5_digest TEXT NOT NULL,
            signature TEXT NOT NULL,
            file_size INTEGER,
            file_deleted INTEGER DEFAULT 0,
            status TEXT DEFAULT 'sent',
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS transfer_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transfer_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            md5_time_ms REAL DEFAULT 0,
            aes_key_gen_time_ms REAL DEFAULT 0,
            aes_encrypt_time_ms REAL DEFAULT 0,
            rsa_key_encrypt_time_ms REAL DEFAULT 0,
            sign_time_ms REAL DEFAULT 0,
            total_time_ms REAL DEFAULT 0,
            decrypt_aes_time_ms REAL DEFAULT 0,
            verify_sig_time_ms REAL DEFAULT 0,
            FOREIGN KEY(transfer_id) REFERENCES file_transfers(id)
        );
    ''')
    conn.commit()
    conn.close()

def create_user(username, email, password_hash, public_key, private_key, certificate, cert_serial, cert_fingerprint):
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, public_key, private_key, certificate, cert_serial, cert_fingerprint) VALUES (?,?,?,?,?,?,?,?)",
            (username, email, password_hash, public_key, private_key, certificate, cert_serial, cert_fingerprint)
        )
        conn.commit()
        return True, None
    except sqlite3.IntegrityError as e:
        if "username" in str(e):
            return False, "Username already exists."
        return False, "Email already registered."
    finally:
        conn.close()

def get_user(username):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_user_by_id(user_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_all_users():
    conn = get_connection()
    rows = conn.execute("SELECT username, email, cert_fingerprint, key_revoked, created_at FROM users ORDER BY username").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def revoke_user_key(username):
    conn = get_connection()
    conn.execute("UPDATE users SET key_revoked=1 WHERE username=?", (username,))
    conn.commit()
    conn.close()

def save_transfer(sender, receiver, original_filename, encrypted_filepath,
                  encrypted_aes_key, aes_iv, md5_digest, signature, file_size):
    conn = get_connection()
    cur = conn.execute(
        '''INSERT INTO file_transfers
           (sender, receiver, original_filename, encrypted_filepath,
            encrypted_aes_key, aes_iv, md5_digest, signature, file_size)
           VALUES (?,?,?,?,?,?,?,?,?)''',
        (sender, receiver, original_filename, encrypted_filepath,
         encrypted_aes_key, aes_iv, md5_digest, signature, file_size)
    )
    transfer_id = cur.lastrowid
    conn.commit()
    conn.close()
    return transfer_id

def get_inbox(username):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM file_transfers WHERE receiver=? ORDER BY timestamp DESC", (username,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_sent(username):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM file_transfers WHERE sender=? ORDER BY timestamp DESC", (username,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_all_transfers():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM file_transfers ORDER BY timestamp DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_transfer_by_id(transfer_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM file_transfers WHERE id=?", (transfer_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def delete_transfer_file(transfer_id, sender_username):
    conn = get_connection()
    row = conn.execute("SELECT * FROM file_transfers WHERE id=? AND sender=?", (transfer_id, sender_username)).fetchone()
    if not row:
        conn.close()
        return False, "Transfer not found or unauthorized."
    transfer = dict(row)
    # Delete encrypted file from disk
    if transfer["encrypted_filepath"] and os.path.exists(transfer["encrypted_filepath"]):
        os.remove(transfer["encrypted_filepath"])
    conn.execute("UPDATE file_transfers SET file_deleted=1, encrypted_filepath=NULL WHERE id=?", (transfer_id,))
    conn.commit()
    conn.close()
    return True, "File deleted successfully."

def save_stats(transfer_id, username, action, **kwargs):
    conn = get_connection()
    conn.execute(
        '''INSERT INTO transfer_stats
           (transfer_id, username, action,
            md5_time_ms, aes_key_gen_time_ms, aes_encrypt_time_ms,
            rsa_key_encrypt_time_ms, sign_time_ms, total_time_ms,
            decrypt_aes_time_ms, verify_sig_time_ms)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
        (transfer_id, username, action,
         kwargs.get("md5_time_ms", 0), kwargs.get("aes_key_gen_time_ms", 0),
         kwargs.get("aes_encrypt_time_ms", 0), kwargs.get("rsa_key_encrypt_time_ms", 0),
         kwargs.get("sign_time_ms", 0), kwargs.get("total_time_ms", 0),
         kwargs.get("decrypt_aes_time_ms", 0), kwargs.get("verify_sig_time_ms", 0))
    )
    conn.commit()
    conn.close()

def get_all_stats():
    conn = get_connection()
    rows = conn.execute(
        '''SELECT ts.*, ft.original_filename, ft.file_size
           FROM transfer_stats ts
           JOIN file_transfers ft ON ts.transfer_id = ft.id
           ORDER BY ts.id DESC'''
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
