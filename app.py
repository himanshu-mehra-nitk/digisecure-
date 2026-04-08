import os
import base64
import hashlib
import time
from functools import wraps

from flask import (Flask, render_template, request, jsonify, session,
                   send_file as flask_send_file, redirect, url_for)

import database
import crypto_utils

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", base64.b64encode(os.urandom(32)).decode())

ENCRYPTED_DIR = os.path.join(os.path.dirname(__file__), "encrypted_files")
RECEIVED_DIR  = os.path.join(os.path.dirname(__file__), "received_files")

try:
    os.makedirs(ENCRYPTED_DIR, exist_ok=True)
    os.makedirs(RECEIVED_DIR,  exist_ok=True)
except Exception:
    pass

# Initialize DB on startup (works locally; on Vercel SQLite is ephemeral)
try:
    database.init_db()
except Exception as e:
    print(f"DB init skipped: {e}")

ALLOWED_EXTENSIONS = {
    'txt','pdf','png','jpg','jpeg','gif','doc','docx',
    'xls','xlsx','zip','csv','json','mp4','py','js','html'
}
MAX_FILE_MB = 50

# ── helpers ──────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return jsonify({"error": "Authentication required."}), 401
        return f(*args, **kwargs)
    return decorated

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def err(msg, code=400):
    return jsonify({"error": msg}), code

def ok(data=None, msg=None):
    resp = {"success": True}
    if msg:   resp["message"] = msg
    if data:  resp.update(data)
    return jsonify(resp)

# ── pages ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("index"))
    return render_template("dashboard.html")

# ── auth ──────────────────────────────────────────────────────────────────────

@app.route("/api/register", methods=["POST"])
def register():
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email    = (data.get("email")    or "").strip()
    password = data.get("password", "")
    confirm  = data.get("confirm",  "")

    if not username or not email or not password:
        return err("Username, email, and password are required.")
    if len(username) < 3:
        return err("Username must be at least 3 characters.")
    if "@" not in email:
        return err("Please enter a valid email address.")
    if len(password) < 6:
        return err("Password must be at least 6 characters.")
    if password != confirm:
        return err("Passwords do not match.")

    priv_pem, pub_pem = crypto_utils.generate_rsa_keys()
    cert_pem, serial, fingerprint = crypto_utils.generate_x509_certificate(username, email, pub_pem, priv_pem)

    success, msg = database.create_user(
        username, email, hash_password(password),
        pub_pem, priv_pem, cert_pem, serial, fingerprint
    )
    if not success:
        return err(msg)

    return ok(msg=f"Account created! Your X.509 certificate (serial {serial[:8]}…) is ready.")


@app.route("/api/login", methods=["POST"])
def login():
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password", "")

    if not username or not password:
        return err("Username and password are required.")

    user = database.get_user(username)
    if not user:
        return err("User not found.")
    if user["password_hash"] != hash_password(password):
        return err("Incorrect password.")
    if user["key_revoked"]:
        return err("Your key has been revoked. Contact an administrator.")

    session["username"] = username
    return ok({"username": username}, "Login successful.")


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return ok(msg="Logged out.")


@app.route("/api/me")
def me():
    if "username" not in session:
        return jsonify({"logged_in": False})
    user = database.get_user(session["username"])
    if not user:
        session.clear()
        return jsonify({"logged_in": False})
    return jsonify({
        "logged_in": True,
        "username":  user["username"],
        "email":     user["email"],
        "cert_serial":      user["cert_serial"],
        "cert_fingerprint": user["cert_fingerprint"],
        "key_revoked":      bool(user["key_revoked"]),
        "created_at":       user["created_at"],
    })

# ── users ─────────────────────────────────────────────────────────────────────

@app.route("/api/users")
@login_required
def list_users():
    users = database.get_all_users()
    me    = session["username"]
    return jsonify([u for u in users if u["username"] != me])


@app.route("/api/users/<username>/certificate")
@login_required
def get_certificate(username):
    user = database.get_user(username)
    if not user:
        return err("User not found.", 404)
    return jsonify({
        "username":    user["username"],
        "email":       user["email"],
        "certificate": user["certificate"],
        "serial":      user["cert_serial"],
        "fingerprint": user["cert_fingerprint"],
        "revoked":     bool(user["key_revoked"]),
    })


@app.route("/api/users/<username>/revoke", methods=["POST"])
@login_required
def revoke_key(username):
    if session["username"] != username:
        return err("You can only revoke your own key.", 403)
    database.revoke_user_key(username)
    session.clear()
    return ok(msg="Key revoked. You have been logged out.")

# ── file transfer ─────────────────────────────────────────────────────────────

@app.route("/api/send", methods=["POST"])
@login_required
def send_file():
    if "file" not in request.files:
        return err("No file uploaded.")

    f         = request.files["file"]
    receivers = request.form.getlist("receivers")
    if not receivers:
        return err("Select at least one recipient.")
    if not f or not f.filename:
        return err("Invalid file.")
    if not allowed_file(f.filename):
        return err(f"File type not allowed. Permitted: {', '.join(sorted(ALLOWED_EXTENSIONS))}.")

    file_data = f.read()
    if len(file_data) > MAX_FILE_MB * 1024 * 1024:
        return err(f"File exceeds {MAX_FILE_MB} MB limit.")

    sender_user = database.get_user(session["username"])
    if not sender_user:
        return err("Session expired. Please log in again.", 401)
    if sender_user["key_revoked"]:
        return err("Your key has been revoked. You cannot send files.")

    receiver_users = []
    for rname in receivers:
        ru = database.get_user(rname.strip())
        if not ru:
            return err(f"Recipient '{rname}' not found.")
        if ru["key_revoked"]:
            return err(f"Recipient '{rname}' has a revoked key and cannot receive files.")
        receiver_users.append(ru)

    original_filename = f.filename
    file_size         = len(file_data)
    results           = []
    total_start       = time.perf_counter()

    md5_digest, md5_ms = crypto_utils.timed(crypto_utils.compute_md5_bytes, file_data)
    signature, sign_ms = crypto_utils.timed(crypto_utils.sign_digest, md5_digest, sender_user["private_key"])

    for receiver in receiver_users:
        try:
            aes_key, aes_key_ms = crypto_utils.timed(crypto_utils.generate_aes_key)

            (encrypted_data, iv), aes_enc_ms = crypto_utils.timed(
                crypto_utils.aes_encrypt_bytes, file_data, aes_key
            )

            enc_filename = f"{sender_user['username']}_to_{receiver['username']}_{original_filename}.enc"
            enc_filepath = os.path.join(ENCRYPTED_DIR, enc_filename)

            try:
                with open(enc_filepath, "wb") as out:
                    out.write(encrypted_data)
            except Exception:
                enc_filepath = None  # Vercel can't write files

            enc_aes_key_b64, rsa_wrap_ms = crypto_utils.timed(
                crypto_utils.rsa_encrypt_aes_key, aes_key, receiver["public_key"]
            )
            iv_b64 = base64.b64encode(iv).decode()

            total_ms = (time.perf_counter() - total_start) * 1000

            transfer_id = database.save_transfer(
                sender=sender_user["username"],
                receiver=receiver["username"],
                original_filename=original_filename,
                encrypted_filepath=enc_filepath,
                encrypted_aes_key=enc_aes_key_b64,
                aes_iv=iv_b64,
                md5_digest=md5_digest,
                signature=signature,
                file_size=file_size
            )

            database.save_stats(
                transfer_id=transfer_id,
                username=sender_user["username"],
                action="send",
                md5_time_ms=md5_ms,
                aes_key_gen_time_ms=aes_key_ms,
                aes_encrypt_time_ms=aes_enc_ms,
                rsa_key_encrypt_time_ms=rsa_wrap_ms,
                sign_time_ms=sign_ms,
                total_time_ms=total_ms
            )

            results.append({
                "receiver":    receiver["username"],
                "transfer_id": transfer_id,
                "total_ms":    round(total_ms, 2),
            })

        except Exception as e:
            results.append({
                "receiver": receiver["username"],
                "error":    str(e),
            })

    return ok({"results": results, "md5": md5_digest, "file_size": file_size})


@app.route("/api/inbox")
@login_required
def inbox():
    transfers = database.get_inbox(session["username"])
    return jsonify(transfers)


@app.route("/api/sent")
@login_required
def sent():
    transfers = database.get_sent(session["username"])
    return jsonify(transfers)


@app.route("/api/receive/<int:transfer_id>", methods=["POST"])
@login_required
def receive_file(transfer_id):
    transfer = database.get_transfer_by_id(transfer_id)
    if not transfer:
        return err("Transfer not found.", 404)
    if transfer["receiver"] != session["username"]:
        return err("Not authorized to access this transfer.", 403)
    if transfer["file_deleted"]:
        return err("The sender has deleted this file.")

    receiver_user = database.get_user(session["username"])
    sender_user   = database.get_user(transfer["sender"])
    if not sender_user:
        return err("Sender account no longer exists.")

    try:
        total_start = time.perf_counter()

        aes_key, rsa_unwrap_ms = crypto_utils.timed(
            crypto_utils.rsa_decrypt_aes_key,
            transfer["encrypted_aes_key"],
            receiver_user["private_key"]
        )
        iv = base64.b64decode(transfer["aes_iv"])

        with open(transfer["encrypted_filepath"], "rb") as fh:
            encrypted_data = fh.read()

        decrypted_data, aes_dec_ms = crypto_utils.timed(
            crypto_utils.aes_decrypt_data, encrypted_data, aes_key, iv
        )

        recomputed_md5, md5_ms = crypto_utils.timed(
            crypto_utils.compute_md5_bytes, decrypted_data
        )

        is_valid, verify_ms = crypto_utils.timed(
            crypto_utils.verify_signature,
            recomputed_md5,
            transfer["signature"],
            sender_user["public_key"]
        )

        total_ms = (time.perf_counter() - total_start) * 1000
        md5_match = recomputed_md5 == transfer["md5_digest"]

        database.save_stats(
            transfer_id=transfer_id,
            username=session["username"],
            action="receive",
            md5_time_ms=md5_ms,
            decrypt_aes_time_ms=aes_dec_ms,
            rsa_key_encrypt_time_ms=rsa_unwrap_ms,
            verify_sig_time_ms=verify_ms,
            total_time_ms=total_ms
        )

        return jsonify({
            "success":          True,
            "md5_match":        md5_match,
            "signature_valid":  is_valid,
            "recorded_md5":     transfer["md5_digest"],
            "computed_md5":     recomputed_md5,
            "total_ms":         round(total_ms, 2),
            "file_data_b64":    base64.b64encode(decrypted_data).decode(),
            "filename":         transfer["original_filename"],
        })

    except FileNotFoundError:
        return err("Encrypted file missing from server storage.")
    except Exception as e:
        return err(f"Decryption failed: {str(e)}")


@app.route("/api/transfer/<int:transfer_id>/delete", methods=["DELETE"])
@login_required
def delete_transfer(transfer_id):
    success, msg = database.delete_transfer_file(transfer_id, session["username"])
    if not success:
        return err(msg, 403)
    return ok(msg=msg)


@app.route("/api/verify/<int:transfer_id>")
@login_required
def verify_transfer(transfer_id):
    transfer = database.get_transfer_by_id(transfer_id)
    if not transfer:
        return err("Transfer not found.", 404)

    sender = database.get_user(transfer["sender"])
    if not sender:
        return err("Sender account not found.")

    file_exists = (
        transfer["encrypted_filepath"] is not None
        and os.path.exists(transfer["encrypted_filepath"])
        and not transfer["file_deleted"]
    )

    is_valid = crypto_utils.verify_signature(
        transfer["md5_digest"], transfer["signature"], sender["public_key"]
    )

    return jsonify({
        "transfer_id":      transfer_id,
        "sender":           transfer["sender"],
        "receiver":         transfer["receiver"],
        "filename":         transfer["original_filename"],
        "md5_digest":       transfer["md5_digest"],
        "timestamp":        transfer["timestamp"],
        "file_exists":      file_exists,
        "file_deleted":     bool(transfer["file_deleted"]),
        "signature_valid":  is_valid,
        "cert_fingerprint": sender["cert_fingerprint"],
    })

# ── stats ─────────────────────────────────────────────────────────────────────

@app.route("/api/stats")
@login_required
def stats():
    return jsonify(database.get_all_stats())

# ── transfers (admin view) ────────────────────────────────────────────────────

@app.route("/api/transfers")
@login_required
def all_transfers():
    return jsonify(database.get_all_transfers())

# ── run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    database.init_db()
    app.run(debug=True, port=5000)