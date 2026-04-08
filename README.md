# DigiSecure Web v2.0

A Flask-powered secure document transfer system with AES-256, RSA-2048, X.509 certificates, and digital signatures.

## Features

- **X.509 Certificates** — auto-generated on register (SHA-256 fingerprint, 365-day validity)
- **AES-256-CBC** file encryption with per-transfer keys
- **RSA-OAEP** key wrapping + **PKCS1v15** digital signatures
- **MD5 integrity** verification on receive
- **One-to-Many** sending — select multiple recipients in one upload
- **File Deletion / Key Revocation** — sender can delete encrypted files; users can revoke their key
- **Third-Party Verification Panel** — verify any transfer without decrypting
- **Cryptographic Timing Dashboard** — per-operation benchmarks

## Setup

```bash
pip install -r requirements.txt
python app.py
```

Then open http://localhost:5000

## Structure

```
digisecure_web/
├── app.py            # Flask routes
├── database.py       # SQLite layer
├── crypto_utils.py   # AES, RSA, X.509 operations
├── requirements.txt
├── templates/
│   ├── index.html    # Login / Register
│   └── dashboard.html # Main app
├── encrypted_files/  # Stored .enc files
└── received_files/   # Decrypted output
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/register | Register + generate RSA keys + X.509 cert |
| POST | /api/login | Authenticate |
| POST | /api/logout | End session |
| GET  | /api/me | Current user info |
| GET  | /api/users | List all other users |
| GET  | /api/users/:name/certificate | View X.509 cert |
| POST | /api/users/:name/revoke | Revoke own key |
| POST | /api/send | Send file (multipart, supports multiple receivers) |
| GET  | /api/inbox | Your received transfers |
| GET  | /api/sent | Your sent transfers |
| POST | /api/receive/:id | Decrypt + verify a file |
| DELETE | /api/transfer/:id/delete | Delete encrypted file |
| GET  | /api/verify/:id | Third-party verify |
| GET  | /api/stats | Timing stats |
| GET  | /api/transfers | All transfers |
