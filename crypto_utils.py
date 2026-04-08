import base64
import hashlib
import os
import time
import datetime

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID


def generate_rsa_keys():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv_pem, pub_pem


def generate_x509_certificate(username, email, public_key_pem, private_key_pem):
    """Generate a self-signed X.509 certificate for a user."""
    priv = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    pub  = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())

    serial = x509.random_serial_number()
    now    = datetime.datetime.utcnow()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DigiSecure"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(email)]),
            critical=False
        )
        .sign(priv, hashes.SHA256(), default_backend())
    )

    cert_pem         = cert.public_bytes(serialization.Encoding.PEM).decode()
    serial_hex       = format(serial, 'x').upper()
    fingerprint_hex  = cert.fingerprint(hashes.SHA256()).hex().upper()
    fingerprint_fmt  = ":".join(fingerprint_hex[i:i+2] for i in range(0, len(fingerprint_hex), 2))

    return cert_pem, serial_hex, fingerprint_fmt


def compute_md5(file_path):
    h = hashlib.md5()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def compute_md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def generate_aes_key():
    return os.urandom(32)


def aes_encrypt_file(file_path, aes_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    with open(file_path, "rb") as f:
        data = f.read()
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)
    return enc.update(data) + enc.finalize(), iv


def aes_encrypt_bytes(data: bytes, aes_key: bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)
    return enc.update(data) + enc.finalize(), iv


def aes_decrypt_data(encrypted_data, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    data = dec.update(encrypted_data) + dec.finalize()
    return data[:-data[-1]]


def rsa_encrypt_aes_key(aes_key, public_key_pem):
    pub = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    enc = pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(enc).decode()


def rsa_decrypt_aes_key(enc_b64, private_key_pem):
    priv = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    return priv.decrypt(
        base64.b64decode(enc_b64),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


def sign_digest(md5_hex, private_key_pem):
    priv = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    sig = priv.sign(md5_hex.encode(), padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(sig).decode()


def verify_signature(md5_hex, sig_b64, public_key_pem):
    pub = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    try:
        pub.verify(base64.b64decode(sig_b64), md5_hex.encode(), padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def timed(fn, *args, **kwargs):
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    return result, (time.perf_counter() - t0) * 1000
