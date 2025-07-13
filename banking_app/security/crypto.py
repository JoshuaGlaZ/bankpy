from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key
)
from cryptography.exceptions import InvalidSignature
import base64
import os
from django.conf import settings
import logging
import json

logger = logging.getLogger(__name__)


# Kunci untuk Fernet (AES)
def get_encryption_key():
    """
    Mendapatkan kunci enkripsi dari settings, atau membuat kunci baru jika belum ada
    """
    key = getattr(settings, 'ENCRYPTION_KEY', None)
    if key is None:
        key = Fernet.generate_key()
        settings.ENCRYPTION_KEY = key
    return key


def encrypt_data(data):
    """
    Enkripsi data menggunakan Fernet (AES-128)
    """
    if not data:
        return data

    key = get_encryption_key()
    f = Fernet(key)
    if isinstance(data, str):
        data = data.encode('utf-8')
    encrypted_data = f.encrypt(data)
    return encrypted_data.decode('utf-8')


def decrypt_data(encrypted_data):
    """
    Dekripsi data yang telah dienkripsi dengan Fernet
    """
    if not encrypted_data:
        return encrypted_data

    key = get_encryption_key()
    f = Fernet(key)
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode('utf-8')
    try:
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data.decode('utf-8')
    except InvalidToken:
        logger.error(
            "Invalid token during decryption. Possible encryption key mismatch.")
        return "Error: Data could not be decrypted"


def _read_pem_file(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception as e:
        logger.error(f"Failed to read PEM file at {path}: {e}")
        return None

def _normalize_transaction_data(transaction_data):
    """
    Normalize transaction data to serialization
    """
    if isinstance(transaction_data, dict):
        normalized_data = {k: str(v) for k, v in transaction_data.items()}
        return json.dumps(normalized_data, sort_keys=True).encode('utf-8')
    elif isinstance(transaction_data, str):
        return transaction_data.encode('utf-8')
    else:
        return transaction_data


def get_transaction_signing_key_pem():
    """
    Load private key PEM for transaction signing from file.
    """
    path = getattr(settings, "SIGNING_KEY_FILE", None)
    if not path:
        logger.error("SIGNING_KEY_FILE setting not configured")
        return None

    pem_data = _read_pem_file(path)
    if not pem_data:
        return None

    return pem_data


def get_transaction_verification_key_pem():
    """
    Load public key PEM for signature verification from file.
    """
    path = getattr(settings, "VERIFICATION_KEY_FILE", None)
    if not path:
        logger.error("VERIFICATION_KEY_FILE setting not configured")
        return None

    pem_data = _read_pem_file(path)
    if not pem_data:
        return None

    return pem_data


def sign_transaction(transaction_data, private_key_pem=None):
    """
    Sign transaction data with private key
    """
    if private_key_pem is None:
        private_key_pem = get_transaction_signing_key_pem()
        if not private_key_pem:
            raise ValueError(
                "Transaction signing key PEM not found or unreadable")

    private_key = load_pem_private_key(
        private_key_pem,
        password=None
    )

    transaction_data = _normalize_transaction_data(transaction_data)

    signature = private_key.sign(
        transaction_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode("ascii")



def verify_signature(transaction_data, signature, public_key_pem=None):
    """
    Verify transaction data with public key for digital signature
    """
    if public_key_pem is None:
        public_key_pem = get_transaction_verification_key_pem()
        if not public_key_pem:
            raise ValueError(
                "Transaction verification key PEM not found or unreadable")

    public_key = load_pem_public_key(public_key_pem)

    transaction_data = _normalize_transaction_data(transaction_data)

    if isinstance(signature, str):
        try:
            signature = base64.b64decode(signature)
        except Exception as e:
            logger.error(f"Error decoding signature: {e}")
            return False

    try:
        public_key.verify(
            signature,
            transaction_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        logger.warning("Invalid signature detected during verification")
        return False
    except Exception as e:
        logger.error(f"Error verifying signature: {e}")
        return False
