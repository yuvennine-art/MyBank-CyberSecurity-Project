import os
from Crypto.Random import get_random_bytes

def load_or_generate_key(filename, key_length=32):
    """
    If the file exists, load the key. Otherwise, generate a new random key and save it.
    """
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            key = f.read()
            if len(key) != key_length:
                key = get_random_bytes(key_length)
                with open(filename, 'wb') as f_write:
                    f_write.write(key)
    else:
        key = get_random_bytes(key_length)
        with open(filename, 'wb') as f:
            f.write(key)
    return key

# Project root directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(BASE_DIR, "certs")

# Server configuration
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 23566

# Certificates and keys
CERTFILE = os.path.join(CERTS_DIR, "server.crt")     # Server certificate
KEYFILE = os.path.join(CERTS_DIR, "server.key")      # Server private key
CA_CERT = os.path.join(CERTS_DIR, "ca.crt")          # CA certificate for verification
MAIN_CLIENT_CERT = os.path.join(CERTS_DIR, "main_client.crt")  #  Added main_client.cert for mutual TLS authentication

# Database file path
DATABASE_PATH = os.path.join(BASE_DIR, "mybank.db")

# Load or generate encryption keys
SESSION_KEY = load_or_generate_key(os.path.join(CERTS_DIR, "session.key"), 32)  # Used for secure transmission
STATIC_KEY = load_or_generate_key(os.path.join(CERTS_DIR, "static.key"), 32)    # Used for static data encryption
MASTER_KEY = load_or_generate_key(os.path.join(CERTS_DIR, "master.key"), 32)    # Used to encrypt other keys
MAIN_CLIENT_KEY = os.path.join(CERTS_DIR, "main_client.key")
# Registration codes
EMPLOYEE_REG_CODE = os.environ.get("EMPLOYEE_REG_CODE", "EMP2023")
ADMIN_REG_CODE = os.environ.get("ADMIN_REG_CODE", "ADM2023")

# Debug mode
DEBUG = True
