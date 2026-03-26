import os
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet

from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from hashlib import sha256
from config import MASTER_KEY
import sqlite3


DATABASE_PATH = "mybank.db"  # Update with actual path


def generate_aes_key(key_size=32):
    """
    Generates a random AES key and returns it as bytes.
    """
    return get_random_bytes(key_size)


def generate_rsa_keys(key_size=2048):
    """
    Generates an RSA key pair and returns (private_key, public_key) as bytes.
    """
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key




# -------------------------------
# Manage the private key
# -------------------------------

def store_private_key(username, encrypted_private_key):
    """
    Stores an encrypted private key in the Key Management database.
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Ensure the private key column exists
        cursor.execute("PRAGMA table_info(Key_Management);")
        columns = [row[1] for row in cursor.fetchall()]
        if "private_key" not in columns:
            cursor.execute("ALTER TABLE Key_Management ADD COLUMN private_key TEXT DEFAULT '';")

        # Insert or update the user's private key
        cursor.execute("""
            INSERT INTO Key_Management (username, private_key) 
            VALUES (?, ?) 
            ON CONFLICT(username) DO UPDATE SET private_key = excluded.private_key
        """, (username, encrypted_private_key))

        conn.commit()
        conn.close()
        print(f"[INFO] Encrypted private key for {username} stored securely.")
    except Exception as e:
        print(f"[ERROR] Failed to store private key for {username}: {str(e)}")




def encrypt_key_with_master(key, master_key):
    """
    Encrypts a given key using the MASTER_KEY.
    Returns the encrypted key in the format: "nonce$ciphertext$tag".
    """
    cipher = AES.new(master_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(key)
    return b64encode(cipher.nonce).decode() + "$" + b64encode(ciphertext).decode() + "$" + b64encode(tag).decode()


def decrypt_key_with_master(encrypted_key, master_key):
    """
    Decrypts a key that was encrypted using `encrypt_key_with_master()`.
    Expects the format: "nonce$ciphertext$tag".
    """
    parts = encrypted_key.split("$")
    if len(parts) != 3:
        raise ValueError("Invalid encrypted key format")
    nonce = b64decode(parts[0])
    ciphertext = b64decode(parts[1])
    tag = b64decode(parts[2])
    cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def rotate_key(old_key=None, key_type="AES"):
    """
    Simulates key rotation by generating a new key and encrypting it using the MASTER_KEY.
    Parameters:
      old_key: The current key (not used in this implementation, included for reference).
      key_type: Either "AES" or "RSA".
    Returns the newly encrypted key as a string.
    """
    if key_type.upper() == "AES":
        new_key = generate_aes_key()
    elif key_type.upper() == "RSA":
        new_key, _ = generate_rsa_keys()
    else:
        raise ValueError("Unsupported key type")

    encrypted_new_key = encrypt_key_with_master(new_key, MASTER_KEY)
    return encrypted_new_key



# -------------------------------
# Manage the private key
# -------------------------------


ENCRYPTION_KEY = Fernet.generate_key()  # Replace with a securely stored key
cipher = Fernet(ENCRYPTION_KEY)

def retrieve_private_key(username):
    """
    Retrieves and decrypts a user's private key from Key_Management.
    If decryption fails, returns the encrypted key instead.
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT private_key FROM Key_Management WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()

        if row and row[0]:
            private_key_data = row[0]

            try:
                # 🔹 Attempt to decrypt if key is encrypted
                if private_key_data.startswith("gAAAA"):  # Fernet encrypted format
                    decrypted_private_key = cipher.decrypt(private_key_data.encode()).decode()
                    print(f"[INFO] Successfully decrypted private key for {username}.")
                else:
                    decrypted_private_key = private_key_data  # Assume it's stored in plaintext
                    print(f"[WARNING] Retrieved plaintext private key for {username}. Consider encrypting it.")

                return decrypted_private_key
            except Exception:
                print(f"[ERROR] Failed to decrypt private key for {username}. Returning encrypted key.")
                return private_key_data  # Return encrypted key if decryption fails

        else:
            print(f"[ERROR] Failed to retrieve private key for {username}: ⚠ No private key found for decryption.")
            return None
    except Exception as e:
        print(f"[ERROR] Failed to retrieve private key for {username}: {str(e)}")
        return None

if __name__ == "__main__":
    # Example: Generate an AES key and encrypt it with the MASTER_KEY
    print("Generating AES key:")
    aes_key = generate_aes_key()
    print("Original AES key:", aes_key)

    encrypted_aes_key = encrypt_key_with_master(aes_key, MASTER_KEY)
    print("Encrypted AES key:", encrypted_aes_key)

    decrypted_aes_key = decrypt_key_with_master(encrypted_aes_key, MASTER_KEY)
    print("Decrypted AES key:", decrypted_aes_key)

    # Simulating key rotation
    print("Rotated and encrypted new key:", rotate_key(aes_key, "AES"))
