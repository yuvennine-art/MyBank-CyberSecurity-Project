import sqlite3
import rsa

# Database path
DATABASE_PATH = "mybank.db"  # Ensure the correct database path

# -------------------------------
# using Test_communication to simulate a secure conversation between client1 and employee1.
# -------------------------------

def get_keys(username):
    """
    Retrieves the public and private keys for a given username from the database.
    Returns (public_key_pem, private_key_pem).
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Fetch public key
        cursor.execute("SELECT public_key FROM Users WHERE username = ?", (username,))
        public_key_row = cursor.fetchone()
        public_key_pem = public_key_row[0] if public_key_row else None

        # Fetch private key
        cursor.execute("SELECT private_key FROM Key_Management WHERE username = ?", (username,))
        private_key_row = cursor.fetchone()
        private_key_pem = private_key_row[0] if private_key_row else None

        conn.close()

        if not public_key_pem:
            print(f"❌ Error: No public key found for {username}.")
            return None, None
        if not private_key_pem:
            print(f"❌ Error: No private key found for {username}.")
            return None, None

        return public_key_pem, private_key_pem
    except Exception as e:
        print(f"❌ Error retrieving keys for {username}: {str(e)}")
        return None, None

def encrypt_with_public_key(message, public_key_pem):
    """
    Encrypts a message using a given public key.
    Returns the encrypted message in bytes.
    """
    try:
        public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode())
        encrypted_message = rsa.encrypt(message.encode(), public_key)
        return encrypted_message
    except Exception as e:
        print(f"❌ Encryption error: {str(e)}")
        return None

def decrypt_with_private_key(encrypted_message, private_key_pem):
    """
    Decrypts an RSA-encrypted message using a given private key.
    Returns the decrypted message as a string.
    """
    try:
        private_key = rsa.PrivateKey.load_pkcs1(private_key_pem.encode())
        decrypted_message = rsa.decrypt(encrypted_message, private_key).decode()
        return decrypted_message
    except Exception as e:
        print(f"❌ Decryption error: {str(e)}")
        return None

# Ask user for the message to encrypt
user_input = input("📨 Enter the message to encrypt: ")

# Run encryption and decryption for both client1 and employee1
for user in ["client1", "employee1"]:
    print(f"\n🔹 Testing encryption and decryption for {user} 🔹")

    # Retrieve public and private keys from the database
    public_key_pem, private_key_pem = get_keys(user)

    if public_key_pem and private_key_pem:
        print(f"📨 Input message: {user_input}")

        # Encrypt the message using the public key
        encrypted_message = encrypt_with_public_key(user_input, public_key_pem)
        if encrypted_message:
            print(f"✅ Encrypted message (hex) with {user}'s public key: {encrypted_message.hex()}")

            # Decrypt the encrypted message using the private key
            decrypted_message = decrypt_with_private_key(encrypted_message, private_key_pem)
            if decrypted_message:
                print(f"🔓 Decrypted message with {user}'s private key: {decrypted_message}")
            else:
                print(f"❌ Decryption failed for {user}.")
        else:
            print(f"❌ Encryption failed for {user}.")
    else:
        print(f"❌ Could not retrieve keys for {user}.")
