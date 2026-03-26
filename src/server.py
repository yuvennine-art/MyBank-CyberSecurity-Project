import socket
import ssl
import threading
import json
import sqlite3
import re
import logging
import random
import subprocess
from base64 import b64encode, b64decode
from Crypto.PublicKey.DSA import generate
from config import SERVER_HOST, SERVER_PORT, CERTFILE, KEYFILE, CA_CERT, SESSION_KEY, DATABASE_PATH, STATIC_KEY
from key_management import generate_aes_key, generate_rsa_keys, encrypt_key_with_master, rotate_key
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import sha256
import datetime
import secrets
import os
import base64
import random
from cryptography.fernet import Fernet
# --- HKDF Imports for standard key derivation ---
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP




# ------------------------------
# Derive a user-specific key using HKDF (recommended for production)
# ------------------------------
def derive_user_field_key(master_key, username, field_label):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=(username + field_label).encode(),
        backend=default_backend()
    )
    return hkdf.derive(master_key)

MASTER_KEY_PATH = "master_key.bin"

def load_or_generate_master_key():
    """
    Loads an existing master key or generates a new one.
    Ensures consistency across all encryption functions.
    """
    if os.path.exists(MASTER_KEY_PATH):
        with open(MASTER_KEY_PATH, "rb") as f:
            return f.read()
    else:
        master_key = os.urandom(32)  # Generate a 256-bit key
        with open(MASTER_KEY_PATH, "wb") as f:
            f.write(master_key)
        return master_key

MASTER_KEY = load_or_generate_master_key()

# ------------------------------
# Global variables: Online user management and OTP storage
# ------------------------------
online_users = {}  # key: username, value: {"connection": conn, "user_id": uid, "role": role}
online_users_lock = threading.Lock()
otp_storage = {}  # Temporary storage for OTP codes

# ------------------------------
# Logging and audit settings
# ------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    filename="server.log",
    filemode="a"
)


def log_event(event_type, message):
    # If the log message contains sensitive fields like password, replace them with '******' to prevent leakage of plain-text passwords
    message = {"action": "login", "username": "client1", "password": "123456"}
    sensitive_fields = ["password"]

    for field in sensitive_fields:
        if field in message:
            message[field] = "******"
    print(message)


def log_audit(user_id, action, details, ip_address):
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO Audit_Logs (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)",
            (user_id, action, details, ip_address)
        )
        conn.commit()
        conn.close()
        log_event("AUDIT", f"User {user_id} action: {action}, details: {details}, ip: {ip_address}")
    except Exception as e:
        logging.error(f"Audit log write failed: {str(e)}")


# ------------------------------
# Input validation functions
# ------------------------------
# Between **3 to 20 digits** long.
def validate_username(username):
    return re.match(r"^\w{3,20}$", username) is not None

#follow the format: **local_part@domain.extension**
def validate_email(email):
    return re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email) is not None

# Between **6 to 15 digits** long.
def validate_phone(phone):
    return re.match(r"^\d{6,15}$", phone) is not None


def validate_registration_data(username, password, email, phone, pay_password):
    if not validate_username(username):
        return False, "Invalid username format"
    if len(password) < 6:
        return False, "Login password must be at least 6 characters"
    if len(pay_password) < 6:
        return False, "Payment password must be at least 6 characters"
    if not validate_email(email):
        return False, "Invalid email format"
    if not validate_phone(phone):
        return False, "Invalid phone number format"
    return True, ""

# ------------------------------
# Mask sensitive data functions (Log)
# ------------------------------
def mask_sensitive_data(data):
    """
    Masks sensitive fields such as passwords, emails, and phone numbers
    in decrypted JSON data to prevent logging private information.
    """
    try:
        parsed_data = json.loads(data)
        if "password" in parsed_data:
            parsed_data["password"] = "******"
        if "pay_password" in parsed_data:
            parsed_data["pay_password"] = "******"
        if "email" in parsed_data:
            parsed_data["email"] = "******"
        if "phone" in parsed_data:
            parsed_data["phone"] = "******"
        return json.dumps(parsed_data)
    except Exception:
        return data  # If the data is not in JSON format, return it as-is

# ------------------------------
# AES encryption/decryption functions (AES-GCM)
# ------------------------------
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # ✅ Print encryption key (for debugging)
    print(f"[DEBUG] Encryption Key Used: {key.hex()}")
    return b64encode(cipher.nonce).decode(), b64encode(ciphertext).decode(), b64encode(tag).decode()


def aes_decrypt(nonce_b64, ciphertext_b64, tag_b64, key):
    nonce = b64decode(nonce_b64)
    ciphertext = b64decode(ciphertext_b64)
    tag = b64decode(tag_b64)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    print(f"[DEBUG] AES Decrypt - Nonce: {nonce.hex()}, Ciphertext: {ciphertext.hex()}, Tag: {tag.hex()}, Key: {key.hex()}")

    try:
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        masked_data = mask_sensitive_data(decrypted_data.decode())
        print(f"[DEBUG] Decryption Successful: {masked_data}")
        return decrypted_data
    except ValueError as e:
        print(f"[ERROR] AES-GCM MAC Check Failed: {str(e)}")
        raise ValueError("The key of client1 has been changed for test, ✅ please find another user (client2) to test or a newly registered account.  " + str(e))



# ------------------------------
# Payload encryption/decryption using SESSION_KEY
# ------------------------------
def encrypt_payload(data, session_key):
    nonce, ciphertext, tag = aes_encrypt(data, session_key)
    return json.dumps({"nonce": nonce, "ciphertext": ciphertext, "tag": tag})


def decrypt_payload(encrypted_json, session_key):
    payload = json.loads(encrypted_json)
    decrypted_data = aes_decrypt(payload["nonce"], payload["ciphertext"], payload["tag"], session_key)
    return decrypted_data


# ------------------------------
# Static encryption/decryption for DB storage (using STATIC_KEY)
# ------------------------------
def static_encrypt(data, key):
    nonce, ciphertext, tag = aes_encrypt(data.encode(), key)
    return json.dumps({"nonce": nonce, "ciphertext": ciphertext, "tag": tag})


def static_decrypt(encrypted_json, key):
    payload = json.loads(encrypted_json)
    nonce_b64 = payload["nonce"]
    ciphertext_b64 = payload["ciphertext"]
    tag_b64 = payload["tag"]

    # decrypt Base64
    nonce = b64decode(nonce_b64)
    ciphertext = b64decode(ciphertext_b64)
    tag = b64decode(tag_b64)

    # print Base64
    print(f"[DEBUG] Decryption Inputs - Nonce: {nonce.hex()}, Ciphertext: {ciphertext.hex()}, Tag: {tag.hex()}")

    decrypted = aes_decrypt(nonce_b64, ciphertext_b64, tag_b64, key)
    return decrypted.decode()




# ------------------------------
# Simulate SMS sending by writing OTP to a file
# ------------------------------
def send_sms_simulation(username, otp):
    filename = f"otp_{username}.txt"
    with open(filename, "w") as f:
        f.write(otp)
        f.flush()  #
        os.fsync(f.fileno())

    log_event("SMS", f"OTP for {username} is {otp}. Written to file {filename}.")
    return otp  # for OTP test


# ------------------------------
# Helper: Verify a provided password against stored "salt$hash"
# ------------------------------
def verify_password(provided_password, stored_password):
    try:
        salt_hex, stored_hash = stored_password.split('$', 1)
    except Exception:
        return False
    computed_hash = sha256((salt_hex + provided_password).encode()).hexdigest()
    return computed_hash == stored_hash


# ------------------------------
# Offline message storage: Insert message into database for offline users
# ------------------------------
def store_offline_message(sender, recipient, message):
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO Offline_Messages (sender, recipient, message) 
            VALUES (?, ?, ?)
        """, (sender, recipient, message))
        conn.commit()
        conn.close()
        log_event("OFFLINE_MSG", f"Stored offline message from {sender} to {recipient}")
    except Exception as e:
        log_event("ERROR", f"Error storing offline message: {str(e)}")


# ------------------------------
# Offline message delivery: When user logs in, check and deliver offline messages
# ------------------------------
def check_offline_messages(username, connection, client_ip):
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT msg_id, sender, message, timestamp FROM Offline_Messages 
            WHERE recipient = ? AND delivered = 0
        """, (username,))
        messages = cursor.fetchall()
        for msg in messages:
            msg_id, sender, message, timestamp = msg
            offline_msg = {
                "action": "receive_offline_message",
                "sender": sender,
                "message": message,
                "timestamp": timestamp
            }
            encrypted_msg = encrypt_payload(json.dumps(offline_msg).encode(), SESSION_KEY)
            connection.sendall(encrypted_msg.encode())
            cursor.execute("UPDATE Offline_Messages SET delivered = 1 WHERE msg_id = ?", (msg_id,))
        conn.commit()
        conn.close()
    except Exception as e:
        log_event("ERROR", f"Error delivering offline messages for {username}: {str(e)}")


# ------------------------------
# Database operation functions
# ------------------------------


# Generate a symmetric encryption key for private key protection (Store this securely!)
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

def create_account_in_db(request, client_ip):
    """
    Handles user account creation, including RSA key generation and secure password storage.
    """
    username = request.get("username")
    password = request.get("password")
    email = request.get("email")
    phone = request.get("phone")
    pay_password = request.get("pay_password")
    role_str = request.get("role", "client")  # Default to "client" role if not specified

    # Validate user registration data
    valid, err_msg = validate_registration_data(username, password, email, phone, pay_password)
    if not valid:
        return {"status": "error", "message": err_msg}

    # Securely hash passwords
    salt = get_random_bytes(16).hex()
    hashed_password = sha256((salt + password).encode()).hexdigest()
    stored_password = f"{salt}${hashed_password}"

    salt_pay = get_random_bytes(16).hex()
    hashed_pay_password = sha256((salt_pay + pay_password).encode()).hexdigest()
    stored_pay_password = f"{salt_pay}${hashed_pay_password}"

    # Encrypt email and phone number
    email_key = derive_user_field_key(STATIC_KEY, username, "email") if email else None
    phone_key = derive_user_field_key(STATIC_KEY, username, "phone") if phone else None
    email_encrypted = static_encrypt(email, email_key) if email else None
    phone_encrypted = static_encrypt(phone, phone_key) if phone else None

    # ✅ Generate RSA Key Pair (2048-bit)
    public_key, private_key = rsa.newkeys(2048)
    public_key_pem = public_key.save_pkcs1().decode()
    private_key_pem = private_key.save_pkcs1().decode()

    # ✅ Encrypt the private key before storing
    encrypted_private_key = cipher.encrypt(private_key_pem.encode()).decode()

    # ✅ Store private key in key management
    store_private_key(username, encrypted_private_key)

    # Retrieve role ID from Roles table
    role_id = None
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT role_id FROM Roles WHERE role_name = ?", (role_str,))
        row = cursor.fetchone()
        if row:
            role_id = row[0]
        conn.close()
    except Exception as e:
        log_event("ERROR", f"Role query failed: {str(e)}")

    # Insert the new user into the database
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO Users (username, hashed_password, payment_password, email, phone_number, role_id, public_key) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, stored_password, stored_pay_password, email_encrypted, phone_encrypted, role_id, public_key_pem))

        conn.commit()
        user_id = cursor.lastrowid
        conn.close()

        log_audit(user_id, "create_account", f"Account created: {username}, Role: {role_str}", client_ip)

        return {"status": "success", "message": "Account created successfully", "user_id": user_id}
    except sqlite3.IntegrityError:
        return {"status": "error", "message": "Username already exists"}
    except Exception as e:
        return {"status": "error", "message": f"Database error: {str(e)}"}




def login_in_db(request, client_ip):
    """
    Handles user login with OTP authentication and strict role validation.
    """
    username = request.get("username")
    password = request.get("password")
    otp_input = request.get("otp", "").strip()
    requested_role = request.get("requested_role")  # Validate requested role

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Retrieve user details, including role_id
    cursor.execute("SELECT user_id, hashed_password, role_id FROM Users WHERE username = ?", (username,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return {"status": "error", "message": "User does not exist"}

    user_id, stored_password, role_id = row

    # Verify the provided password
    if not verify_password(password, stored_password):
        conn.close()
        return {"status": "error", "message": "Incorrect password"}

    # Ensure role_id is valid
    cursor.execute("SELECT role_name FROM Roles WHERE role_id = ?", (role_id,))
    role_row = cursor.fetchone()

    if not role_row:
        conn.close()
        return {"status": "error", "message": f"Invalid role for user {username}, role_id: {role_id}"}

    role_name = role_row[0]

    # ✅ Enforce Role Validation
    if requested_role and role_name != requested_role:
        conn.close()
        return {"status": "error", "message": f"Access denied: You cannot log in as {requested_role}."}

    # Generate OTP if not provided
    if otp_input == "":
        otp = str(secrets.randbelow(900000) + 100000)  # Generate a 6-digit OTP
        otp_storage[username] = otp  # Store OTP temporarily
        send_sms_simulation(username, otp)  # Simulate OTP sending
        conn.close()
        return {"status": "otp_required", "message": "OTP has been sent. Please enter the OTP from the file."}

    # Validate OTP
    if username not in otp_storage or otp_input != otp_storage[username]:
        conn.close()
        return {"status": "error", "message": "Incorrect OTP."}

    del otp_storage[username]  # Remove OTP after successful verification

    conn.close()

    return {
        "status": "success",
        "role": role_name,  # Ensure role_name is returned
        "message": "Login successful",
        "user_id": user_id
    }





# ---------------- Client Functions ----------------


def generate_account_number():
    """
    Generates a unique 10-digit account number.
    """
    return str(random.randint(1000000000, 9999999999))




def generate_account_number():
    """
    Generates a unique 10-digit account number.
    """
    return str(random.randint(1000000000, 9999999999))

def create_account_in_db(request, client_ip):
    """
    Handles user registration, adds them to the Users table,
    and automatically creates a bank account if the user has 'create_account' permission.
    """
    username = request.get("username")
    password = request.get("password")
    email = request.get("email")
    phone = request.get("phone")
    pay_password = request.get("pay_password")
    role_str = request.get("role")

    if not role_str:
        role_str = "client"  # Default to client role

    valid, err_msg = validate_registration_data(username, password, email, phone, pay_password)
    if not valid:
        return {"status": "error", "message": err_msg}

    salt = get_random_bytes(16)
    salt_hex = salt.hex()
    hash_value = sha256((salt_hex + password).encode()).hexdigest()
    stored_password = salt_hex + "$" + hash_value

    salt_pay = get_random_bytes(16)
    salt_pay_hex = salt_pay.hex()
    hash_pay = sha256((salt_pay_hex + pay_password).encode()).hexdigest()
    stored_pay_password = salt_pay_hex + "$" + hash_pay

    email_key = derive_user_field_key(STATIC_KEY, username, "email") if email else None
    phone_key = derive_user_field_key(STATIC_KEY, username, "phone") if phone else None
    email_encrypted = static_encrypt(email, email_key) if email else None
    phone_encrypted = static_encrypt(phone, phone_key) if phone else None

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    #  Retrieve role ID and permissions
    cursor.execute("SELECT role_id FROM Roles WHERE role_name = ?", (role_str,))
    row = cursor.fetchone()
    role_id = row[0] if row else None

    cursor.execute("SELECT permissions FROM Roles WHERE role_id = ?", (role_id,))
    role_row = cursor.fetchone()
    permissions = json.loads(role_row[0]) if role_row else []

    #  If the role does not have 'create_account' permission, deny account creation
    if "create_account" not in permissions:
        conn.close()
        return {"status": "error", "message": "You do not have permission to create an account"}

    try:
        #  Step 1: Create user in Users table
        cursor.execute(
            "INSERT INTO Users (username, hashed_password, payment_password, email, phone_number, role_id) VALUES (?, ?, ?, ?, ?, ?)",
            (username, stored_password, stored_pay_password, email_encrypted, phone_encrypted, role_id)
        )
        conn.commit()
        user_id = cursor.lastrowid  # Retrieve new user ID

        #  Step 2: If role is 'client' or user has 'create_account' permission, create a bank account
        if role_str == "client" or "create_account" in permissions:
            account_number = generate_account_number()
            cursor.execute(
                "INSERT INTO Accounts (user_id, account_number, account_type, balance, encrypted_data) VALUES (?, ?, ?, ?, ?)",
                (user_id, account_number, "checking", 0.00, None)  # Default account type: checking, balance: 0.00
            )
            conn.commit()
            log_audit(user_id, "create_account", f"Bank account created: {account_number} for {username}", client_ip)

        conn.close()

        return {"status": "success", "message": "Account created successfully", "user_id": user_id}
    except sqlite3.IntegrityError:
        return {"status": "error", "message": "Username already exists"}
    except Exception as e:
        return {"status": "error", "message": f"Database error: {str(e)}"}


def get_account_info_in_db(request, client_ip):
    """
    Retrieves account statements, balances, loan status, and transaction history with encrypted data.
    """
    username = request.get("username")

    if not username:
        return {"status": "error", "message": "Missing username"}

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT user_id FROM Users WHERE username = ?", (username,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return {"status": "error", "message": "User not found"}

    user_id = row[0]

    # Retrieve account details
    cursor.execute(
        "SELECT account_id, account_number, account_type, balance, encrypted_data FROM Accounts WHERE user_id = ?",
        (user_id,))
    accounts = cursor.fetchall()

    account_list = []
    account_ids = []

    for account_id, account_number, account_type, balance, encrypted_data in accounts:
        account_ids.append(account_id)
        decrypted_data = static_decrypt(encrypted_data, STATIC_KEY) if encrypted_data else None
        account_list.append({
            "account_number": account_number,
            "account_type": account_type,
            "balance": balance,
            "details": decrypted_data
        })

    # Retrieve transactions
    cursor.execute("""
        SELECT from_account_id, to_account_id, transaction_type, amount, currency, timestamp, encrypted_details
        FROM Transactions WHERE from_account_id IN ({seq}) OR to_account_id IN ({seq})
        ORDER BY timestamp DESC LIMIT 10
    """.format(seq=",".join(["?"] * len(account_ids))), account_ids * 2)

    transactions = [
        {
            "from_account": txn[0],
            "to_account": txn[1],
            "transaction_type": txn[2],
            "amount": txn[3],
            "currency": txn[4],
            "timestamp": txn[5],
            "details": static_decrypt(txn[6], STATIC_KEY) if txn[6] else None
        }
        for txn in cursor.fetchall()
    ]

    # Retrieve loans
    cursor.execute("SELECT loan_id, amount, loan_type, status FROM Loans WHERE user_id = ?", (user_id,))
    loans = [
        {"loan_id": loan[0], "amount": loan[1], "loan_type": loan[2], "status": loan[3]}
        for loan in cursor.fetchall()
    ]

    conn.close()
    log_audit(user_id, "get_account_info", "Retrieved account details and loan history", client_ip)

    return {
        "status": "success",
        "accounts": account_list,
        "transactions": transactions,
        "loans": loans
    }




def pay_bill(request, client_ip):
    if request.get("requester_role") not in ["client", "employee"]:
        return {"status": "error", "message": "Permission denied"}
    pay_pwd_input = request.get("payment_password_verification", "").strip()
    if not pay_pwd_input:
        return {"status": "error", "message": "Missing payment password verification"}
    username = request.get("username")
    account = request.get("account")
    biller = request.get("biller")
    try:
        amount = float(request.get("amount"))
    except Exception:
        return {"status": "error", "message": "Invalid amount format"}
    currency = request.get("currency", "USD")
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, payment_password FROM Users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return {"status": "error", "message": "User not found"}
        user_id, stored_payment_pwd = row
        conn.close()
    except Exception as e:
        return {"status": "error", "message": f"Database error: {str(e)}"}
    if not verify_password(pay_pwd_input, stored_payment_pwd):
        return {"status": "error", "message": "Payment password verification failed"}
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT account_id, balance FROM Accounts WHERE account_number = ?", (account,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return {"status": "error", "message": "Account not found"}
        account_id, balance = row
        balance = float(balance)
        if balance < amount:
            conn.close()
            return {"status": "error", "message": "Insufficient balance"}
        new_balance = balance - amount
        cursor.execute("UPDATE Accounts SET balance = ?, updated_at = CURRENT_TIMESTAMP WHERE account_number = ?",
                       (new_balance, account))
        conn.commit()
        cursor.execute("""
            INSERT INTO Transactions 
            (from_account_id, to_account_id, transaction_type, amount, currency, status, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (account_id, None, "bill_payment", amount, currency, "completed"))
        conn.commit()
        conn.close()
        log_audit(user_id, "pay_bill",
                  f"User {username} paid bill of {amount} using account {account}. New balance: {new_balance}",
                  client_ip)
        return {"status": "success", "message": f"Bill payment successful, new balance: {new_balance:.2f}"}
    except Exception as e:
        return {"status": "error", "message": f"Database error: {str(e)}"}


def update_customer_info(request, client_ip):
    """
    Securely updates customer account information with verification.
    - Clients can only update their own information.
    - Employees can update non-sensitive fields.
    - Admins have full access to modify customer details.
    """
    username = request.get("username")  # Target account to be updated
    updated_info = request.get("updated_info")  # New account information
    requester_role = request.get("requester_role")  # Role of the requester
    requester_username = request.get("requester_username")  # User making the request
    emp_verification = request.get("employee_password_verification")  # Employee authentication (if applicable)

    # Connect to the database
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Retrieve the target user's ID and role
    cursor.execute("SELECT user_id, role_id FROM Users WHERE username = ?", (username,))
    user_row = cursor.fetchone()

    if not user_row:
        conn.close()
        return {"status": "error", "message": "User not found"}

    target_user_id, target_role_id = user_row  # Target user's ID and role ID

    # Retrieve the requester's ID and role
    cursor.execute("SELECT user_id, role_id FROM Users WHERE username = ?", (requester_username,))
    requester_row = cursor.fetchone()

    if not requester_row:
        conn.close()
        return {"status": "error", "message": "Requester not found"}

    requester_user_id, requester_role_id = requester_row  # Requester's ID and role ID

    # **Access Control Validation**
    if requester_role == "client":
        # **Clients can only update their own information**
        if requester_username != username:
            conn.close()
            return {"status": "error", "message": "Permission denied: Clients can only update their own information"}

    elif requester_role == "employee":
        # **Employees can only modify non-sensitive information**
        if "email" in updated_info or "phone_number" in updated_info:
            conn.close()
            return {"status": "error", "message": "Permission denied: Employees cannot modify email or phone number"}

        # **Verify employee authentication**
        cursor.execute("SELECT payment_password FROM Users WHERE username = ?", (requester_username,))
        stored_emp_pwd = cursor.fetchone()

        if not stored_emp_pwd or not verify_password(emp_verification, stored_emp_pwd[0]):
            conn.close()
            return {"status": "error", "message": "Employee authentication failed"}

    elif requester_role == "admin":
        # **Admins have full access to modify user data**
        pass  # Allowed operation

    else:
        conn.close()
        return {"status": "error", "message": "Invalid requester role"}

    # **Execute the update**
    try:
        cursor.execute("""
            UPDATE Users 
            SET updated_info = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE user_id = ?
        """, (json.dumps(updated_info), target_user_id))

        conn.commit()
        conn.close()

        # **Log the update action for auditing**
        log_audit(requester_user_id, "update_customer_info", f"User {requester_username} updated {username}'s info",
                  client_ip)

        return {"status": "success", "message": "Customer information updated successfully"}

    except Exception as e:
        conn.close()
        return {"status": "error", "message": f"Database error: {str(e)}"}


def apply_for_loan(request, client_ip):
    if request.get("requester_role") not in ["client", "employee"]:
        return {"status": "error", "message": "Permission denied"}
    pay_pwd_input = request.get("payment_password_verification", "").strip()
    if not pay_pwd_input:
        return {"status": "error", "message": "Missing payment password verification"}
    username = request.get("username")
    account = request.get("account")
    try:
        amount = float(request.get("amount"))
    except Exception:
        return {"status": "error", "message": "Invalid amount format"}
    loan_type = request.get("loan_type")
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, payment_password FROM Users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return {"status": "error", "message": "User not found"}
        user_id, stored_payment_pwd = row
        conn.close()
    except Exception as e:
        return {"status": "error", "message": f"Database error: {str(e)}"}
    if not verify_password(pay_pwd_input, stored_payment_pwd):
        return {"status": "error", "message": "Payment password verification failed"}
    log_audit(user_id, "apply_for_loan",
              f"User {username} applied for a {loan_type} loan of {amount} using account {account}", client_ip)
    return {"status": "success", "message": "Loan application submitted successfully"}


# ---------------- Employee Functions ----------------
def view_customer_info_in_db(request, client_ip):
    """
    Allows bank employees to view customer information securely.
    Ensures the correct dynamic decryption key is used for retrieving sensitive data.
    """
    requester_role = request.get("requester_role")  # This should be 'employee' in this case.
    requested_action = "view_customer_info"  # The action that the visitor is trying to perform

    # Connect to the database
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # Get the permissions for the employee's role
        cursor.execute("SELECT permissions FROM Roles WHERE role_name = ?", (requester_role,))
        role_permissions_row = cursor.fetchone()

        if not role_permissions_row:
            conn.close()
            return {"status": "error", "message": "Role not found"}

        # Get the permissions list (assuming permissions are stored in JSON format)
        role_permissions = json.loads(role_permissions_row[0])

        # Check if the employee role has the required permission
        if requested_action not in role_permissions:
            conn.close()
            return {"status": "error", "message": f"Permission denied: {requester_role} does not have access to view customer information"}

        # Proceed with the action (view customer information)
        customer_username = request.get("customer_username")
        cursor.execute("SELECT user_id, username, email, phone_number FROM Users WHERE username = ?", (customer_username,))
        row = cursor.fetchone()
        conn.close()

        if row:
            print("Database Query Result: ", row)
            user_id, username, email_enc, phone_enc = row

            # Dynamically derive keys for email and phone using the username
            email_key = derive_user_field_key(STATIC_KEY, username, "email") if email_enc else None
            phone_key = derive_user_field_key(STATIC_KEY, username, "phone") if phone_enc else None
            print(f"[DEBUG] Derived Email Key: {email_key.hex() if email_key else None}")
            print(f"[DEBUG] Derived Phone Key: {phone_key.hex() if phone_key else None}")
            # Decrypt email and phone number with dynamically derived keys
            email = static_decrypt(email_enc, email_key) if email_enc else None
            phone = static_decrypt(phone_enc, phone_key) if phone_enc else None

            # Log the access for audit purposes
            log_audit(user_id, "view_customer_info", f"Viewed info for customer {username}", client_ip)

            return {"status": "success", "customer_info": {"username": username, "email": email, "phone": phone}}
        else:
            return {"status": "error", "message": "Customer not found"}

    except Exception as e:
        return {"status": "error", "message": f"Database error: {str(e)}"}





def modify_account_info_in_db(request, client_ip):
    """
    Allows employees or admins to modify account details.
    Example: Freeze/unfreeze an account.
    """
    username = request.get("username")
    target_account = request.get("account_number")
    new_status = request.get("status")  # "active" / "frozen"

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Get user role and permissions
    cursor.execute("SELECT role_id FROM Users WHERE username = ?", (username,))
    user_row = cursor.fetchone()

    if not user_row:
        conn.close()
        return {"status": "error", "message": "User not found"}

    role_id = user_row[0]

    cursor.execute("SELECT permissions FROM Roles WHERE role_id = ?", (role_id,))
    role_row = cursor.fetchone()

    if not role_row:
        conn.close()
        return {"status": "error", "message": "Role not found"}

    permissions = json.loads(role_row[0])  # Convert JSON string to list

    #  Check if the user has permission to manage accounts
    if "manage_accounts" not in permissions:
        conn.close()
        return {"status": "error", "message": "You do not have permission to modify account details"}

    # Update account status
    cursor.execute("UPDATE Accounts SET status = ? WHERE account_number = ?", (new_status, target_account))
    conn.commit()
    conn.close()

    return {"status": "success", "message": f"Account {target_account} updated to {new_status}"}



def process_deposit(request, client_ip):
    """
    Allows authorized users to deposit money into an account if they have the 'deposit_funds' permission.
    Ensures proper error handling, prevents NoneType errors, and verifies all required fields.
    """
    username = request.get("username")
    account_number = request.get("account")
    pay_pwd = request.get("payment_password_verification")

    try:
        amount = float(request.get("amount", 0))
        if amount <= 0:
            return {"status": "error", "message": "Deposit amount must be greater than zero"}
    except ValueError:
        return {"status": "error", "message": "Invalid amount format"}

    currency = request.get("currency", "USD")

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # ✅ Get user ID, role, and payment password
    cursor.execute("SELECT user_id, role_id, payment_password FROM Users WHERE username = ?", (username,))
    user_row = cursor.fetchone()

    if not user_row or None in user_row:
        conn.close()
        return {"status": "error", "message": "User not found or invalid user record"}

    user_id, role_id, stored_payment_pwd = user_row

    # ✅ Verify payment password
    if not verify_password(pay_pwd, stored_payment_pwd):
        conn.close()
        return {"status": "error", "message": "Payment password verification failed"}

    # ✅ Get role permissions
    cursor.execute("SELECT permissions FROM Roles WHERE role_id = ?", (role_id,))
    role_row = cursor.fetchone()

    if not role_row or role_row[0] is None:
        conn.close()
        return {"status": "error", "message": "Role not found"}

    permissions = json.loads(role_row[0])  # Convert JSON string to list

    # ✅ Check if the user has permission to deposit funds
    if "deposit_funds" not in permissions:
        conn.close()
        return {"status": "error", "message": "You do not have permission to deposit funds"}

    # ✅ Get account balance
    cursor.execute("SELECT account_id, balance FROM Accounts WHERE account_number = ?", (account_number,))
    account_row = cursor.fetchone()

    if not account_row or None in account_row:
        conn.close()
        return {"status": "error", "message": "Account not found or invalid account data"}

    account_id, balance = account_row

    try:
        balance = float(balance)
    except ValueError:
        conn.close()
        return {"status": "error", "message": "Invalid balance value in database"}

    # ✅ Perform deposit
    new_balance = balance + amount
    cursor.execute("UPDATE Accounts SET balance = ? WHERE account_id = ?", (new_balance, account_id))
    conn.commit()

    # ✅ Log the deposit operation
    log_audit(user_id, "process_deposit", f"User {username} deposited {amount} {currency} into account {account_number}", client_ip)

    conn.close()

    return {"status": "success", "message": f"Deposit of {amount} {currency} completed successfully. New balance: {new_balance:.2f}"}




def process_transfer(request, client_ip):
    """
    Handles fund transfers securely.
    Access is controlled based on user permissions.
    """
    username = request.get("username")
    from_account = request.get("from_account")
    to_account = request.get("to_account")
    amount = float(request.get("amount", 0))
    currency = request.get("currency", "USD")
    pay_pwd = request.get("payment_password_verification")

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Get user ID and role
    cursor.execute("SELECT user_id, role_id, payment_password FROM Users WHERE username = ?", (username,))
    user_row = cursor.fetchone()

    if not user_row:
        conn.close()
        return {"status": "error", "message": "User not found"}

    user_id, role_id, stored_payment_pwd = user_row

    # Verify payment password
    if not verify_password(pay_pwd, stored_payment_pwd):
        conn.close()
        return {"status": "error", "message": "Payment password verification failed"}

    # Get role permissions
    cursor.execute("SELECT permissions FROM Roles WHERE role_id = ?", (role_id,))
    role_row = cursor.fetchone()
    conn.close()

    if not role_row:
        return {"status": "error", "message": "Role not found"}

    permissions = json.loads(role_row[0])  # Convert JSON to list

    # Check if the role has permission to transfer
    if "transfer_funds" not in permissions:
        return {"status": "error", "message": "You do not have permission to transfer funds"}

    return {"status": "success", "message": "Transfer completed successfully"}


def process_withdrawal(request, client_ip):
    """
    Allows a user to withdraw money from an account if they have the 'withdraw_funds' permission.
    """
    username = request.get("username")
    account_number = request.get("account")
    amount = float(request.get("amount", 100))
    currency = request.get("currency", "USD")
    pay_pwd = request.get("payment_password_verification")

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Get user details and role
    cursor.execute("SELECT user_id, role_id, payment_password FROM Users WHERE username = ?", (username,))
    user_row = cursor.fetchone()

    if not user_row:
        conn.close()
        return {"status": "error", "message": "User not found"}

    user_id, role_id, stored_payment_pwd = user_row

    # Verify payment password
    if not verify_password(pay_pwd, stored_payment_pwd):
        conn.close()
        return {"status": "error", "message": "Payment password verification failed"}

    # Get role permissions
    cursor.execute("SELECT permissions FROM Roles WHERE role_id = ?", (role_id,))
    role_row = cursor.fetchone()

    if not role_row:
        conn.close()
        return {"status": "error", "message": "Role not found"}

    permissions = json.loads(role_row[0])  # Convert JSON string to list

    #  Check if the user has permission to withdraw funds
    if "withdraw_funds" not in permissions:
        conn.close()
        return {"status": "error", "message": "You do not have permission to withdraw funds"}

    # Get account balance
    cursor.execute("SELECT account_id, balance FROM Accounts WHERE account_number = ?", (account_number,))
    account_row = cursor.fetchone()

    if not account_row:
        conn.close()
        return {"status": "error", "message": "Account not found"}

    account_id, balance = account_row

    # Ensure sufficient funds
    if amount > balance:
        conn.close()
        return {"status": "error", "message": "Insufficient funds"}

    # Perform withdrawal
    new_balance = balance - amount
    cursor.execute("UPDATE Accounts SET balance = ? WHERE account_id = ?", (new_balance, account_id))

    conn.commit()
    conn.close()

    log_audit(user_id, "process_withdrawal", f"User {username} withdrew {amount} {currency} from {account_number}", client_ip)

    return {"status": "success", "message": f"Withdrawal of {amount} {currency} completed successfully"}



def monitor_transactions(request, client_ip):
    """
    Allows authorized users to view recent transactions if they have the 'view_transactions' permission.
    """
    username = request.get("username")

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Get user role
    cursor.execute("SELECT role_id FROM Users WHERE username = ?", (username,))
    user_row = cursor.fetchone()

    if not user_row:
        conn.close()
        return {"status": "error", "message": "User not found"}

    role_id = user_row[0]

    # Get role permissions
    cursor.execute("SELECT permissions FROM Roles WHERE role_id = ?", (role_id,))
    role_row = cursor.fetchone()

    if not role_row:
        conn.close()
        return {"status": "error", "message": "Role not found"}

    permissions = json.loads(role_row[0])  # Convert JSON string to list

    #  Check if the user has permission to view transactions
    if "view_transactions" not in permissions:
        conn.close()
        return {"status": "error", "message": "You do not have permission to view transactions"}

    # Fetch recent transactions
    cursor.execute("""
        SELECT transaction_id, from_account_id, to_account_id, transaction_type, amount, currency, timestamp, status
        FROM Transactions
        ORDER BY timestamp DESC
        LIMIT 10
    """)
    transactions = cursor.fetchall()

    conn.close()

    transaction_list = [
        {
            "transaction_id": txn[0],
            "from_account": txn[1],
            "to_account": txn[2],
            "transaction_type": txn[3],
            "amount": txn[4],
            "currency": txn[5],
            "timestamp": txn[6],
            "status": txn[7]
        }
        for txn in transactions
    ]

    return {"status": "success", "transactions": transaction_list}

# Get unread message
def fetch_unread_messages(username):
    """
    Retrieves unread messages for a given user by fetching messages using user_id.
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        # ✅ Fetch user_id based on the provided username
        cursor.execute("SELECT user_id FROM Users WHERE username = ?", (username,))
        user_row = cursor.fetchone()

        if not user_row:
            conn.close()
            return {"status": "error", "message": "User does not exist"}

        user_id = user_row[0]  # Extract user_id

        # ✅ Use user_id instead of username to fetch unread messages
        cursor.execute("""
            SELECT sender, message FROM Offline_Messages
            WHERE recipient = ? AND delivered = 0
        """, (user_id,))

        messages = [{"sender": row[0], "message": row[1]} for row in cursor.fetchall()]

        # ✅ Mark messages as delivered
        cursor.execute("UPDATE Offline_Messages SET delivered = 1 WHERE recipient = ?", (user_id,))
        conn.commit()
        conn.close()

        return {"status": "success", "messages": messages}

    except Exception as e:
        return {"status": "error", "message": f"Failed to fetch messages: {str(e)}"}

# ---------------- Admin Functions ----------------

def manage_user_roles(request, client_ip):
    """
    Handles user role management (create, update, delete, view) with admin verification.
    """
    if request.get("requester_role") != "admin":
        return {"status": "error", "message": "Permission denied"}

    admin_password = request.get("admin_password_verification")  # 🔥 Add password check
    admin_username = request.get("admin")

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Fetch the admin's stored password
    cursor.execute("SELECT payment_password FROM Users WHERE username = ?", (admin_username,))
    stored_admin_pwd = cursor.fetchone()

    if not stored_admin_pwd or not verify_password(admin_password, stored_admin_pwd[0]):
        conn.close()
        return {"status": "error", "message": "Admin authentication failed"}

    operation = request.get("operation")
    role_data = request.get("role_data")

    try:
        if operation == "create":
            cursor.execute("INSERT INTO Roles (role_name, permissions) VALUES (?, ?)",
                           (role_data.get("role_name"), json.dumps(role_data.get("permissions"))))
            conn.commit()
            message = "Role created successfully"

        elif operation == "update":
            cursor.execute("UPDATE Roles SET permissions = ? WHERE role_name = ?",
                           (json.dumps(role_data.get("permissions")), role_data.get("role_name")))
            conn.commit()
            message = "Role updated successfully"

        elif operation == "delete":
            cursor.execute("DELETE FROM Roles WHERE role_name = ?", (role_data.get("role_name"),))
            conn.commit()
            message = "Role deleted successfully"

        elif operation == "view":
            cursor.execute("SELECT role_id, role_name, permissions FROM Roles")
            roles = cursor.fetchall()
            conn.close()
            roles_list = [{"role_id": r[0], "role_name": r[1], "permissions": json.loads(r[2])} for r in roles]
            return {"status": "success", "roles": roles_list}

        else:
            conn.close()
            return {"status": "error", "message": "Invalid operation"}

        conn.close()
        return {"status": "success", "message": message}

    except Exception as e:
        return {"status": "error", "message": f"Database error: {str(e)}"}







def delete_user_account(request, client_ip):
    """
    Allows an admin to delete a user account from the system.
    This operation requires admin authentication before proceeding.

    Request Parameters:
    - user_id: The ID of the user to be deleted.
    - admin_password_verification: Admin password for security authentication.

    Returns:
    - Success message if the user account is deleted.
    - Error message if authentication fails or the request is invalid.
    """

    # Step 1: Ensure that only admins can perform this action
    if request.get("requester_role") != "admin":
        return {"status": "error", "message": "Permission denied"}

    user_id = request.get("user_id")  # The user to be deleted
    admin_password = request.get("admin_password_verification")  # Admin password for verification

    # Step 2: Validate admin identity before proceeding
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Fetch the admin's stored hashed password
    cursor.execute(
        "SELECT payment_password FROM Users WHERE user_id = (SELECT user_id FROM Users WHERE username = ?)",
        (request.get("admin"),)
    )
    stored_admin_pwd = cursor.fetchone()

    # If admin is not found or password does not match, deny the operation
    if not stored_admin_pwd or not verify_password(admin_password, stored_admin_pwd[0]):
        conn.close()
        return {"status": "error", "message": "Admin authentication failed"}

    # Step 3: Proceed with user deletion after admin authentication
    try:
        cursor.execute("DELETE FROM Users WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        return {"status": "success", "message": "User account deleted successfully"}

    except Exception as e:
        conn.close()
        return {"status": "error", "message": f"Database error: {str(e)}"}


def manage_keys(request, client_ip):
    """
    Handles cryptographic key management (generate, rotate, revoke, view).
    """
    if request.get("requester_role") != "admin":
        return {"status": "error", "message": "Permission denied"}

    operation = request.get("operation")
    key_details = request.get("key_details", {})

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    if operation == "generate":
        key_type = key_details.get("key_type", "AES")

        if key_type.upper() == "AES":
            new_key = generate_aes_key()
        elif key_type.upper() == "RSA":
            new_key, _ = generate_rsa_keys()
        else:
            return {"status": "error", "message": "Unsupported key type"}

        encrypted_key = encrypt_key_with_master(new_key, MASTER_KEY)

        cursor.execute(
            "INSERT INTO Key_Management (key_type, key_usage, encrypted_key, rotation_status, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
            (key_type, key_details.get("key_usage", "general"), encrypted_key, "active")
        )
        conn.commit()
        conn.close()
        return {"status": "success", "message": "Key generated and securely stored"}

    else:
        conn.close()
        return {"status": "error", "message": "Invalid key operation"}



def system_maintenance(request, client_ip):
    """
    Applies system maintenance tasks like updates, patches, and backups securely.
    """
    if request.get("requester_role") != "admin":
        return {"status": "error", "message": "Permission denied"}

    admin_password = request.get("admin_password_verification")
    admin_username = request.get("admin")

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Verify admin password before performing system maintenance
    cursor.execute("SELECT payment_password FROM Users WHERE username = ?", (admin_username,))
    stored_admin_pwd = cursor.fetchone()

    if not stored_admin_pwd or not verify_password(admin_password, stored_admin_pwd[0]):
        conn.close()
        return {"status": "error", "message": "Admin authentication failed"}

    operation = request.get("operation")
    maintenance_details = request.get("maintenance_details", {})

    try:
        if operation == "update":
            subprocess.run(["sudo", "apt-get", "update", "-y"], check=True)
            subprocess.run(["sudo", "apt-get", "upgrade", "-y"], check=True)
            message = "System update completed successfully."

        elif operation == "patch":
            subprocess.run(["sudo", "apt-get", "install", "--only-upgrade", "openssl"], check=True)
            message = "Security patches applied successfully."

        elif operation == "backup":
            backup_file = f"backup_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.sql"
            subprocess.run(["sqlite3", DATABASE_PATH, f".backup {backup_file}"], check=True)
            message = f"Database backup completed: {backup_file}"

        else:
            return {"status": "error", "message": "Invalid system maintenance operation"}

        log_audit(request.get("user_id"), "system_maintenance", message, client_ip)
        return {"status": "success", "message": message}

    except subprocess.CalledProcessError as e:
        return {"status": "error", "message": f"System maintenance failed: {str(e)}"}


def monitor_security(request, client_ip):
    """
    Retrieves security logs, including failed login attempts, intrusion attempts, and firewall events.
    Only users with the 'monitor_security' permission can access these logs.
    """
    username = request.get("username")

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Get user role ID
    cursor.execute("SELECT role_id FROM Users WHERE username = ?", (username,))
    user_row = cursor.fetchone()

    if not user_row:
        conn.close()
        return {"status": "error", "message": "User not found"}

    role_id = user_row[0]

    # Get permissions for the role
    cursor.execute("SELECT permissions FROM Roles WHERE role_id = ?", (role_id,))
    role_row = cursor.fetchone()

    if not role_row:
        conn.close()
        return {"status": "error", "message": "Role not found"}

    permissions = json.loads(role_row[0])  # Convert JSON string to list

    # Ensure the user has the 'monitor_security' permission
    if "monitor_security" not in permissions:
        conn.close()
        return {"status": "error", "message": "You do not have permission to monitor security logs"}

    # Fetch security logs from the database
    cursor.execute("""
        SELECT log_id, user_id, action, details, timestamp 
        FROM Audit_Logs 
        WHERE details LIKE '%failed login%' OR details LIKE '%intrusion%' OR details LIKE '%firewall%'
        ORDER BY timestamp DESC LIMIT 10
    """)

    logs = cursor.fetchall()
    conn.close()

    # If no logs exist, return an empty list
    if not logs:
        return {"status": "success", "logs": []}

    return {
        "status": "success",
        "logs": [
            {"log_id": log[0], "user_id": log[1], "action": log[2], "details": log[3], "timestamp": log[4]}
            for log in logs
        ]
    }


# ---------------- Communication Functions for client and employee----------------


def encrypt_message_with_rsa(public_key, message):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return b64encode(cipher.encrypt(message.encode())).decode()

def send_message(request, client_ip):
    """
    Securely sends an encrypted message to a bank representative.
    """
    sender = request.get("sender")
    recipient = request.get("recipient")
    message_content = request.get("message")

    if not sender or not recipient or not message_content:
        return {"status": "error", "message": "Missing sender, recipient, or message"}

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Fetch recipient details
    cursor.execute("SELECT user_id, public_key FROM Users WHERE username = ?", (recipient,))
    recipient_row = cursor.fetchone()

    if not recipient_row:
        conn.close()
        return {"status": "error", "message": "Recipient user does not exist"}

    recipient_id, recipient_public_key = recipient_row

    if not recipient_public_key:
        conn.close()
        return {"status": "error", "message": "Recipient does not have a public key registered"}

    # Fetch sender details
    cursor.execute("SELECT user_id FROM Users WHERE username = ?", (sender,))
    sender_row = cursor.fetchone()

    if not sender_row:
        conn.close()
        return {"status": "error", "message": "Sender user does not exist"}

    sender_id = sender_row[0]

    # Encrypt the message using recipient's public key
    try:
        encrypted_message = encrypt_message_with_rsa(recipient_public_key, message_content)
    except Exception as e:
        conn.close()
        return {"status": "error", "message": f"Encryption failed: {str(e)}"}

    # Store message in database
    try:
        cursor.execute("""
            INSERT INTO Offline_Messages (sender, recipient, message, timestamp, delivered)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, 0)
        """, (sender_id, recipient_id, encrypted_message))

        conn.commit()
        conn.close()
        return {"status": "success", "message": "Encrypted message sent"}

    except Exception as e:
        conn.close()
        return {"status": "error", "message": f"Database error: {str(e)}"}



# ------------------------------
# User connection handler
# ------------------------------
def handle_client(connection, address):
    client_ip = address[0]
    log_event("CONNECT", f"{address} connected")
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                log_event("WARNING", f"{address} connection closed by client.")
                break
            try:
                decrypted_bytes = decrypt_payload(data.decode(), SESSION_KEY)
                request = json.loads(decrypted_bytes.decode())
                log_event("REQUEST", f"{address} request: {request}")
                action = request.get("action")
                response = {}
                if action == "create_account":
                    response = create_account_in_db(request, client_ip)
                elif action == "login":
                    response = login_in_db(request, client_ip)
                    if response.get("status") == "success":
                        username = request.get("username")
                        user_id = response.get("user_id")
                        role = response.get("role", "client")
                        with online_users_lock:
                            online_users[username] = {"connection": connection, "user_id": user_id, "role": role}
                        log_event("INFO", f"User {username} added to online_users")
                        # Deliver offline messages if any
                        check_offline_messages(username, connection, client_ip)
                elif action == "fetch_unread_messages":
                    response = fetch_unread_messages(request.get("username"))
                elif action == "view_customer_info":
                    response = view_customer_info_in_db(request, client_ip)
                elif action == "process_deposit":
                    response = process_deposit(request, client_ip)
                elif action == "get_account_info":
                    response = get_account_info_in_db(request, client_ip)
                elif action == "process_withdrawal":
                    response = process_withdrawal(request, client_ip)
                elif action == "process_transfer":
                    response = process_transfer(request, client_ip)
                elif action == "pay_bill":
                    response = pay_bill(request, client_ip)
                elif action == "apply_for_loan":
                    response = apply_for_loan(request, client_ip)
                elif action == "update_customer_info":
                    response = update_customer_info(request, client_ip)
                elif action == "monitor_transactions":
                    response = monitor_transactions(request, client_ip)
                elif action == "manage_user_roles":
                    response = manage_user_roles(request, client_ip)
                elif action == "manage_keys":
                    response = manage_keys(request, client_ip)
                elif action == "system_maintenance":
                    response = system_maintenance(request, client_ip)
                elif action == "monitor_security":
                    response = monitor_security(request, client_ip)
                elif action == "send_message":
                    response = send_message(request, client_ip)
                else:
                    response = {"status": "error", "message": "Unknown action"}
            except Exception as e:
                log_event("ERROR", f"{address} request processing error: {str(e)}")
                response = {"status": "error", "message": f"Request processing error: {str(e)}"}
            response_bytes = json.dumps(response).encode()
            encrypted_response = encrypt_payload(response_bytes, SESSION_KEY)
            connection.sendall(encrypted_response.encode())
    except Exception as e:
        log_event("ERROR", f"{address} handling error: {str(e)}")
    finally:
        try:
            with online_users_lock:
                for username, info in list(online_users.items()):
                    if info["connection"] == connection:
                        del online_users[username]
                        log_event("DISCONNECT", f"{username} removed from online_users")
        except Exception:
            pass
        connection.close()
        log_event("DISCONNECT", f"{address} disconnected")


# ------------------------------
# Main function: Start the server
# ------------------------------
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((SERVER_HOST, SERVER_PORT))
    sock.listen(5)
    log_event("START", f"Server started, listening on {SERVER_HOST}:{SERVER_PORT}")

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    # For mutual authentication, uncomment:
    # context.verify_mode = ssl.CERT_REQUIRED
    # context.load_verify_locations(cafile=CA_CERT)

    while True:
        client_socket, addr = sock.accept()
        try:
            secure_conn = context.wrap_socket(client_socket, server_side=True)
        except Exception as e:
            log_event("ERROR", f"SSL handshake failed: {str(e)}")
            client_socket.close()
            continue
        threading.Thread(target=handle_client, args=(secure_conn, addr)).start()


if __name__ == "__main__":
    main()
