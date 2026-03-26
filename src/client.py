import socket
import ssl
import json
import getpass
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from hashlib import sha256
from config import SERVER_HOST, SERVER_PORT, CERTFILE, KEYFILE, CA_CERT, SESSION_KEY
import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import sqlite3
import rsa

# -------------------------------
# AES encryption/decryption functions (using AES-GCM)
# -------------------------------
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return b64encode(cipher.nonce).decode(), b64encode(ciphertext).decode(), b64encode(tag).decode()

def aes_decrypt(nonce_b64, ciphertext_b64, tag_b64, key):
    nonce = b64decode(nonce_b64)
    ciphertext = b64decode(ciphertext_b64)
    tag = b64decode(tag_b64)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def encrypt_payload(data, session_key):
    nonce, ciphertext, tag = aes_encrypt(data, session_key)
    return json.dumps({"nonce": nonce, "ciphertext": ciphertext, "tag": tag})

def decrypt_payload(encrypted_json, session_key):
    payload = json.loads(encrypted_json)
    decrypted_data = aes_decrypt(payload["nonce"], payload["ciphertext"], payload["tag"], session_key)
    return decrypted_data

# -------------------------------
# MyBankClient Class (for client role)
# -------------------------------
class MyBankClient:
    def __init__(self, server_host, server_port, certfile, keyfile, ca_cert):
        self.server_host = server_host
        self.server_port = server_port
        self.certfile = certfile
        self.keyfile = keyfile
        self.ca_cert = ca_cert
        self.session_key = SESSION_KEY  # set in config
        self.secure_sock = None
        self.username = None

    def connect(self):
        print("Connecting to secure server...")
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.ca_cert)
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        sock = socket.socket()
        self.secure_sock = context.wrap_socket(sock, server_hostname=self.server_host)
        self.secure_sock.connect((self.server_host, self.server_port))
        print("Connected successfully.")

    def disconnect(self):
        if self.secure_sock:
            self.secure_sock.close()
            print("Disconnected from server.")

    def send_request(self, data):
        encrypted_data = encrypt_payload(json.dumps(data).encode(), self.session_key)
        self.secure_sock.sendall(encrypted_data.encode())
        response = self.secure_sock.recv(4096).decode()
        try:
            decrypted_response = decrypt_payload(response, self.session_key)
            return json.loads(decrypted_response.decode())
        except Exception as e:
            print("Failed to decrypt response:", e)
            return None

    # -------------------------------
    # Register new client account
    # -------------------------------
    def create_account(self):
        print("----- Register New Account -----")
        username = input("Enter username: ")
        password = input("Enter password: ")
        email = input("Enter email: ")
        phone = input("Enter phone number: ")
        pay_password = input("Enter payment password: ")
        role = "client"
        data = {
            "action": "create_account",
            "username": username,
            "password": password,
            "email": email,
            "phone": phone,
            "pay_password": pay_password,
            "role": role
        }
        response = self.send_request(data)
        print("Registration response:", response)

    # -------------------------------
    # Client login with OTP (two-phase login)
    # -------------------------------
    def login(self):
        """
        Handles client login with OTP verification and role validation.
        Ensures non-clients cannot log into the client panel.
        """
        print("----- Client Login -----")
        username = input("Enter username: ")
        password = input("Enter password: ")

        data = {
            "action": "login",
            "username": username,
            "password": password,
            "otp": ""  # First request without OTP
        }

        response = self.send_request(data)

        if response:
            if response.get("status") == "otp_required":
                print(f"OTP has been sent. Check the file 'otp_{username}.txt'.")

                # Prompt for OTP immediately instead of restarting login
                otp = input("Enter OTP: ")
                data["otp"] = otp
                response = self.send_request(data)  # Resend with OTP

            if response.get("status") == "success":
                role = response.get("role", "client")  # Default role is "client"

                # ✅ Enforce Role-Based Login (Block non-clients)
                if role != "client":
                    print("❌ Access denied: Only clients can log in here.")
                    return False  # Prevent further execution

                print(f"✅ Login successful! Welcome, {username}")
                self.username = username  # Set username after successful login
                return True  # Allow access

            else:
                print("❌ Login failed:", response.get("message"))
                return False  # Prevent further execution
        else:
            print("⚠ No response from server.")
            return False  # Prevent further execution

    # -------------------------------
    # Get account information (client view)
    # -------------------------------
    def get_account_info(self):
        if not self.username:
            print("Please log in first.")
            return
        print("----- Get Account Information -----")
        data = {
            "action": "get_account_info",
            "username": self.username,
            "requester_role": "client"
        }
        response = self.send_request(data)
        print("Account Information:", response)

    # -------------------------------
    # Transfer funds (requires payment password verification)
    # -------------------------------
    import getpass

    def transfer_funds(self):
        if not self.username:
            print("Please log in first.")
            return
        print("----- Transfer Funds -----")
        from_account = input("Enter source account number: ")
        to_account = input("Enter destination account number: ")
        amount = input("Enter transfer amount: ")
        currency = input("Enter currency (default USD): ") or "USD"
        pay_pwd = input("Enter payment password for verification: ")  # 🔒 Hide input

        data = {
            "action": "process_transfer",
            "username": self.username,
            "from_account": from_account,
            "to_account": to_account,
            "amount": amount,
            "currency": currency,
            "payment_password_verification": pay_pwd,
            "requester_role": "client"
        }
        response = self.send_request(data)
        print("Transfer response:", response.get("message"))

    # -------------------------------
    # Pay bill (requires payment password verification)
    # -------------------------------
    def pay_bill(self):
        if not self.username:
            print("Please log in first.")
            return
        print("----- Pay Bill -----")
        account = input("Enter account number for payment: ")
        biller = input("Enter biller name: ")
        amount = input("Enter payment amount: ")
        pay_pwd = input("Enter payment password for verification: ")
        data = {
            "action": "pay_bill",
            "username": self.username,
            "account": account,
            "biller": biller,
            "amount": amount,
            "payment_password_verification": pay_pwd,
            "requester_role": "client"
        }
        response = self.send_request(data)
        print("Bill payment response:", response.get("message"))

    # -------------------------------
    # Update personal information
    # -------------------------------
    def update_info(self):
        if not self.username:
            print("Please log in first.")
            return
        print("----- Update Personal Information -----")
        new_address = input("Enter new address: ")
        new_phone = input("Enter new phone number: ")
        data = {
            "action": "update_info",
            "username": self.username,
            "updated_info": {
                "address": new_address,
                "phone": new_phone
            },
            "requester_role": "client"
        }
        response = self.send_request(data)
        print("Update response:", response.get("message"))

    # -------------------------------
    # Apply for loan (requires payment password verification)
    # -------------------------------
    def apply_for_loan(self):
        if not self.username:
            print("Please log in first.")
            return
        print("----- Apply for Loan -----")
        account = input("Enter loan account number: ")
        amount = input("Enter loan amount: ")
        loan_type = input("Enter loan type (e.g., personal, mortgage): ")
        pay_pwd = input("Enter payment password for verification: ")
        data = {
            "action": "apply_for_loan",
            "username": self.username,
            "account": account,
            "amount": amount,
            "loan_type": loan_type,
            "payment_password_verification": pay_pwd,
            "requester_role": "client"
        }
        response = self.send_request(data)
        print("Loan application response:", response.get("message"))

    # -------------------------------
    # Send message to bank representative
    # -------------------------------
    import rsa
    import sqlite3

    def send_message(self):
        """
        Sends a plaintext message to the server without encryption.
        """
        if not self.username:
            print("Please log in first.")
            return

        print("----- Send Message -----")
        recipient = input("Enter recipient username: ")
        message = input("Enter message: ")

        # Send plaintext message
        data = {
            "action": "send_message",
            "sender": self.username,
            "recipient": recipient,
            "message": message  #  Sent as plaintext
        }

        response = self.send_request(data)
        print("📨 Message response:", response.get("message"))
    # -------------------------------
    # Get private_key from key_management
    # -------------------------------

    def retrieve_private_key(username):
        """
        Retrieves and decrypts the private key for a given user from KeyManagement.
        """
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT private_key FROM KeyManagement WHERE username = ?", (username,))
            row = cursor.fetchone()
            conn.close()

            if row and row[0]:
                decrypted_private_key = cipher.decrypt(row[0].encode()).decode()
                return decrypted_private_key
            else:
                print(f"[INFO] No private key found for {username}.")
                return None
        except Exception as e:
            print(f"[ERROR] Failed to retrieve private key for {username}: {str(e)}")
            return None

    # -------------------------------
    # decrypt_message
    # -------------------------------

    def decrypt_message_with_rsa(self, private_key_pem, encrypted_message):

        try:
            private_key = RSA.import_key(private_key_pem)
            cipher_rsa = PKCS1_OAEP.new(private_key)
            decrypted_message = cipher_rsa.decrypt(base64.b64decode(encrypted_message))
            return decrypted_message.decode()
        except Exception as e:
            print(f"⚠ Error decrypting message: {str(e)}")
            return f"[Encrypted message: {encrypted_message}]"
    # -------------------------------
    # get unread message
    # -------------------------------

    def fetch_unread_messages(self):
        """
        Fetches, decrypts, and displays unread messages.
        """
        if not self.username:
            return

        data = {"action": "fetch_unread_messages", "username": self.username}
        response = self.send_request(data)

        if response:
            if response.get("status") == "success" and "messages" in response:
                messages = response["messages"]
                if messages:
                    print("\n📩 Unread Messages:")

                    # ✅ Load the user's private key for decryption
                    try:
                        with open(self.keyfile, "r") as key_file:
                            private_key_pem = key_file.read()
                    except FileNotFoundError:
                        print(f"⚠ Private key file {self.keyfile} not found.")
                        return

                    for msg in messages:
                        decrypted_message = self.decrypt_message_with_rsa(private_key_pem, msg['message'])
                        print(f"📨 From {msg['sender']}: {decrypted_message}")
                else:
                    print("✅ No new messages.")
            else:
                print("⚠ Server response error:", response.get("message"))
        else:
            print("⚠ No response from server.")

    # -------------------------------
    # Main interactive menu
    # -------------------------------
    def run(self):
        """
        Main client menu, allowing users to interact with the system.
        Prevents system termination due to failed login.
        """
        while True:
            # If the user is not logged in, prompt for login
            if self.username is None:
                print("\n==== MyBank Client ====")
                print("1 - Register New Account")
                print("2 - User Login")
                print("9 - Exit")
                choice = input("Enter your choice: ")

                if choice == "1":
                    self.create_account()
                elif choice == "2":
                    # Call login, but only exit if login fails after retry
                    if not self.login():  # ✅ If login fails, prompt again instead of exiting
                        print("🔒 Login failed. Please try again.")
                        continue  # Keep asking for login if failed
                elif choice == "9":
                    print("Exiting.")
                    break  # Exit the program gracefully
                else:
                    print("Invalid option. Please try again.")
            else:
                print(f"Logged in as: {self.username}")
                self.fetch_unread_messages()
                print("3 - Get Account Information")
                print("4 - Transfer Funds")
                print("5 - Pay Bill")
                print("6 - Update Personal Information")
                print("7 - Apply for Loan")
                print("8 - Send Message to Bank Representative")
                print("9 - Logout")
                choice = input("Enter your choice: ")
                self.fetch_unread_messages()
                if choice == "3":
                    self.get_account_info()
                elif choice == "4":
                    self.transfer_funds()
                elif choice == "5":
                    self.pay_bill()
                elif choice == "6":
                    self.update_info()
                elif choice == "7":
                    self.apply_for_loan()
                elif choice == "8":
                    self.send_message()
                elif choice == "9":
                    print("Logging out.")
                    self.username = None
                    break  # ✅ Ensure proper logout and stop the loop
                else:
                    print("Invalid option, please try again.")


if __name__ == "__main__":
    client = MyBankClient(SERVER_HOST, SERVER_PORT, CERTFILE, KEYFILE, CA_CERT)
    try:
        client.connect()
    except Exception as e:
        print("Failed to connect to server:", e)
        exit(1)
    client.run()
