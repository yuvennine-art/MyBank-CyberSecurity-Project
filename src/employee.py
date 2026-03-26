import socket
import ssl
import json
import getpass
import sys
import random
import threading
from base64 import b64encode, b64decode
from config import SERVER_HOST, SERVER_PORT, CERTFILE, KEYFILE, CA_CERT, SESSION_KEY, EMPLOYEE_REG_CODE
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import sha256
import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from key_management import retrieve_private_key
from networkx import selfloop_edges
import sqlite3
import rsa
# -----------------------------
# AES encryption/decryption functions (AES-GCM)
# -----------------------------
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

# -----------------------------
# Employee Client Class
# -----------------------------
class BankEmployee:
    def __init__(self, server_host, server_port, certfile, keyfile, ca_cert):
        self.server_host = server_host
        self.server_port = server_port
        self.certfile = certfile    # Employee certificate
        self.keyfile = keyfile      # Employee private key
        self.ca_cert = ca_cert
        self.session_key = SESSION_KEY
        self.secure_sock = None
        self.username = None  # Employee username after login

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
        """
        Encrypts and sends a request to the server, ensuring it handles decryption failures gracefully.
        """
        try:
            encrypted_data = encrypt_payload(json.dumps(data).encode(), self.session_key)
            self.secure_sock.sendall(encrypted_data.encode())

            response_data = self.secure_sock.recv(4096)
            if not response_data:
                print("⚠ No response from server.")
                return {"status": "error", "message": "No response from server"}

            try:
                decrypted_response = decrypt_payload(response_data.decode(), self.session_key)
                return json.loads(decrypted_response.decode())
            except json.JSONDecodeError:
                print("⚠ Failed to parse JSON response from server.")
                return {"status": "error", "message": "Invalid JSON response from server"}
            except Exception as e:
                print(f"⚠ Decryption error: {str(e)}")
                return {"status": "error", "message": "Failed to decrypt server response"}

        except Exception as e:
            print(f"⚠ Error in send_request: {str(e)}")
            return {"status": "error", "message": "Request failed"}

    # Employee registration function with registration code validation from config
    def register(self):
        print("----- Employee Registration -----")
        username = input("Enter employee username: ")
        try:
            password = input("Enter password (hidden): ")
        except Exception:
            password = input("Enter password: ")
        pay_password = input("Enter employee operation password: ")
        email = input("Enter email: ")
        phone = input("Enter phone number: ")
        reg_code = input("Enter employee registration code: ")
        if reg_code != EMPLOYEE_REG_CODE:
            print("Registration code incorrect. Registration failed!")
            return
        data = {
            "action": "create_account",
            "username": username,
            "password": password,
            "pay_password": pay_password,
            "email": email,
            "phone": phone,
            "role": "employee"
        }
        response = self.send_request(data)
        print("Registration response:", response)

    # Employee login with OTP (two-phase login)

    def login(self):
        """
        Handles employee login with OTP verification and role validation.
        Ensures non-employees cannot log into the employee panel.
        """
        print("----- Employee Login -----")
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

                # ✅ Enforce Role-Based Login (Block non-employees)
                if role != "employee":
                    print("❌ Access denied: Only employees can log in here.")
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
    # Based function
    # -------------------------------

    def view_customer_info(self):
        if not self.username:
            print("Please log in first.")
            return
        print("----- View Customer Information -----")
        customer_username = input("Enter customer username: ")
        data = {
            "action": "view_customer_info",
            "requester_role": "employee",
            "customer_username": customer_username
        }
        response = self.send_request(data)
        if response.get("status") == "success":
            info = response.get("customer_info")
            print("Customer Information:")
            print("Username:", info.get("username"))
            print("Email:", info.get("email"))
            print("Phone:", info.get("phone"))
        else:
            print("Failed to retrieve customer information:", response.get("message"))

    import getpass

    def process_deposit(self):
        if not self.username:
            print("Please log in first.")
            return
        print("----- Process Deposit -----")

        customer_username = input("Enter customer username: ")
        try:
            amount = float(input("Enter deposit amount: "))  # ✅ Get deposit amount
            if amount <= 0:
                print("❌ Deposit amount must be greater than zero.")
                return
        except ValueError:
            print("❌ Invalid amount. Please enter a valid number.")
            return

        emp_pwd = getpass.getpass("Re-enter your employee password for verification: ")  # 🔒 Hide input

        data = {
            "action": "process_deposit",
            "requester_role": "employee",
            "username": customer_username,  # ✅ Send username instead of user_id
            "amount": amount,  # ✅ Include deposit amount
            "employee_password_verification": emp_pwd
        }
        response = self.send_request(data)
        print("Deposit response:", response.get("message"))

    def process_withdrawal(self):
        if not self.username:
            print("Please log in first.")
            return
        print("----- Process Withdrawal -----")
        customer_username = input("Enter customer username: ")
        data = {
            "action": "process_withdrawal",
            "requester_role": "employee",
            "username": customer_username
        }
        response = self.send_request(data)
        print("Withdrawal response:", response.get("message"))

    def process_transfer(self):
        if not self.username:
            print("Please log in first.")
            return
        print("----- Process Transfer -----")
        customer_username = input("Enter customer username: ")  # ✅ Use username instead of user ID
        from_account = input("Enter source account number: ")
        to_account = input("Enter destination account number: ")
        amount = input("Enter transfer amount: ")
        currency = input("Enter currency (default USD): ") or "USD"
        pay_pwd = input("Enter payment password for verification: ")  #

        data = {
            "action": "process_transfer",
            "requester_role": "employee",
            "username": customer_username,  #  Send username
            "from_account": from_account,
            "to_account": to_account,
            "amount": amount,
            "currency": currency,
            "payment_password_verification": pay_pwd
        }
        response = self.send_request(data)
        print("Transfer response:", response.get("message"))

    def update_info(self):
        if not self.username:
            print("Please log in first.")
            return
        print("----- Update Customer Information -----")
        customer_username = input("Enter customer username: ")  # Changed
        new_info = input("Enter new information (in JSON format): ")
        try:
            updated_info = json.loads(new_info)
        except Exception as e:
            print("Invalid JSON format:", e)
            return
        data = {
            "action": "update_customer_info",
            "requester_role": "employee",
            "username": customer_username,  #
            "updated_info": updated_info
        }
        response = self.send_request(data)
        print("Update response:", response.get("message"))

    def monitor_transactions(self):
        if not self.username:
            print("Please log in first.")
            return
        print("----- Monitor Transactions -----")
        customer_username = input("Enter customer username: ")  #
        data = {
            "action": "monitor_transactions",
            "requester_role": "employee",
            "username": customer_username  #
        }
        response = self.send_request(data)
        if response.get("status") == "success" and "transactions" in response:
            print("Recent transaction audit logs:")
            for log in response["transactions"]:
                print(f"ID: {log['log_id']} Action: {log['action']} Details: {log['details']} Timestamp: {log['timestamp']}")
        else:
            print("Failed to retrieve transaction logs:", response.get("message"))

    # -------------------------------
    # Communication function
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

    def retrieve_private_key(username):
        """
        Retrieves and decrypts the private key for a given user from Key_Management.
        """
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT private_key FROM Key_Management WHERE username = ?", (username,))
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

    # ✅ Define decrypt_message_with_rsa inside the class
    def decrypt_message_with_rsa(self, private_key_pem, encrypted_message):
        """
        Decrypts an RSA-encrypted message using the user's private key.
        """
        try:
            private_key = RSA.import_key(private_key_pem)
            cipher_rsa = PKCS1_OAEP.new(private_key)
            decrypted_message = cipher_rsa.decrypt(base64.b64decode(encrypted_message))
            return decrypted_message.decode()
        except Exception as e:
            print(f"⚠ Error decrypting message: {str(e)}")
            return f"[Encrypted message: {encrypted_message}]"

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

                    private_key_pem = retrieve_private_key(self.username)
                    if not private_key_pem:
                        print("⚠ No private key found for decryption.")
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

    def listen_for_messages(self):
        """
        Continuously listens for incoming encrypted messages from the server.
        When a message is received, it is decrypted using the recipient's private RSA key.
        """
        """
         Retrieves and decrypts messages for the logged-in employee.
         """
        if not self.username:
            print("Please log in first.")
            return

        data = {"action": "fetch_unread_messages", "username": self.username}
        response = self.send_request(data)

        if response:
            if response.get("status") == "success" and "messages" in response:
                messages = response["messages"]
                if messages:
                    print("\n📩 Unread Messages:")

                    # 🔹 Retrieve the private key from Key_Management
                    private_key_pem = retrieve_private_key(self.username)
                    if not private_key_pem:
                        print("⚠ No private key found for decryption.")
                        return

                    private_key = rsa.PrivateKey.load_pkcs1(private_key_pem.encode())

                    for msg in messages:
                        try:
                            encrypted_message_bytes = bytes.fromhex(msg['message'])
                            decrypted_message = rsa.decrypt(encrypted_message_bytes, private_key).decode()
                            print(f"📨 From {msg['sender']}: {decrypted_message}")
                        except Exception as e:
                            print(f"❌ Error decrypting message from {msg['sender']}: {str(e)}")
                else:
                    print("✅ No new messages.")
            else:
                print("⚠ Server response error:", response.get("message"))
        else:
            print("⚠ No response from server.")

    # -------------------------------
    # Main function
    # -------------------------------

    def run(self):
        """
        Runs the employee panel only if the user has successfully logged in.
        Prevents unauthorized access.
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
                # After login, if the user is logged in, show the employee panel
                print(f"\n==== Employee Panel (Logged in as: {self.username}) ====")
                self.fetch_unread_messages()
                print("3 - View Customer Information")
                print("4 - Process Deposit")
                print("5 - Process Withdrawal")
                print("6 - Process Transfer")
                print("7 - Update Customer Information")
                print("8 - Monitor Transactions")
                print("9 - Send Message")
                print("0 - Logout")

                choice = input("Enter your choice: ")

                if choice == "3":
                    self.view_customer_info()
                elif choice == "4":
                    self.process_deposit()
                elif choice == "5":
                    self.process_withdrawal()
                elif choice == "6":
                    self.process_transfer()
                elif choice == "7":
                    self.update_info()
                elif choice == "8":
                    self.monitor_transactions()
                elif choice == "9":
                    self.send_message()
                elif choice == "0":
                    print("Logging out.")
                    self.username = None  # Reset username to None when logging out
                    break  # ✅ Ensures proper logout
                else:
                    print("Invalid option, please try again.")


if __name__ == "__main__":
    employee = BankEmployee(SERVER_HOST, SERVER_PORT, CERTFILE, KEYFILE, CA_CERT)
    try:
        employee.connect()
    except Exception as e:
        print("Failed to connect to server:", e)
        sys.exit(1)
    employee.run()
