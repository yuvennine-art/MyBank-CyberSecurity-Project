import ssl
import socket
import json
import sys
from base64 import b64encode, b64decode
from config import SERVER_HOST, SERVER_PORT, CERTFILE, KEYFILE, CA_CERT, SESSION_KEY, ADMIN_REG_CODE
from Crypto.Cipher import AES
from hashlib import sha256

# -------------------------------
# AES Encryption/Decryption Functions (AES-GCM)
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
# Admin Client Class
# -------------------------------
class Admin:
    def __init__(self, server_host, server_port, certfile, keyfile, ca_cert):
        self.server_host = server_host
        self.server_port = server_port
        self.certfile = certfile
        self.keyfile = keyfile
        self.ca_cert = ca_cert
        self.session_key = SESSION_KEY
        self.secure_sock = None
        self.username = None
        self.role = None  # Should be "admin" after login

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
    # Admin Registration (Requires ADMIN_REG_CODE)
    # -------------------------------
    def register(self):
        print("----- Admin Registration -----")
        username = input("Enter admin username: ")
        password = input("Enter login password: ")
        admin_password = input("Enter admin operation password: ")
        email = input("Enter email: ")
        phone = input("Enter phone number: ")
        reg_code = input("Enter admin registration code: ")

        if reg_code != ADMIN_REG_CODE:
            print(" Registration code incorrect. Registration failed!")
            return

        data = {
            "action": "create_account",
            "username": username,
            "password": password,
            "pay_password": admin_password,
            "email": email,
            "phone": phone,
            "role": "admin"
        }
        response = self.send_request(data)
        print("Registration response:", response)

    # -------------------------------
    # Admin Login with OTP (Two-Step Login)
    # -------------------------------
    def login(self):
        """
        Handles admin login with OTP verification and strict role validation.
        Ensures non-admin users cannot log into the admin panel.
        """
        print("----- Admin Login -----")
        username = input("Enter admin username: ")
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

                # ✅ Enforce Role-Based Login (Block non-admin users)
                if role != "admin":
                    print("❌ Access denied: Only admins can log in here.")
                    return False  # Prevent further execution

                print(f"✅ Login successful! Welcome, {username}")
                self.username = username  # Set username after successful login
                self.role = role  # Store role for further validation
                return True  # Allow access

            else:
                print("❌ Login failed:", response.get("message"))
                return False  # Prevent further execution
        else:
            print("⚠ No response from server.")
            return False  # Prevent further execution

    # -------------------------------
    # Admin Password Verification
    # -------------------------------
    def get_admin_verification(self):
        return input("Re-enter admin password for verification: ")

        # -------------------------------
        # Fuction parts
        # -------------------------------

    def manage_user_roles(self):
        """
        Allows the admin to manage user roles (create, update, delete, view).
        - "create": Adds a new role with specific permissions.
        - "update": Modifies an existing role's permissions.
        - "delete": Removes a role from the system.
        - "view": Displays all existing roles.
        """
        admin_verification = input("Re-enter admin password for verification: ")
        op = input("Enter role management operation (create/update/delete/view): ")
        role_data = {}

        if op in ["create", "update", "delete"]:
            role_data["role_name"] = input("Enter role name: ")
        if op in ["create", "update"]:
            role_data["permissions"] = input("Enter permissions ((comma-separated, e.g., read,write,execute)): ")

        data = {
            "action": "manage_user_roles",
            "admin": self.username,
            "operation": op,
            "role_data": role_data,
            "requester_role": "admin",
            "admin_password_verification": admin_verification
        }

        response = self.send_request(data)

        # If "view" is selected, format and display roles properly
        if op == "view" and response.get("status") == "success":
            roles = response.get("roles", [])
            print("\n==== Existing Roles ====")
            for role in roles:
                print(f"ID: {role['role_id']} | Name: {role['role_name']} | Permissions: {role['permissions']}")
        else:
            print("Manage User Roles response:", response)

    def manage_keys(self):
        """
        Allows admin to manage cryptographic keys (generate, rotate, revoke, view).
        """
        admin_verification = input("Re-enter admin password for verification: ")
        operation = input("Enter key management operation (generate/rotate/revoke/view): ")
        key_details = {}

        if operation in ["generate", "rotate"]:
            key_details["key_type"] = input("Enter key type (AES, RSA, etc.): ")
            key_details["key_usage"] = input("Enter key usage (general, session, encryption): ")
            if operation == "rotate":
                key_details["key_id"] = input("Enter key ID to rotate: ")
        elif operation == "revoke":
            key_details["key_id"] = input("Enter key ID to revoke: ")

        data = {
            "action": "manage_keys",
            "admin": self.username,
            "operation": operation,
            "key_details": key_details,
            "requester_role": "admin",
            "admin_password_verification": admin_verification
        }

        response = self.send_request(data)
        print("Manage Keys response:", response)


    def system_maintenance(self):
        """
        Allows admin to perform system maintenance tasks.
        - "update": Performs a system update (e.g., updating software packages).
        - "patch": Applies security patches to the system.
        - "backup": Creates a backup of the system database.
        """
        admin_verification = input("Re-enter admin password for verification: ")
        op = input("Enter system maintenance operation (update/patch/backup): ")
        maintenance_details = {}

        if op == "update":
            maintenance_details["update_info"] = input("Enter update description: ")
        elif op == "backup":
            maintenance_details["backup_location"] = input("Enter backup location (default: server backup directory): ")

        data = {
            "action": "system_maintenance",
            "admin": self.username,
            "operation": op,
            "maintenance_details": maintenance_details,
            "requester_role": "admin",
            "admin_password_verification": admin_verification
        }

        response = self.send_request(data)
        print("System Maintenance response:", response)

    def monitor_security(self):
        """
        Retrieves security logs from the server and displays them in a structured format.
        - The logs include firewall events, intrusion attempts, and failed login attempts.
        """
        data = {
            "action": "monitor_security",
            "admin": self.username,
            "requester_role": "admin"
        }
        response = self.send_request(data)

        if response.get("status") == "success" and "security_logs" in response:
            logs = response["security_logs"]
            print("\n==== Security Logs ====")
            for log in logs:
                print(f"ID: {log['log_id']} | User ID: {log['user_id']} | Action: {log['action']}")
                print(f"Details: {log['details']}")
                print(f"Timestamp: {log['timestamp']}\n")
        else:
            print("Failed to retrieve security logs.")

    # -------------------------------
    # Main Interactive Menu
    # -------------------------------
    def run(self):
        while True:
            if self.username is None:
                print("\n==== Admin Client ====")
                print("1 - Register")
                print("2 - Login")
                print("9 - Exit")
                choice = input("Enter your choice: ")
                if choice == "1":
                    self.register()
                elif choice == "2":
                    self.login()
                elif choice == "9":
                    print("Exiting.")
                    break
                else:
                    print("Invalid option, please try again.")
            else:
                print(f"\n==== Admin Panel (Logged in as: {self.username}) ====")
                print("3 - Manage User Roles")
                print("4 - Monitor Security")
                print("5 - Manage Keys")
                print("6 - System Maintenance")
#               print("7 - Send Message")
                print("8 - Logout")
                choice = input("Enter your choice: ")

                # FIX: Add function calls for menu options
                if choice == "3":
                    self.manage_user_roles()  # Handles user role management
                elif choice == "4":
                    self.monitor_security()  # Monitors system security
                elif choice == "5":
                    self.manage_keys()  # Handles key management
                elif choice == "6":
                    self.system_maintenance()  # Handles system maintenance

#                elif choice == "7":
#                    self.send_message()  # Sends messages
                elif choice == "8":
                    print("Logging out.")
                    self.username = None  # Logs out the admin user
                else:
                    print("Invalid option, please try again.")

        self.disconnect()  # Ensures connection is closed when exiting



if __name__ == "__main__":
    admin = Admin(SERVER_HOST, SERVER_PORT, CERTFILE, KEYFILE, CA_CERT)
    try:
        admin.connect()
    except Exception as e:
        print(" Failed to connect to server:", e)
        sys.exit(1)
    admin.run()
