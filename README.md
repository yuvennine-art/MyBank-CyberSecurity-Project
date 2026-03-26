# MyBank Cyber Security Project
Module: Managing Cyber Risk, Audit and Compliance (WM9C4-15)
Student ID: 5663262
Submission Date: 09th December 2024

## 项目简介
本项目为基于Python的网络银行安全系统，实现了**AES-GCM加密、RSA密钥交换、HKDF密钥派生、RBAC权限控制、MFA双因素认证**等核心安全功能，保障金融交易的机密性、完整性和不可否认性，同时通过STRIDE模型完成威胁分析和安全测试。

## 核心技术
- 对称加密：AES-256-GCM（数据加密+完整性验证）
- 非对称加密：RSA-2048（密钥交换/安全通信）
- 密钥派生：HKDF-SHA256（用户/字段专属密钥）
- 认证/权限：MFA(OTP)、RBAC角色控制
- 通信安全：TLS 1.3、端到端加密
- 数据完整性：HMAC-SHA256、数字签名
- 数据库：SQLite（结构化schema，加密存储敏感字段）

## 项目结构



/SecureBankingSystem
│── README.md          # Project documentation
│── server.py          # Secure banking server
│── client.py          # Client application
│── employee.py        # Bank employee application
│── admin.py           # Administrator application
│── database.py        # Database initialization and management
│── config.py          # System configuration file
│── certs/             # SSL/TLS certificates
│── Test_communication.py
- **Logs are stored in `server.log`**.
- **OTP codes are generated upon first login and stored in OTP files** (`otp_client_1.txt`, `otp_employee_1.txt`, `otp_admin_1.txt`).
- **Do not delete OTP files** as OTP generation will be delayed.

---

---

## 📌 Python File Descriptions

### **1. Test_communication.py**
- **Purpose**: Simulates secure messaging between `client1` and `employee1`.
- **Key Functions**:
  - `get_keys(username)`: Fetches public and private keys from `mybank.db`.
  - `encrypt_with_public_key(message, public_key_pem)`: Encrypts a message using an RSA public key.
  - `decrypt_with_private_key(encrypted_message, private_key_pem)`: Decrypts an RSA-encrypted message.
  - **User Interaction**:
    - `client1` sends an encrypted message.
    - `employee1` decrypts and replies securely.

### **2. generate_keys.py**
- **Purpose**: Generates RSA key pairs and stores them in the database.
- **Key Functions**:
  - `generate_and_store_keys(username)`: Creates and stores RSA public-private key pairs.
  - **Usage**:
    ```sh
    python generate_keys.py
    ```
    - Ensures `client1` and `employee1` have unique key pairs stored in `mybank.db`.

### **3. key_management.py**
- **Purpose**: Manages secure storage and retrieval of RSA private keys.
- **Key Functions**:
  - `store_private_key(username, encrypted_private_key)`: Encrypts and stores private keys.
  - `retrieve_private_key(username)`: Retrieves and decrypts a user’s private key.

### **4. client.py**
- **Purpose**: Handles `client1` authentication, transactions, and secure messaging.
- **Key Functions**:
  - `send_request(data)`: Sends encrypted messages to the server.
  - `get_account_info()`: Fetches account details securely.
  - `transfer_funds()`: Processes secure transactions.
  - `fetch_unread_messages()`: Retrieves and decrypts messages.

### **5. employee.py**
- **Purpose**: Allows `employee1` to manage client transactions and view customer information securely.
- **Key Functions**:
  - `view_customer_info()`: Decrypts and retrieves customer details.
  - `monitor_transactions()`: Logs and audits financial transactions.
  - `send_message()`: Encrypts and sends messages securely.

### **6. server.py**
- **Purpose**: Handles all encrypted communications between `client1`, `employee1`, and the database.
- **Key Functions**:
  - `handle_client(connection, address)`: Manages incoming secure connections.
  - `encrypt_payload(data, session_key)`: Encrypts communication using AES-GCM.
  - `decrypt_payload(encrypted_json, session_key)`: Decrypts incoming messages.
  - `send_message(request, client_ip)`: Stores and transmits encrypted messages.

### **7. config.py**
- **Purpose**: Stores essential configuration settings.
- **Contains**:
  - `SERVER_HOST`, `SERVER_PORT`: Defines server network settings.
  - `DATABASE_PATH`: Path to `mybank.db`.
  - `SESSION_KEY`: Shared encryption key for AES-GCM.
  - `MASTER_KEY`: Key used to encrypt and store sensitive data.

---

## 📌 Setup & Usage

### **Step 1: Install Dependencies**
Ensure Python and required libraries are installed:
```sh
pip install rsa sqlite3

## User Guide

### Client

#### Run the Client Application

#### Register a New Client Account
1. Select `1 - Register New Account`
2. Enter:
   - Username
   - Login Password
   - Email
   - Phone Number
   - Payment Password
3. If registration is successful, the system will confirm account creation.

#### Login as Client
1. Select `2 - User Login`
2. Enter:
   - Username
   - Password
   - **Leave OTP blank and press Enter on first login**
3. OTP will be generated and saved in `otp_client_1.txt`.
4. Re-run the login and enter the **OTP from the file**.
5. Login will be successful upon OTP validation.

#### Client Functions
- `3 - Get Account Information` – View balance, transactions, and loan status.
- `4 - Transfer Funds` – Secure money transfer (requires payment password).
- `5 - Pay Bill` – Make payments (requires authentication).
- `6 - Update Personal Information` – Modify contact details.
- `7 - Apply for Loan` – Submit a loan request.
- `8 - Send Message` – Securely communicate with bank representatives.

---

### Bank Employee

#### Run the Employee Application

#### Register a New Employee
1. Select `1 - Register`
2. Enter:
   - Employee Username
   - Login Password
   - Employee Payment Password
   - Email
   - Phone Number
   - **Employee Registration Code** (predefined in `config.py`)
3. Registration will be confirmed.

#### Login as Employee
1. Select `2 - Login`
2. Enter:
   - Username
   - Password
   - **Leave OTP blank and press Enter on first login**
3. OTP will be generated and saved in `otp_employee_1.txt`.
4. Re-run the login and enter the **OTP from the file**.
5. Login will be successful.

#### Employee Functions
- `3 - View Customer Information` – View customer details.
- `4 - Process Deposit` – Approve customer deposits.
- `5 - Process Withdrawal` – Handle withdrawal requests.
- `6 - Process Transfer` – Verify and approve fund transfers.
- `7 - Update Customer Information` – Modify customer details.
- `8 - Monitor Transactions` – Audit customer transactions.

---

### Administrator

#### Run the Admin Application

#### Register a New Admin
1. Select `1 - Register`
2. Enter:
   - Admin Username
   - Login Password
   - Admin Payment Password
   - Email
   - Phone Number
   - **Admin Registration Code** (predefined in `config.py`)
3. Registration will be confirmed.

#### Login as Admin
1. Select `2 - Login`
2. Enter:
   - Username
   - Password
   - **Leave OTP blank and press Enter on first login**
3. OTP will be generated and saved in `otp_admin_1.txt`.
4. Re-run the login and enter the **OTP from the file**.
5. Login will be successful.

#### Admin Functions
- `3 - Manage User Roles` – Create, modify, delete user roles.
- `4 - Monitor Security` – View logs of failed logins, intrusion attempts.
- `5 - Manage Keys` – Generate, rotate, and revoke security keys.
- `6 - System Maintenance` – Apply updates, patches, and backups.

---

## Testing and Evaluation
To verify system functionality, execute the following tests:

### Functional Tests
- **Register a client** – Run `client.py` and create an account.
- **Login as a client** – Use `client.py`, leave OTP blank, then enter OTP from file.
- **Transfer funds** – Select `4 - Transfer Funds`, input valid account details.
- **Pay a bill** – Select `5 - Pay Bill`, authenticate with payment password.
- **Apply for a loan** – Select `7 - Apply for Loan`, input loan details.

### Security Tests
- **AES-256 Encryption** – Verify encrypted database storage.
- **RSA Authentication** – Attempt to send encrypted messages.
- **OTP Verification** – Check `otp_client_1.txt` and ensure OTP changes per login.
- **SSL/TLS Secure Communication** – Use network monitoring tools to verify encrypted traffic.

### Performance Tests
- **Multiple login attempts with incorrect password** – Account remains locked after 3 failures.
- **High-volume transactions** – System maintains transaction integrity.

---

## Troubleshooting
- **OTP file missing** – Check `server.log` for OTP or restart login.
- **SSL/TLS error** – Ensure correct certificate paths in `config.py`.
- **Database not initializing** – Run `database.py` to reset the database.

---

## Logs and Security Monitoring
- **Logs are stored in `server.log`**.
- **Audit logs track transactions and security events**.
- **Admins can monitor logs for intrusion attempts**.

---

## Best Practices
1. **Do not delete OTP files (`otp_client_1.txt`, `otp_employee_1.txt`, `otp_admin_1.txt`)**.
2. **Use strong passwords and enable MFA for added security**.
3. **Ensure SSL/TLS certificates are correctly configured**.
4. **Regularly rotate encryption keys using the admin interface**.

---

## License
