import sqlite3
import os
import logging
import json
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Define the database file path
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mybank.db")

# SQL statements for table creation
create_statements = [
    # Table creation statements as you already have...
]


def column_exists(cursor, table_name, column_name):
    """Checks if a column exists in a given table."""
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [row[1] for row in cursor.fetchall()]
    return column_name in columns


def update_existing_database():
    """Ensures that the database schema is updated without data loss."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON;")
        logging.info("Foreign key support enabled.")

        alter_statements = [
            "ALTER TABLE Users ADD COLUMN public_key TEXT DEFAULT '';" if not column_exists(cursor, "Users",
                                                                                            "public_key") else None,
            "ALTER TABLE Accounts ADD COLUMN encrypted_data TEXT;" if not column_exists(cursor, "Accounts",
                                                                                        "encrypted_data") else None,
            "ALTER TABLE Transactions ADD COLUMN encrypted_details TEXT;" if not column_exists(cursor, "Transactions",
                                                                                               "encrypted_details") else None
        ]

        for sql in filter(None, alter_statements):
            cursor.execute(sql)
            logging.info(f"Updated table with: {sql}")

        conn.commit()
        conn.close()
        logging.info("Database schema update completed successfully.")
    except Exception as e:
        logging.error(f"Database update failed: {str(e)}")


def add_missing_permissions():
    """Ensures that all predefined roles have the necessary permissions."""
    predefined_permissions = {
        "client": [
            "read", "execute", "transfer_funds", "withdraw_funds", "deposit_funds",
            "apply_for_loan", "view_transactions", "send_message", "view_own_account", "create_account"
        ],
        "employee": [
            "read", "write", "manage_transactions", "approve_loans", "deposit_funds",
            "withdraw_funds", "view_transactions", "view_logs", "view_all_accounts",
            "manage_accounts", "create_account", "view_customer_info"
        ],
        "admin": [
            "read", "write", "delete", "manage_roles", "view_logs",
            "backup_system", "update_system", "approve_payments", "create_user",
            "delete_user", "view_all_accounts", "manage_accounts", "create_account"
        ],
        "auditor": [
            "read", "view_logs", "view_transactions"
        ]
    }

    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        for role, permissions in predefined_permissions.items():
            cursor.execute("SELECT permissions FROM Roles WHERE role_name = ?", (role,))
            row = cursor.fetchone()

            # Check if the role already exists
            if row:
                # Role exists, update permissions
                existing_permissions = json.loads(row[0]) if isinstance(row[0], str) else []
                if not isinstance(existing_permissions, list):
                    existing_permissions = []

                # Add missing permissions
                for perm in permissions:
                    if perm not in existing_permissions:
                        existing_permissions.append(perm)

                cursor.execute("UPDATE Roles SET permissions = ? WHERE role_name = ?",
                               (json.dumps(existing_permissions), role))
                logging.info(f"Updated permissions for role: {role}")
            else:
                # Role doesn't exist, insert it
                cursor.execute("INSERT INTO Roles (role_name, permissions) VALUES (?, ?)",
                               (role, json.dumps(permissions)))
                logging.info(f"Inserted new role: {role}")

        conn.commit()
        conn.close()
        logging.info("Updated Roles table with missing permissions.")
    except Exception as e:
        logging.error(f"Failed to update permissions: {str(e)}")


def init_database():
    """Creates or updates the database schema."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON;")
        logging.info("Foreign key support enabled.")

        for sql in create_statements:
            cursor.executescript(sql)
            logging.info(f"Executed: {sql.strip().split('(')[0]}")

        conn.commit()
        conn.close()

        update_existing_database()
        add_missing_permissions()

        logging.info("Database initialization completed.")
    except Exception as e:
        logging.error("Database initialization failed: %s", str(e))


if __name__ == "__main__":
    init_database()
