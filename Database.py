import sqlite3
import bcrypt

class DatabaseManager:
    # Function: __init__ - Initializes the database and ensures tables are created
    def __init__(self, db_name="usb_whitelisting.db"):
        """
        Initialize the DatabaseManager with a database name.
        Creates the necessary tables if they don't already exist.
        """
        self.db_name = db_name
        self.create_tables()

    # Function: create_connection - Establishes a connection to the SQLite database
    def create_connection(self):
        """
        Create and return a new SQLite database connection.
        """
        return sqlite3.connect(self.db_name)

    # Function: create_tables - Creates necessary database tables if they do not exist
    def create_tables(self):
        """Create the required tables in the database."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()

            # Creates the 'admins' table to store admin details
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS admins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    admin_name TEXT NOT NULL,
                    admin_password TEXT NOT NULL,  -- Store hashed passwords
                    email TEXT UNIQUE NOT NULL
                )
            """)

            conn.commit()

    # Function: hash_password - Hashes a plaintext password for secure storage
    def hash_password(self, plain_password):
        """Hash a plain-text password."""
        return bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt())

    # Function: verify_password - Verifies a plaintext password against its hashed version
    def verify_password(self, plain_password, hashed_password):
        """Verify if a plain-text password matches the hashed password."""
        if isinstance(hashed_password, str):
            hashed_password = hashed_password.encode('utf-8')
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

    # Function: rehash_admin_passwords - Updates admin passwords to bcrypt hash format if needed
    def rehash_admin_passwords(self):
        """Rehash plain text passwords in the database to bcrypt format."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, admin_password FROM admins")
            admins = cursor.fetchall()

            for admin_id, plain_password in admins:
                if not plain_password.startswith("$2b$"):
                    hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt())
                    cursor.execute(
                        "UPDATE admins SET admin_password = ? WHERE id = ?",
                        (hashed_password.decode('utf-8'), admin_id)
                    )
            conn.commit()

    # Function: get_admins - Retrieves all admin records from the database
    def get_admins(self):
        """Retrieve all admin records."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, admin_name, email FROM admins")
            return cursor.fetchall()

    # Function: get_admin - Retrieves a specific admin's hashed password by their username
    def get_admin(self, username):
        """Retrieve a single admin record by username."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT admin_password FROM admins WHERE admin_name = ?", (username,))
            return cursor.fetchone()  # Returns None if not found

    # Function: add_admin - Adds a new admin to the database
    def add_admin(self, admin_name, admin_password, admin_email):
        """Add a new admin to the database. Hashes the password before storing it."""
        with self.create_connection() as conn:
            cursor = conn.cursor()
            hashed_password = self.hash_password(admin_password).decode('utf-8')  # Hash the password
            cursor.execute("""
                INSERT INTO admins (admin_name, admin_password, email)
                VALUES (?, ?, ?)
            """, (admin_name, hashed_password, admin_email))
            conn.commit()

    # Function: add_device - Adds a USB device to the whitelist
    def add_device(self, device_name, device_id, vid, pid):
        """
        Add a new USB device to the whitelist.
        Logs the action to the activity log.
        """
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO usb_devices (device_name, device_id, vid, pid)
                VALUES (?, ?, ?, ?)
            """, (device_name, device_id, vid, pid))
            conn.commit()
            self.log_action(f"Added device: {device_name} ({device_id})")

    # Function: remove_device - Removes a USB device from the whitelist
    def remove_device(self, device_id):
        """
        Remove a USB device from the whitelist.
        Logs the action to the activity log.
        """
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM usb_devices WHERE device_id = ?", (device_id,))
            conn.commit()
            self.log_action(f"Removed device with ID: {device_id}")

    # Function: update_device - Updates the name of a USB device in the whitelist
    def update_device(self, device_id, new_name):
        """
        Update the name of a USB device in the whitelist.
        Logs the action to the activity log.
        """
        with self.create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE usb_devices
                SET device_name = ?
                WHERE device_id = ?
            """, (new_name, device_id))
            conn.commit()
            self.log_action(f"Updated device '{device_id}' to '{new_name}'")

    # Function: get_all_devices - Retrieves all USB devices from the whitelist
    def get_all_devices(self):
        """
        Retrieve all USB devices from the whitelist.
        Returns a list of dictionaries with device details.
        """
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT device_name, device_id, vid, pid FROM usb_devices")
            return [dict(zip(["device_name", "device_id", "vid", "pid"], row)) for row in cursor.fetchall()]

    # Function: get_whitelist_devices - Retrieves all whitelisted devices
    def get_whitelist_devices(self):
        """
        Retrieve all whitelisted devices.
        Returns a list of dictionaries with device details.
        """
        with self.create_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT device_name, device_id, vid, pid FROM usb_devices
            """)
            return [dict(zip(["device_name", "device_id", "vid", "pid"], row)) for row in cursor.fetchall()]

    # Function: log_action - Logs an action into the activity log table
    def log_action(self, action):
        """
        Log an action in the activity log.
        """
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO activity_log (timestamp, action)
                VALUES (datetime('now'), ?)
            """, (action,))
            conn.commit()

    # Function: get_logs - Retrieves all entries from the activity log
    def get_logs(self):
        """
        Retrieve all entries from the activity log.
        Returns a list of tuples containing timestamps and actions.
        """
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp, action FROM activity_log")
            return cursor.fetchall()
