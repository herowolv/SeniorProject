import sqlite3


class DatabaseManager:
    def __init__(self, db_name="usb_whitelisting.db"):
        """Initialize the database manager and create tables."""
        self.db_name = db_name
        self.create_tables()

    def create_tables(self):
        """Create the required tables for admins, USB devices, and activity logs."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()

            # Admins table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS admins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    admin_name TEXT NOT NULL,
                    admin_password TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL
                )
            """)

            # USB Devices table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS usb_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_name TEXT NOT NULL,
                    device_id TEXT UNIQUE NOT NULL
                )
            """)

            # Activity Log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS activity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL
                )
            """)

            conn.commit()
            
    def get_admins(self):
        """Retrieve all admins."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM admins")
            return cursor.fetchall()


if __name__ == "__main__":
    # Create the database and tables
    # Initialize the database manager
    db_manager = DatabaseManager()

    # Retrieve and display all admins
    admins = db_manager.get_admins()
    print("Admins in the database:", admins)


# no attribute (add device)
