import sqlite3

class DatabaseManager:
    def __init__(self, db_name="usb_devices.db"):
        self.db_name = db_name
        self.create_table()

    def create_table(self):
        """Create the USB devices table if it doesn't exist."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            # Update the table creation to include the group_name column
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS usb_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_name TEXT,
                    device_id TEXT UNIQUE,
                    group_name TEXT  # New column for grouping
                )
            """)
            conn.commit()

    def add_device(self, device_name, device_id, group_name):
        """Add a new USB device with a group name."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO usb_devices (device_name, device_id, group_name) VALUES (?, ?, ?)",
                           (device_name, device_id, group_name))
            conn.commit()

    def remove_device(self, device_id):
        """Remove a USB device by device_id."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM usb_devices WHERE device_id = ?", (device_id,))
            conn.commit()

    def update_device(self, device_id, new_name, new_group):
        """Update the device name and group of a USB device."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE usb_devices SET device_name = ?, group_name = ? WHERE device_id = ?",
                           (new_name, new_group, device_id))
            conn.commit()

    def get_all_devices(self):
        """Get all devices from the database."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT device_name, device_id, group_name FROM usb_devices")
            rows = cursor.fetchall()
            return rows

    def view_data(self):
        """View all data in the database."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM usb_devices")
            rows = cursor.fetchall()
            for row in rows:
                print(row)
