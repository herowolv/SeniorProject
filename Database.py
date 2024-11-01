import sqlite3

class DatabaseManager:
    def __init__(self, db_name="usb_devices.db"):
        self.db_name = db_name
        self.create_table()

    def create_table(self):
        """Create the USB devices table if it doesn't exist."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS usb_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_name TEXT,
                    device_id TEXT UNIQUE
                )
            """)
            conn.commit()

    def add_device(self, device_name, device_id):
        """Add a new USB device."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO usb_devices (device_name, device_id) VALUES (?, ?)", (device_name, device_id))
            conn.commit()

    def remove_device(self, device_id):
        """Remove a USB device by device_id."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM usb_devices WHERE device_id = ?", (device_id,))
            conn.commit()

    def update_device(self, device_id, new_name):
        """Update the device name of a USB device."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE usb_devices SET device_name = ? WHERE device_id = ?", (new_name, device_id))
            conn.commit()
# view the database
    def view_data(db_name="usb_devices.db"):
        with sqlite3.connect(db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM usb_devices")
            rows = cursor.fetchall()
            for row in rows:
                print(row)

    view_data()
