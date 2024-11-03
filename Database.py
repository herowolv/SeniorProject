import sqlite3

class DatabaseManager:
    def __init__(self, db_name):
        self.db_name = db_name
        self.create_tables()  # Ensure both tables are created when initialized

    def connect(self):
        """Connect to the SQLite database."""
        return sqlite3.connect(self.db_name)

    def create_tables(self):
        """Create tables for USB devices, groups, and activity logs if they don't exist."""
        conn = self.connect()
        cursor = conn.cursor()
        
        # USB devices table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS usb_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_name TEXT NOT NULL,
            device_id TEXT NOT NULL,
            group_name TEXT,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        # Activity logs table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        conn.commit()
        conn.close()

    def log_action(self, action):
        """Log actions in the activity_logs table."""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO activity_logs (action) VALUES (?)
        ''', (action,))
        conn.commit()
        conn.close()

    def add_device(self, device_name, device_id, group_name=None):
        """Add a new USB device to the database."""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO usb_devices (device_name, device_id, group_name) VALUES (?, ?, ?)
        ''', (device_name, device_id, group_name))
        conn.commit()
        conn.close()
        self.log_action(f"Added USB device: {device_name} (ID: {device_id}) in group: {group_name}")

    def get_all_devices(self):
        """Retrieve all USB devices from the database."""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM usb_devices')
        devices = cursor.fetchall()
        conn.close()
        return devices

    def get_device_by_id(self, device_id):
        """Retrieve a specific USB device by device ID."""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM usb_devices WHERE device_id = ?', (device_id,))
        device = cursor.fetchone()
        conn.close()
        return device

    def update_device_name(self, device_id, new_name):
        """Update the name of a USB device."""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute('UPDATE usb_devices SET device_name = ? WHERE device_id = ?', (new_name, device_id))
        conn.commit()
        conn.close()
        self.log_action(f"Updated USB device ID {device_id} to new name: {new_name}")

    def update_device_group(self, device_id, new_group):
        """Update the group of a USB device."""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute('UPDATE usb_devices SET group_name = ? WHERE device_id = ?', (new_group, device_id))
        conn.commit()
        conn.close()
        self.log_action(f"Updated USB device ID {device_id} to new group: {new_group}")

    def delete_device(self, device_id):
        """Delete a USB device from the database."""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM usb_devices WHERE device_id = ?', (device_id,))
        conn.commit()
        conn.close()
        self.log_action(f"Deleted USB device with ID: {device_id}")

    def get_all_logs(self):
        """Retrieve all logs from the activity_logs table."""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM activity_logs')
        logs = cursor.fetchall()
        conn.close()
        return logs
