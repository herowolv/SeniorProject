import sys
import re
import threading
import time
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox, QWidget, QTabWidget, QTableWidget, QTableWidgetItem, QSplitter, QFrame
)
from PySide6.QtCore import Signal, Qt
from Database import DatabaseManager
import win32com.client  # For USB monitoring


class UserInterface(QMainWindow):
    usb_list_updated = Signal(list)  # Signal to update USB Devices table in real-time

    # Function: __init__ - Initialize the main GUI interface and set its properties
    def __init__(self, db_manager):
        """
        Initialize the UserInterface class with the provided DatabaseManager.
        Sets up the GUI structure, including the login and main application UI.
        """
        super().__init__()
        self.db_manager = db_manager
        self.setWindowTitle("USB Whitelist Manager")
        self.setGeometry(300, 300, 1200, 700)  # Set window size
        self.running = True  # Flag to manage the USB monitoring thread
        self.is_authenticated = False  # Tracks authentication status
        self.init_ui()  # Initializes the UI

    # Function: init_ui - Decides whether to show login or main UI based on authentication
    def init_ui(self):
        """
        Initialize the user interface by displaying either the login screen
        or the main application interface based on authentication status.
        """
        if not self.is_authenticated:
            self.show_login()
        else:
            self.show_main_ui()

    # Function: show_login - Displays the login page layout
    def show_login(self):
        """
        Set up and display the login page where users can enter their credentials.
        """
        self.login_widget = QWidget()
        layout = QVBoxLayout()

        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Title Label
        title_label = QLabel("Login to USB Whitelist Manager")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(title_label, alignment=Qt.AlignCenter)

        # Username Input
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter Username")
        self.username_input.setStyleSheet("padding: 8px; font-size: 14px;")
        layout.addWidget(self.username_input)

        # Password Input
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter Password")
        self.password_input.setEchoMode(QLineEdit.Password)  # Hide password input
        self.password_input.setStyleSheet("padding: 8px; font-size: 14px;")
        layout.addWidget(self.password_input)

        # Login Button
        login_button = QPushButton("Login")
        login_button.setObjectName("loginButton")
        login_button.clicked.connect(self.authenticate)
        layout.addWidget(login_button)

        self.login_widget.setLayout(layout)
        self.setCentralWidget(self.login_widget)

    # Function: authenticate - Handles user login authentication
    def authenticate(self):
        """
        Authenticate the user by verifying the provided username and password.
        Switch to the main UI upon successful authentication.
        """
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        admin_record = self.db_manager.get_admin(username)
        if not admin_record:
            QMessageBox.warning(self, "Login Failed", "Incorrect username or password.")
            return

        stored_hashed_password = admin_record[0]  # Extract hashed password from database
        if self.db_manager.verify_password(password, stored_hashed_password):
            QMessageBox.information(self, "Login Successful", "Welcome!")
            self.is_authenticated = True
            self.show_main_ui()
        else:
            QMessageBox.warning(self, "Login Failed", "Incorrect username or password.")

    # Function: show_main_ui - Displays the main application interface
    def show_main_ui(self):
        """
        Set up and display the main application UI with tabs for managing devices,
        viewing logs, and managing admins.
        """
        self.tabs = QTabWidget()
        self.tabs.setObjectName("mainTabs")

        # Tab 1: Manage Devices
        self.manage_tab = QWidget()
        self.init_manage_tab()
        self.tabs.addTab(self.manage_tab, "Manage Devices")

        # Tab 2: Activity Log
        log_tab = QWidget()
        log_layout = QVBoxLayout()
        self.log_table = QTableWidget(0, 2)
        self.log_table.setHorizontalHeaderLabels(["Timestamp", "Action"])
        log_layout.addWidget(QLabel("Activity Log:"))
        log_layout.addWidget(self.log_table)
        log_tab.setLayout(log_layout)
        self.tabs.addTab(log_tab, "Activity Log")

        # Tab 3: Manage Admins
        self.add_manage_admins_tab()

        self.setCentralWidget(self.tabs)

        # Start USB monitoring in a separate thread
        self.start_usb_monitoring()

        # Populate initial data
        self.refresh_log_table()
        self.refresh_whitelist_table()
        self.usb_list_updated.connect(self.update_usb_list_from_thread)

    # Function: init_manage_tab - Initializes the Manage Devices tab
    def init_manage_tab(self):
        """
        Set up the layout and widgets for the Manage Devices tab,
        including inputs for device details and tables for device lists.
        """
        main_layout = QSplitter(Qt.Horizontal)

        # Left Section: Inputs and Buttons
        left_frame = QFrame()
        left_layout = QVBoxLayout()
        left_frame.setLayout(left_layout)

        self.device_name_input = QLineEdit()
        self.device_name_input.setPlaceholderText("Device Name")
        left_layout.addWidget(QLabel("Device Name:"))
        left_layout.addWidget(self.device_name_input)

        self.device_id_input = QLineEdit()
        self.device_id_input.setPlaceholderText("Device ID")
        left_layout.addWidget(QLabel("Device ID:"))
        left_layout.addWidget(self.device_id_input)

        add_button = QPushButton("Add Device")
        add_button.setObjectName("addButton")
        add_button.clicked.connect(self.add_device)
        left_layout.addWidget(add_button)

        remove_button = QPushButton("Remove Device")
        remove_button.setObjectName("removeButton")
        remove_button.clicked.connect(self.remove_device)
        left_layout.addWidget(remove_button)

        update_button = QPushButton("Update Device")
        update_button.setObjectName("updateButton")
        update_button.clicked.connect(self.update_device)
        left_layout.addWidget(update_button)

        # Right Section: Tables for Whitelisted and Detected Devices
        right_frame = QFrame()
        right_layout = QVBoxLayout()
        right_frame.setLayout(right_layout)

        self.whitelist_table = QTableWidget(0, 4)
        self.whitelist_table.setHorizontalHeaderLabels(["Device Name", "Device ID", "VID", "PID"])
        right_layout.addWidget(QLabel("Whitelisted Devices:"))
        right_layout.addWidget(self.whitelist_table)

        self.usb_table = QTableWidget(0, 4)
        self.usb_table.setHorizontalHeaderLabels(["Description", "VID", "PID", "Serial Number"])
        right_layout.addWidget(QLabel("Detected USB Devices:"))
        right_layout.addWidget(self.usb_table)

        main_layout.addWidget(left_frame)
        main_layout.addWidget(right_frame)

        self.manage_tab.setLayout(QVBoxLayout())
        self.manage_tab.layout().addWidget(main_layout)


        # Function: add_manage_admins_tab - Adds the "Manage Admins" tab to the interface
    def add_manage_admins_tab(self):
        """
        Add a new tab for managing admin accounts. 
        Includes inputs for admin details and a table for displaying existing admins.
        """
        admin_tab = QWidget()
        admin_layout = QVBoxLayout()

        # Admin Name Input
        self.admin_name_input = QLineEdit()
        self.admin_name_input.setPlaceholderText("Admin Name")
        admin_layout.addWidget(QLabel("Admin Name:"))
        admin_layout.addWidget(self.admin_name_input)

        # Admin Password Input
        self.admin_password_input = QLineEdit()
        self.admin_password_input.setPlaceholderText("Admin Password")
        self.admin_password_input.setEchoMode(QLineEdit.Password)  # Hide password input
        admin_layout.addWidget(QLabel("Admin Password:"))
        admin_layout.addWidget(self.admin_password_input)

        # Admin Email Input
        self.admin_email_input = QLineEdit()
        self.admin_email_input.setPlaceholderText("Admin Email")
        admin_layout.addWidget(QLabel("Admin Email:"))
        admin_layout.addWidget(self.admin_email_input)

        # Add Admin Button
        add_admin_button = QPushButton("Add Admin")
        add_admin_button.clicked.connect(self.add_admin)
        admin_layout.addWidget(add_admin_button)

        # Admins Table
        self.admins_table = QTableWidget(0, 3)
        self.admins_table.setHorizontalHeaderLabels(["ID", "Admin Name", "Email"])
        admin_layout.addWidget(QLabel("Admins List:"))
        admin_layout.addWidget(self.admins_table)

        # Remove Admin Button
        remove_admin_button = QPushButton("Remove Selected Admin")
        remove_admin_button.clicked.connect(self.remove_admin)
        admin_layout.addWidget(remove_admin_button)

        admin_tab.setLayout(admin_layout)
        self.tabs.addTab(admin_tab, "Manage Admins")

        # Populate the table with current admin data
        self.refresh_admins_table()

    # Function: refresh_admins_table - Updates the Admins table with current database records
    def refresh_admins_table(self):
        """
        Refresh the admins table with data from the database.
        Clears the current table and repopulates it with admin records.
        """
        self.admins_table.setRowCount(0)
        admins = self.db_manager.get_admins()
        for admin in admins:
            row_position = self.admins_table.rowCount()
            self.admins_table.insertRow(row_position)
            self.admins_table.setItem(row_position, 0, QTableWidgetItem(str(admin[0])))  # ID
            self.admins_table.setItem(row_position, 1, QTableWidgetItem(admin[1]))  # Admin Name
            self.admins_table.setItem(row_position, 2, QTableWidgetItem(admin[2]))  # Email

    # Function: add_admin - Handles adding a new admin to the database
    def add_admin(self):
        """
        Add a new admin to the database using the input fields.
        Displays a success or error message depending on the outcome.
        """
        admin_name = self.admin_name_input.text().strip()
        admin_password = self.admin_password_input.text().strip()
        admin_email = self.admin_email_input.text().strip()

        # Validate inputs
        if not admin_name or not admin_password or not admin_email:
            QMessageBox.warning(self, "Input Error", "All fields are required.")
            return

        try:
            self.db_manager.add_admin(admin_name, admin_password, admin_email)
            QMessageBox.information(self, "Success", f"Admin '{admin_name}' added.")
            self.refresh_admins_table()
            self.refresh_log_table()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to add admin: {e}")

    # Function: remove_admin - Handles removing an admin from the database
    def remove_admin(self):
        """
        Remove the selected admin from the database.
        Displays a confirmation message upon success or an error message otherwise.
        """
        selected_row = self.admins_table.currentRow()
        if selected_row < 0:
            QMessageBox.warning(self, "Selection Error", "Please select an admin to remove.")
            return

        admin_id = self.admins_table.item(selected_row, 0).text()  # Get Admin ID
        try:
            with self.db_manager.create_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM admins WHERE id = ?", (admin_id,))
                conn.commit()
            QMessageBox.information(self, "Success", "Admin removed.")
            self.refresh_admins_table()
            self.refresh_log_table()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to remove admin: {e}")

    # Function: refresh_log_table - Updates the Activity Log table with database records
    def refresh_log_table(self):
        """
        Refresh the activity log table with recent log entries from the database.
        Clears the table and repopulates it with log data.
        """
        self.log_table.setRowCount(0)
        logs = self.db_manager.get_logs()
        for timestamp, action in logs:
            row_position = self.log_table.rowCount()
            self.log_table.insertRow(row_position)
            self.log_table.setItem(row_position, 0, QTableWidgetItem(timestamp))
            self.log_table.setItem(row_position, 1, QTableWidgetItem(action))

    # Function: refresh_whitelist_table - Updates the Whitelisted Devices table
    def refresh_whitelist_table(self):
        """
        Refresh the whitelist table with data from the database.
        Clears the table and repopulates it with device details.
        """
        self.whitelist_table.setRowCount(0)  # Clear the table
        devices = self.db_manager.get_whitelist_devices()
        for device in devices:
            row_position = self.whitelist_table.rowCount()
            self.whitelist_table.insertRow(row_position)
            self.whitelist_table.setItem(row_position, 0, QTableWidgetItem(device["device_name"]))
            self.whitelist_table.setItem(row_position, 1, QTableWidgetItem(device["device_id"]))
            self.whitelist_table.setItem(row_position, 2, QTableWidgetItem(device["vid"]))
            self.whitelist_table.setItem(row_position, 3, QTableWidgetItem(device["pid"]))

    # Function: add_device - Adds a new device to the whitelist
    def add_device(self):
        """
        Add a new USB device to the whitelist using the input fields.
        Displays a success or error message based on the operation result.
        """
        name = self.device_name_input.text().strip()
        device_id = self.device_id_input.text().strip()
        vid, pid = self.extract_vid_pid(device_id)

        try:
            self.db_manager.add_device(name, device_id, vid, pid)
            QMessageBox.information(self, "Success", f"Device '{name}' added.")
            self.refresh_log_table()
            self.refresh_whitelist_table()  # Refresh whitelist after adding
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to add device: {e}")

    # Function: remove_device - Removes a device from the whitelist
    def remove_device(self):
        """
        Remove a USB device from the whitelist based on the input Device ID.
        Displays a success or error message depending on the result.
        """
        device_id = self.device_id_input.text().strip()
        try:
            self.db_manager.remove_device(device_id)
            QMessageBox.information(self, "Success", f"Device '{device_id}' removed.")
            self.refresh_log_table()
            self.refresh_whitelist_table()  # Refresh whitelist after removing
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to remove device: {e}")

    # Function: update_device - Updates the name of a device in the whitelist
    def update_device(self):
        """
        Update the name of an existing USB device in the whitelist.
        Displays a success or error message depending on the operation.
        """
        device_id = self.device_id_input.text().strip()
        new_name = self.device_name_input.text().strip()

        if not device_id or not new_name:
            QMessageBox.warning(self, "Input Error", "Please enter both Device ID and new Device Name.")
            return

        try:
            self.db_manager.update_device(device_id, new_name)
            QMessageBox.information(self, "Success", f"Device '{device_id}' updated to '{new_name}'.")
            self.refresh_log_table()
            self.refresh_whitelist_table()  # Refresh whitelist after updating
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to update device: {e}")


        # Function: extract_vid_pid - Extracts VID and PID from the Device ID string
    def extract_vid_pid(self, device_id):
        """
        Extract the Vendor ID (VID) and Product ID (PID) from a given Device ID string.
        Returns None for both if the format is invalid.
        """
        match = re.search(r"VID_([0-9A-F]+)&PID_([0-9A-F]+)", device_id, re.I)
        if match:
            return match.groups()
        return None, None

    # Function: start_usb_monitoring - Starts a background thread for USB device monitoring
    def start_usb_monitoring(self):
        """
        Start monitoring connected USB devices in a separate thread.
        Continuously updates the USB devices table with detected devices.
        """
        self.monitor_thread = threading.Thread(target=self.monitor_usb_devices, daemon=True)
        self.monitor_thread.start()

    # Function: monitor_usb_devices - Monitors USB devices in real-time
    def monitor_usb_devices(self):
        """
        Continuously monitor connected USB devices using WMI (Windows Management Instrumentation).
        Emits the updated device list to the GUI.
        """
        conn = win32com.client.Dispatch("WbemScripting.SWbemLocator").ConnectServer(".", "root\\CIMV2")
        while self.running:
            devices = []
            for device in conn.ExecQuery("SELECT * FROM Win32_PnPEntity WHERE PNPClass = 'USB'"):
                # Filter out non-external devices
                if not self.is_external_device(device):
                    continue

                # Extract relevant device details
                device_id = getattr(device, "DeviceID", "N/A")
                vid, pid = self.extract_vid_pid(device_id)
                devices.append({
                    "Description": getattr(device, "Description", "N/A"),
                    "VID": vid or "N/A",
                    "PID": pid or "N/A",
                    "Serial Number": getattr(device, "PNPDeviceID", "N/A"),
                })
            self.usb_list_updated.emit(devices)
            time.sleep(5)

    # Function: is_external_device - Determines if a USB device is external
    def is_external_device(self, device):
        """
        Determine if a USB device is external based on its description and PNPDeviceID.
        Excludes host controllers, root hubs, and known internal composite devices.
        """
        description = getattr(device, "Description", "").lower()
        pnp_device_id = getattr(device, "PNPDeviceID", "").lower()

        # Exclude host controllers
        if "host controller" in description:
            return False

        # Exclude root hubs
        if "root_hub" in pnp_device_id:
            return False

        # Exclude specific known internal devices (e.g., built-in webcams)
        if "vid_13d3" in pnp_device_id:  # Example VID for internal webcams
            return False

        # Assume the device is external if it doesn't match the above exclusions
        return True

    # Function: update_usb_list_from_thread - Updates the USB Devices table with detected devices
    def update_usb_list_from_thread(self, devices):
        """
        Update the USB Devices table in the GUI with the list of detected devices.
        This method is called by the USB monitoring thread.
        """
        self.usb_table.setRowCount(0)  # Clear the table
        for device in devices:
            row_position = self.usb_table.rowCount()
            self.usb_table.insertRow(row_position)
            self.usb_table.setItem(row_position, 0, QTableWidgetItem(device["Description"]))
            self.usb_table.setItem(row_position, 1, QTableWidgetItem(device["VID"]))
            self.usb_table.setItem(row_position, 2, QTableWidgetItem(device["PID"]))
            self.usb_table.setItem(row_position, 3, QTableWidgetItem(device["Serial Number"]))

# Main execution block
if __name__ == "__main__":
    db_manager = DatabaseManager()  # Create an instance of the DatabaseManager
    db_manager.rehash_admin_passwords()  # Rehash admin passwords if necessary
    app = QApplication(sys.argv)  # Initialize the application

    # Load the external stylesheet for the application
    with open("style.qss", "r") as stylesheet:
        app.setStyleSheet(stylesheet.read())

    # Create the main window and start the application
    window = UserInterface(db_manager)
    window.show()
    sys.exit(app.exec())

