import sqlite3
import sys
import threading
import time
import datetime
import win32com.client
from Database import DatabaseManager
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox, QWidget, QTabWidget, QTableWidget, QTableWidgetItem, QSystemTrayIcon
from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QIcon


class UserInterface(QMainWindow):
    def __init__(self, db_manager):
        super().__init__()
        self.db_manager = db_manager
        self.setWindowTitle("USB Device Manager")
        self.setGeometry(300, 300, 800, 500)
        
        self.running = True  # Flag to control the background monitoring thread
        self.init_ui()

    def init_ui(self):
        # Create a tab widget to add tabs
        self.tabs = QTabWidget()
        
        # Tab 1: Main functionality
        main_tab = QWidget()
        main_layout = QVBoxLayout()

        # Device Name input
        self.device_name_label = QLabel("Device Name:")
        self.device_name_input = QLineEdit()
        main_layout.addWidget(self.device_name_label)
        main_layout.addWidget(self.device_name_input)

        # Device ID input
        self.device_id_label = QLabel("Device ID:")
        self.device_id_input = QLineEdit()
        main_layout.addWidget(self.device_id_label)
        main_layout.addWidget(self.device_id_input)

        # Add Device Button
        add_button = QPushButton("Add Device")
        add_button.clicked.connect(self.add_device)
        main_layout.addWidget(add_button)

        # Remove Device Button
        remove_button = QPushButton("Remove Device")
        remove_button.clicked.connect(self.remove_device)
        main_layout.addWidget(remove_button)

        # Update Device Button
        update_button = QPushButton("Update Device")
        update_button.clicked.connect(self.update_device)
        main_layout.addWidget(update_button)

        main_tab.setLayout(main_layout)
        self.tabs.addTab(main_tab, "Main")

        # Tab 2: USB Devices
        usb_tab = QWidget()
        usb_layout = QVBoxLayout()
        
        # Table widget to display detected USB devices
        self.usb_list = QTableWidget(0, 3)  # 3 columns for device properties
        self.usb_list.setHorizontalHeaderLabels(["DeviceID", "PNPDeviceID", "Description"])
        
        usb_layout.addWidget(QLabel("Detected USB Devices:"))
        usb_layout.addWidget(self.usb_list)
        
        usb_tab.setLayout(usb_layout)
        self.tabs.addTab(usb_tab, "USB Devices")

        # Tab 3: Whitelist
        whitelist_tab = QWidget()
        whitelist_layout = QVBoxLayout()
        
        # Table widget to display whitelisted USB devices
        self.whitelist_table = QTableWidget(0, 6)  # 6 columns for device properties
        self.whitelist_table.setHorizontalHeaderLabels(["Device Name", "DeviceID", "VID", "PID", "Date Added", "Time Added"])
        
        whitelist_layout.addWidget(QLabel("Whitelisted USB Devices:"))
        whitelist_layout.addWidget(self.whitelist_table)
        
        whitelist_tab.setLayout(whitelist_layout)
        self.tabs.addTab(whitelist_tab, "Whitelist")

        # Add tabs to the main window
        container = QWidget()
        container.setLayout(QVBoxLayout())
        container.layout().addWidget(self.tabs)
        self.setCentralWidget(container)

        # Search bar and button
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search by Device Name or Device ID")
        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self.search_whitelist)

        # Add the search bar and button to the layout
        whitelist_layout.addWidget(self.search_input)
        whitelist_layout.addWidget(self.search_button)


        # Start the USB monitoring in a background thread
        self.start_usb_monitoring()

    def add_device(self):
        name = self.device_name_input.text()
        device_id = self.device_id_input.text()
        if name and device_id:
            try:
                # Extract VID and PID from device_id
                vid, pid = self.extract_vid_pid(device_id)

                # Check if VID and PID were successfully extracted
                if not vid or not pid:
                    QMessageBox.warning(self, "Error", "Failed to extract VID and PID from the device ID. Please check the ID format.")
                    return

                # Attempt to add the device to the database with vid and pid
                self.db_manager.add_device(name, device_id, vid, pid)
                QMessageBox.information(self, "Success", f"Device '{name}' added to whitelist.")

                # Show notification
                self.show_notification("Notice: A new USB device added into whitelist")

                # Record date and time
                date_added = datetime.date.today().strftime("%Y-%m-%d")
                time_added = datetime.datetime.now().strftime("%H:%M:%S")

                # Add device to whitelist table in GUI
                # Add device to whitelist table in GUI
                row_position = self.whitelist_table.rowCount()
                self.whitelist_table.insertRow(row_position)
                self.whitelist_table.setItem(row_position, 0, QTableWidgetItem(name))  # Device Name
                self.whitelist_table.setItem(row_position, 1, QTableWidgetItem(device_id))
                self.whitelist_table.setItem(row_position, 2, QTableWidgetItem(vid))
                self.whitelist_table.setItem(row_position, 3, QTableWidgetItem(pid))
                self.whitelist_table.setItem(row_position, 4, QTableWidgetItem(date_added))
                self.whitelist_table.setItem(row_position, 5, QTableWidgetItem(time_added))


            except sqlite3.IntegrityError as e:
                # Handle duplicate entry error
                if "UNIQUE constraint failed" in str(e):
                    QMessageBox.warning(self, "Duplicate Device ID", "This device ID is already in the whitelist. Please check the device details or use a different ID.")
                else:
                    QMessageBox.warning(self, "Database Error", f"An error occurred: {e}")
            except Exception as e:
                # General error message for any other exceptions
                QMessageBox.warning(self, "Error", f"Failed to add device: {e}")
        else:
            QMessageBox.warning(self, "Input Error", "Please enter both name and device ID.")



    def show_notification(self, message):
        """Display a notification for 10 seconds."""
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon("path/to/icon.png"))  # Set an icon for the notification
        self.tray_icon.show()
        self.tray_icon.showMessage("USB Device Manager", message, QSystemTrayIcon.Information, 10000)  # 10 seconds

    def remove_device(self):
        device_id = self.device_id_input.text()
        if device_id:
            try:
                # Attempt to remove the device from the database
                self.db_manager.remove_device(device_id)
                
                # Update the whitelist table in the UI
                self.refresh_whitelist_table()

                # Show a notification confirming the removal
                self.show_notification(f"Notice: Device with ID '{device_id}' removed from the whitelist")

                # Show success message in the dialog
                QMessageBox.information(self, "Success", f"Device with ID '{device_id}' removed from the whitelist.")

            except Exception as e:
                # General error message if removal fails
                QMessageBox.warning(self, "Error", f"Failed to remove device: {e}")
        else:
            QMessageBox.warning(self, "Input Error", "Please enter a device ID.")
    
    def refresh_whitelist_table(self):
        """Refresh the whitelist table with data from the database."""
        self.search_input.clear()  # Clear search input to show all entries
        self.whitelist_table.setRowCount(0)

        # Fetch all devices from the database
        devices = self.db_manager.get_all_devices()

        # Populate the whitelist table with all devices from the database
        for device in devices:
            row_position = self.whitelist_table.rowCount()
            self.whitelist_table.insertRow(row_position)
            self.whitelist_table.setItem(row_position, 0, QTableWidgetItem(device["device_name"]))
            self.whitelist_table.setItem(row_position, 1, QTableWidgetItem(device["device_id"]))
            self.whitelist_table.setItem(row_position, 2, QTableWidgetItem(device["vid"]))
            self.whitelist_table.setItem(row_position, 3, QTableWidgetItem(device["pid"]))
            self.whitelist_table.setItem(row_position, 4, QTableWidgetItem(device["date_added"]))
            self.whitelist_table.setItem(row_position, 5, QTableWidgetItem(device["time_added"]))


    def show_notification(self, message):
        """Display a notification for 10 seconds."""
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon("path/to/icon.png"))  # Set an icon for the notification
        self.tray_icon.show()
        self.tray_icon.showMessage("USB Device Manager", message, QSystemTrayIcon.Information, 10000)  # 10 seconds

    def update_device(self):
        device_id = self.device_id_input.text()
        new_name = self.device_name_input.text()
        if device_id and new_name:
            self.db_manager.update_device(device_id, new_name)
            QMessageBox.information(self, "Success", f"Device with ID '{device_id}' updated to '{new_name}'.")
        else:
            QMessageBox.warning(self, "Input Error", "Please enter both the device ID and new name.")

    def start_usb_monitoring(self):
        """Start the USB monitoring in a background thread."""
        self.monitor_thread = threading.Thread(target=self.update_usb_devices)
        self.monitor_thread.start()

    def stop_usb_monitoring(self):
        """Stop the USB monitoring thread."""
        self.running = False
        self.monitor_thread.join()

    def extract_vid_pid(self, device_id):
        """Extracts VID and PID from the device ID."""
        import re
        match = re.search(r"VID_([0-9A-F]+)&PID_([0-9A-F]+)", device_id, re.I)
        if match:
            return match.groups()
        return None, None

    def update_usb_devices(self):
        """Monitor USB devices and update the GUI list in real time."""
        conn = win32com.client.Dispatch("WbemScripting.SWbemLocator").ConnectServer(".", "root\\CIMV2")
        
        while self.running:
            # Clear the list before updating
            self.usb_list.setRowCount(0)
            
            # Query USB devices and update the list
            for device in conn.ExecQuery("SELECT * FROM Win32_PnPEntity WHERE PNPClass = 'USB'"):
                device_id = getattr(device, "DeviceID", "N/A")
                row_position = self.usb_list.rowCount()
                self.usb_list.insertRow(row_position)
                
                # Populate the row with device information
                self.usb_list.setItem(row_position, 0, QTableWidgetItem(device_id))
                self.usb_list.setItem(row_position, 1, QTableWidgetItem(getattr(device, "PNPDeviceID", "N/A")))
                self.usb_list.setItem(row_position, 2, QTableWidgetItem(getattr(device, "Description", "N/A")))

            # Wait before the next update
            time.sleep(10)



    def search_whitelist(self):
        """Filter the whitelist table based on the search query."""
        query = self.search_input.text().strip().lower()  # Get the search query and convert to lowercase

        # Clear existing rows in the table and fetch all devices from the database
        self.whitelist_table.setRowCount(0)
        devices = self.db_manager.get_all_devices()

        # Populate the table with filtered results
        for device in devices:
            device_name = device["device_name"].lower()  # Convert to lowercase for case-insensitive search
            device_id = device["device_id"].lower()  # Convert to lowercase for case-insensitive search

            # Check if the search query matches either the device name or device ID
            if query in device_name or query in device_id or not query:
                row_position = self.whitelist_table.rowCount()
                self.whitelist_table.insertRow(row_position)
                self.whitelist_table.setItem(row_position, 0, QTableWidgetItem(device["device_name"]))
                self.whitelist_table.setItem(row_position, 1, QTableWidgetItem(device["device_id"]))
                self.whitelist_table.setItem(row_position, 2, QTableWidgetItem(device["vid"]))
                self.whitelist_table.setItem(row_position, 3, QTableWidgetItem(device["pid"]))
                self.whitelist_table.setItem(row_position, 4, QTableWidgetItem(device["date_added"]))
                self.whitelist_table.setItem(row_position, 5, QTableWidgetItem(device["time_added"]))



    def closeEvent(self, event):
        """Handle window close event to stop USB monitoring thread."""
        self.stop_usb_monitoring()
        event.accept()


class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login")
        self.setGeometry(500, 300, 300, 150)

        # Username Label and Input
        self.username_label = QLabel("Username:", self)
        self.username_label.move(20, 20)
        self.username_input = QLineEdit(self)
        self.username_input.move(100, 20)

        # Password Label and Input
        self.password_label = QLabel("Password:", self)
        self.password_label.move(20, 60)
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)  # Hide password characters
        self.password_input.move(100, 60)

        # Login Button
        self.login_button = QPushButton("Login", self)
        self.login_button.move(100, 100)
        self.login_button.clicked.connect(self.check_credentials)

    def check_credentials(self):
        # Hardcoded credentials
        username = "admin"
        password = "noentry"

        # Get input credentials
        entered_username = self.username_input.text()
        entered_password = self.password_input.text()

        # Check if the credentials match
        if entered_username == username and entered_password == password:
            QMessageBox.information(self, "Login Successful", "Welcome!")
            self.open_main_window()
        else:
            QMessageBox.warning(self, "Login Failed", "Incorrect username or password.")

    def open_main_window(self):
        # Close the login window and open the main application window
        self.main_window = UserInterface(db_manager=DatabaseManager())  # Replace with your actual DatabaseManager instance
        self.main_window.show()
        self.close()

# To run the application
if __name__ == "__main__":
    app = QApplication(sys.argv)
    # These two lines are responsible for showing credentials popup window
    login_window = LoginWindow()
    login_window.show()
  
    sys.exit(app.exec_())
