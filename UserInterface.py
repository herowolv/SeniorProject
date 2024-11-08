from PyQt5.QtWidgets import *

class UserInterface(QMainWindow):
    def __init__(self, db_manager):
        super().__init__() 
        self.db_manager = db_manager
        self.setWindowTitle("USB Device Manager")
        self.setGeometry(300, 300, 400, 200)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Device Name input
        self.device_name_label = QLabel("Device Name:")
        self.device_name_input = QLineEdit()
        layout.addWidget(self.device_name_label)
        layout.addWidget(self.device_name_input)

        # Device ID input
        self.device_id_label = QLabel("Device ID:")
        self.device_id_input = QLineEdit()
        layout.addWidget(self.device_id_label)
        layout.addWidget(self.device_id_input)

        # Add Device Button
        add_button = QPushButton("Add Device")
        add_button.clicked.connect(self.add_device)
        layout.addWidget(add_button)

        # Remove Device Button
        remove_button = QPushButton("Remove Device")
        remove_button.clicked.connect(self.remove_device)
        layout.addWidget(remove_button)

        # Update Device Button
        update_button = QPushButton("Update Device")
        update_button.clicked.connect(self.update_device)
        layout.addWidget(update_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def add_device(self):
        name = self.device_name_input.text()
        device_id = self.device_id_input.text()
        if name and device_id:
            try:
                self.db_manager.add_device(name, device_id)
                QMessageBox.information(self, "Success", f"Device '{name}' added successfully.")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to add device: {e}")
        else:
            QMessageBox.warning(self, "Input Error", "Please enter both name and device ID.")

    def remove_device(self):
        device_id = self.device_id_input.text()
        if device_id:
            self.db_manager.remove_device(device_id)
            QMessageBox.information(self, "Success", f"Device with ID '{device_id}' removed.")
        else:
            QMessageBox.warning(self, "Input Error", "Please enter a device ID.")

    def update_device(self):
        device_id = self.device_id_input.text()
        new_name = self.device_name_input.text()
        if device_id and new_name:
            self.db_manager.update_device(device_id, new_name)
            QMessageBox.information(self, "Success", f"Device with ID '{device_id}' updated to '{new_name}'.")
        else:
            QMessageBox.warning(self, "Input Error", "Please enter both the device ID and new name.")
