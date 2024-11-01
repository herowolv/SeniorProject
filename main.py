import sys
from PyQt5.QtWidgets import QApplication
from Database import DatabaseManager
from UserInterface import UserInterface

def main():
    db_manager = DatabaseManager()  # Initialize database
    app = QApplication(sys.argv)  # Initialize PyQt5 application
    ui = UserInterface(db_manager)  # Create the main UI
    ui.show()  # Show the UI window
    sys.exit(app.exec_())  # Start the event loop

if __name__ == "__main__":
    main()

# search features
# view devices in UI
 
# database number reset
#
# database for admin and device
 
# notification to admin
# authentication for admin
#
# admin credintials
# Steps:
# creating all the features, Create database for admin, whitelist devices and activity log, Create script to detect USB device and compare it to whitelist database.
# create authentication protocol and notification
# create GUI
 
