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
# database
#