from Database import DatabaseManager  # Import the database logic
from UserInterface import Application       # Import the UI logic

def main():
    # Initialize the database
    db = DatabaseManager('whitelist.db')  # Name of your database file

    # Launch the UI
    app = Application(db)
    app.run()

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
 
