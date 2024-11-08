import sqlite3

def view_data(db_name="usb_devices.db"):
    with sqlite3.connect(db_name) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM usb_devices")
        rows = cursor.fetchall()
        for row in rows:
            print(row)

view_data()
