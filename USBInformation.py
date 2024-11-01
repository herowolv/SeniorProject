import win32com.client

def get_usb_info():
    # Connect to the WMI service
    conn = win32com.client.Dispatch("WbemScripting.SWbemLocator").ConnectServer(".", "root\\CIMV2")

    # Query and print information for each USB device
    for device in conn.ExecQuery("SELECT * FROM Win32_USBHub"):
        print("DeviceID:", getattr(device, "DeviceID", "N/A"))
        print("PNPDeviceID:", getattr(device, "PNPDeviceID", "N/A"))
        print("Description:", getattr(device, "Description", "N/A"))
        print("Manufacturer:", getattr(device, "Manufacturer", "N/A"))
        print("Name:", getattr(device, "Name", "N/A"))
        print("Status:", getattr(device, "Status", "N/A"))
        print("-" * 40)

# Run the function to display USB information
get_usb_info()
