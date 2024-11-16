import threading
import time
import win32com.client

# Flag to control the running state of the background task
running = True

def get_usb_info():
    # Connect to the WMI service
    conn = win32com.client.Dispatch("WbemScripting.SWbemLocator").ConnectServer(".", "root\\CIMV2")
    
    while running:
        # Query and print information for each USB device
        for device in conn.ExecQuery("SELECT * FROM Win32_USBHub"):
            print("DeviceID:", getattr(device, "DeviceID", "N/A"))
            print("PNPDeviceID:", getattr(device, "PNPDeviceID", "N/A"))
            print("Description:", getattr(device, "Description", "N/A"))
            print("Manufacturer:", getattr(device, "Manufacturer", "N/A"))
            print("Name:", getattr(device, "Name", "N/A"))
            print("Status:", getattr(device, "Status", "N/A"))
            print("-" * 40)
        
        # Wait before the next check to avoid excessive CPU usage
        time.sleep(20)

def start_background_task():
    # Start the USB monitoring function in a background thread
    thread = threading.Thread(target=get_usb_info)
    thread.start()
    return thread

def stop_background_task():
    # Stop the background USB monitoring task
    global running
    running = False

# Example of running and stopping the background task
if __name__ == "__main__":
    try:
        # Start the USB monitoring in the background
        background_thread = start_background_task()
        
        # Main loop to simulate the tool being open
        while True:
            # Simulate the main tool's tasks (replace with actual tool functionality)
            print("Tool is running...")
            time.sleep(1)
    except KeyboardInterrupt:
        # When the tool closes, stop the background thread
        stop_background_task()
        background_thread.join()
        print("Tool closed.")
