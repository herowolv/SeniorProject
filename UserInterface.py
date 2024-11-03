import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from Database import DatabaseManager  # Ensure DatabaseManager is correctly imported

class Application:
    def __init__(self, database):
        self.db = database
        self.root = tk.Tk()
        self.root.title("USB Device Whitelisting Tool")
        
        # UI Elements Setup for Device Input
        tk.Label(self.root, text="Device Name:").pack()
        self.entry_device_name = tk.Entry(self.root)
        self.entry_device_name.pack()
        
        tk.Label(self.root, text="Device ID:").pack()
        self.entry_device_id = tk.Entry(self.root)
        self.entry_device_id.pack()

        tk.Label(self.root, text="Device Group:").pack()
        self.entry_group = tk.Entry(self.root)
        self.entry_group.pack()
        
        # Buttons for actions
        tk.Button(self.root, text="Add USB Device", command=self.add_device).pack(pady=5)
        tk.Button(self.root, text="View USB Devices", command=self.show_devices_window).pack(pady=5)
        tk.Button(self.root, text="Update USB Device", command=self.update_device).pack(pady=5)
        tk.Button(self.root, text="Delete USB Device", command=self.delete_device).pack(pady=5)
        tk.Button(self.root, text="View Activity Logs", command=self.view_logs).pack(pady=5)
    
    def run(self):
        self.root.mainloop()
    
    def add_device(self):
        """Add a new USB device using the DatabaseManager."""
        device_name = self.entry_device_name.get()
        device_id = self.entry_device_id.get()
        group_name = self.entry_group.get()
        
        if device_name and device_id:
            self.db.add_device(device_name, device_id, group_name)
            messagebox.showinfo("Success", f"Device '{device_name}' added successfully.")
        else:
            messagebox.showwarning("Input Error", "Please enter both device name and ID.")
    
    def show_devices_window(self):
        """Open a new window to display devices grouped by their assigned groups."""
        devices_window = tk.Toplevel(self.root)
        devices_window.title("View USB Devices")

        # Create a Treeview widget
        tree = ttk.Treeview(devices_window)
        tree.pack(fill='both', expand=True)
        tree.heading("#0", text="USB Devices by Group", anchor="w")

        # Get all devices and group them
        devices = self.db.get_all_devices()
        grouped_devices = {}
        for device in devices:
            group_name = device[3] if device[3] else "Ungrouped"
            if group_name not in grouped_devices:
                grouped_devices[group_name] = []
            grouped_devices[group_name].append(device)

        # Populate the Treeview with groups and devices
        for group, devices in grouped_devices.items():
            group_id = tree.insert("", "end", text=group, open=False)  # Create group item
            for device in devices:
                tree.insert(group_id, "end", text=f"{device[1]} (ID: {device[2]}) added on {device[4]}")

    def update_device(self):
        """Update the name and/or group of an existing USB device."""
        device_id = simpledialog.askstring("Device ID", "Enter the Device ID to update:")
        new_name = simpledialog.askstring("New Name", "Enter the new name for the device:")
        new_group = simpledialog.askstring("New Group", "Enter the new group for the device:")

        if device_id and (new_name or new_group):
            device = self.db.get_device_by_id(device_id)
            if device:
                if new_name:
                    self.db.update_device_name(device_id, new_name)
                if new_group:
                    self.db.update_device_group(device_id, new_group)
                messagebox.showinfo("Success", f"Device ID '{device_id}' updated.")
            else:
                messagebox.showerror("Error", "Device not found.")
        else:
            messagebox.showwarning("Input Error", "Please provide device ID and at least one update field.")
    
    def delete_device(self):
        """Delete a USB device from the database."""
        device_id = simpledialog.askstring("Device ID", "Enter the Device ID to delete:")
        
        if device_id:
            device = self.db.get_device_by_id(device_id)
            if device:
                self.db.delete_device(device_id)
                messagebox.showinfo("Success", f"Device ID '{device_id}' deleted successfully.")
            else:
                messagebox.showerror("Error", "Device not found.")
        else:
            messagebox.showwarning("Input Error", "Please provide a device ID.")
    
    def view_logs(self):
        """Display all activity logs from the database."""
        logs = self.db.get_all_logs()
        log_list = "\n".join([f"{l[0]}: {l[1]} at {l[2]}" for l in logs])
        messagebox.showinfo("Activity Logs", log_list or "No logs found.")
