import tkinter as tk
from tkinter import ttk
import socket
import threading
import ipaddress

class PortScanner:
    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("CyberShield - Port Scanner")
        self.window.geometry("800x600")
        
        self.bg_color = "#1E2124"
        self.text_color = "#FFFFFF"
        self.accent_color = "#4ADE80"
        self.input_bg = "#2A2D31"
        
        self.window.configure(bg=self.bg_color)
        
        self.create_widgets()
        self.apply_theme()
        
    def create_widgets(self):
        main_frame = tk.Frame(self.window, bg=self.bg_color, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(main_frame, text="Port Scanner", font=("Arial", 24, "bold"), bg=self.bg_color, fg=self.text_color).pack(pady=(0, 20))
        
        input_frame = tk.Frame(main_frame, bg=self.bg_color)
        input_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(input_frame, text="IP Address:", bg=self.bg_color, fg=self.text_color).pack(side=tk.LEFT, padx=(0, 10))
        self.ip_entry = tk.Entry(input_frame, width=20, bg=self.input_bg, fg=self.text_color, insertbackground=self.text_color)
        self.ip_entry.pack(side=tk.LEFT)
        self.ip_entry.insert(0, "127.0.0.1")  # Default to localhost
        
        self.scan_button = tk.Button(input_frame, text="Scan", command=self.start_scan, bg=self.accent_color, fg=self.bg_color)
        self.scan_button.pack(side=tk.LEFT, padx=(10, 0))
        
        self.result_text = tk.Text(main_frame, wrap=tk.WORD, width=60, height=20, bg=self.input_bg, fg=self.text_color)
        self.result_text.pack(pady=(0, 20))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(0, 20))
        
        # Back button
        self.back_button = tk.Button(main_frame, text="Back", command=self.go_back, bg=self.accent_color, fg=self.bg_color)
        self.back_button.pack(pady=(10, 0))
        
    def apply_theme(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TProgressbar", background=self.accent_color, troughcolor=self.input_bg, bordercolor=self.input_bg, lightcolor=self.accent_color, darkcolor=self.accent_color)
        
    def start_scan(self):
        ip = self.ip_entry.get()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "Invalid IP address. Please enter a valid IP.\n")
            return

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Scanning {ip}...\n")
        self.progress_var.set(0)
        self.scan_button.config(state=tk.DISABLED)
        
        thread = threading.Thread(target=self.run_scan, args=(ip,))
        thread.start()
        
    def run_scan(self, ip):
        try:
            open_ports = []
            total_ports = 1024  # Scan first 1024 ports for quicker results
            
            for port in range(1, total_ports + 1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    open_ports.append((port, service))
                    self.result_text.insert(tk.END, f"Port {port}: Open ({service})\n")
                    self.result_text.see(tk.END)
                sock.close()
                
                progress = (port / total_ports) * 100
                self.progress_var.set(progress)
                self.window.update_idletasks()
            
            if not open_ports:
                self.result_text.insert(tk.END, "No open ports found.\n")
            
            self.result_text.insert(tk.END, "Scan complete.\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"An error occurred: {str(e)}\n")
        finally:
            self.progress_var.set(100)
            self.scan_button.config(state=tk.NORMAL)
            self.window.update_idletasks()
    
    def go_back(self):
        self.window.destroy()  # Close the Port Scanner window

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()
    scanner = PortScanner(root)
    root.mainloop()
