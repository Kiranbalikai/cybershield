import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import nmap
import ipaddress
import threading
import time
import json
from datetime import datetime
import socket

class PortScanner:
    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("CyberShield - Advanced Port Scanner")
        self.window.geometry("1000x700")
        
        self.bg_color = "#1E2124"
        self.text_color = "#FFFFFF"
        self.accent_color = "#4ADE80"
        self.input_bg = "#2A2D31"
        self.danger_color = "#EF4444"
        
        self.window.configure(bg=self.bg_color)
        
        self.scan_results = {}
        self.is_scanning = False
        
        self.create_widgets()
        self.apply_theme()
        
    def create_widgets(self):
        main_frame = tk.Frame(self.window, bg=self.bg_color, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_frame = tk.Frame(main_frame, bg=self.bg_color)
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(title_frame, text="🔍 Advanced Port Scanner", font=("Arial", 24, "bold"), 
                bg=self.bg_color, fg=self.accent_color).pack()
        tk.Label(title_frame, text="Network Security Assessment Tool", font=("Arial", 12), 
                bg=self.bg_color, fg=self.text_color).pack()
        
        # Configuration Frame
        config_frame = tk.LabelFrame(main_frame, text="Scan Configuration", font=("Arial", 12, "bold"),
                                   bg=self.bg_color, fg=self.accent_color, bd=2)
        config_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Target Configuration
        target_frame = tk.Frame(config_frame, bg=self.bg_color)
        target_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(target_frame, text="Target:", bg=self.bg_color, fg=self.text_color, 
                font=("Arial", 11, "bold")).grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        self.ip_entry = tk.Entry(target_frame, width=25, bg=self.input_bg, fg=self.text_color, 
                               insertbackground=self.text_color, font=("Arial", 11))
        self.ip_entry.grid(row=0, column=1, padx=(0, 20))
        self.ip_entry.insert(0, "127.0.0.1")
        
        tk.Label(target_frame, text="Ports:", bg=self.bg_color, fg=self.text_color, 
                font=("Arial", 11, "bold")).grid(row=0, column=2, sticky=tk.W, padx=(0, 10))
        
        self.range_entry = tk.Entry(target_frame, width=20, bg=self.input_bg, fg=self.text_color, 
                                  insertbackground=self.text_color, font=("Arial", 11))
        self.range_entry.grid(row=0, column=3, padx=(0, 20))
        self.range_entry.insert(0, "1-1000")
        
        # Scan Type Configuration
        scan_type_frame = tk.Frame(config_frame, bg=self.bg_color)
        scan_type_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        tk.Label(scan_type_frame, text="Scan Type:", bg=self.bg_color, fg=self.text_color, 
                font=("Arial", 11, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        
        self.scan_type = tk.StringVar(value="tcp_connect")
        scan_types = [
            ("TCP Connect", "tcp_connect"),
            ("SYN Scan", "syn_scan"),
            ("UDP Scan", "udp_scan"),
            ("Comprehensive", "comprehensive")
        ]
        
        for text, value in scan_types:
            tk.Radiobutton(scan_type_frame, text=text, variable=self.scan_type, value=value,
                         bg=self.bg_color, fg=self.text_color, selectcolor=self.input_bg,
                         font=("Arial", 10)).pack(side=tk.LEFT, padx=10)
        
        # Control Buttons
        control_frame = tk.Frame(config_frame, bg=self.bg_color)
        control_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.scan_button = tk.Button(control_frame, text="Start Scan", command=self.start_scan, 
                                   bg=self.accent_color, fg=self.bg_color, font=("Arial", 12, "bold"))
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.preset_button = tk.Button(control_frame, text="Quick Presets", command=self.show_presets, 
                                     bg="#60A5FA", fg=self.bg_color, font=("Arial", 12, "bold"))
        self.preset_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.demo_button = tk.Button(control_frame, text="Demo Scan", command=self.demo_scan, 
                                   bg="#F59E0B", fg=self.bg_color, font=("Arial", 12, "bold"))
        self.demo_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Progress Frame
        progress_frame = tk.Frame(main_frame, bg=self.bg_color)
        progress_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(0, 5))
        
        self.status_label = tk.Label(progress_frame, text="Ready to scan", bg=self.bg_color, 
                                   fg=self.text_color, font=("Arial", 10))
        self.status_label.pack()
        
        # Results Notebook
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        # Scan Results Tab
        results_frame = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(results_frame, text="Scan Results")
        
        # Results with Treeview for better formatting
        self.results_tree = ttk.Treeview(results_frame, columns=("Port", "State", "Service", "Version"), 
                                       show="headings", height=15)
        self.results_tree.heading("Port", text="Port")
        self.results_tree.heading("State", text="State")
        self.results_tree.heading("Service", text="Service")
        self.results_tree.heading("Version", text="Version")
        
        self.results_tree.column("Port", width=80)
        self.results_tree.column("State", width=80)
        self.results_tree.column("Service", width=120)
        self.results_tree.column("Version", width=200)
        
        self.results_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Vulnerabilities Tab
        vuln_frame = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(vuln_frame, text="🚨 Vulnerabilities")
        
        self.vuln_text = tk.Text(vuln_frame, wrap=tk.WORD, bg=self.input_bg, fg=self.text_color, 
                               font=("Consolas", 10))
        self.vuln_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Raw Output Tab
        raw_frame = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(raw_frame, text="Raw Output")
        
        self.raw_text = tk.Text(raw_frame, wrap=tk.WORD, bg=self.input_bg, fg=self.text_color, 
                              font=("Consolas", 9))
        self.raw_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bottom Buttons
        bottom_frame = tk.Frame(main_frame, bg=self.bg_color)
        bottom_frame.pack(fill=tk.X)
        
        self.save_button = tk.Button(bottom_frame, text="Save Report", command=self.save_report, 
                                   bg="#8B5CF6", fg=self.text_color, font=("Arial", 11, "bold"))
        self.save_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.export_button = tk.Button(bottom_frame, text="Export JSON", command=self.export_json, 
                                     bg="#10B981", fg=self.text_color, font=("Arial", 11, "bold"))
        self.export_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.back_button = tk.Button(bottom_frame, text="Back", command=self.go_back, 
                                   bg=self.danger_color, fg=self.text_color, font=("Arial", 11, "bold"))
        self.back_button.pack(side=tk.RIGHT)
        
    def apply_theme(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TProgressbar", background=self.accent_color, troughcolor=self.input_bg, 
                       bordercolor=self.input_bg, lightcolor=self.accent_color, darkcolor=self.accent_color)
        
        # Configure Treeview
        style.configure("Treeview", background=self.input_bg, foreground=self.text_color, 
                       fieldbackground=self.input_bg)
        style.configure("Treeview.Heading", background=self.bg_color, foreground=self.accent_color)
        
    def show_presets(self):
        """Show quick scan presets"""
        preset_window = tk.Toplevel(self.window)
        preset_window.title("Quick Scan Presets")
        preset_window.geometry("400x300")
        preset_window.configure(bg=self.bg_color)
        
        tk.Label(preset_window, text="Select a Preset Scan", font=("Arial", 14, "bold"), 
                bg=self.bg_color, fg=self.accent_color).pack(pady=10)
        
        presets = [
            ("Web Server Scan", "127.0.0.1", "80,443,8080,8443"),
            ("Database Scan", "127.0.0.1", "1433,3306,5432,1521,27017"),
            ("Common Services", "127.0.0.1", "21,22,23,25,53,80,110,143,443,993,995"),
            ("High Ports", "127.0.0.1", "8000-9000"),
            ("Full TCP Scan", "127.0.0.1", "1-65535")
        ]
        
        for name, ip, ports in presets:
            btn = tk.Button(preset_window, text=name, 
                          command=lambda i=ip, p=ports: self.apply_preset(i, p, preset_window),
                          bg=self.accent_color, fg=self.bg_color, font=("Arial", 11), width=25)
            btn.pack(pady=5)
    
    def apply_preset(self, ip, ports, window):
        self.ip_entry.delete(0, tk.END)
        self.ip_entry.insert(0, ip)
        self.range_entry.delete(0, tk.END)
        self.range_entry.insert(0, ports)
        window.destroy()
        
    def start_scan(self):
        if self.is_scanning:
            return
            
        ip = self.ip_entry.get().strip()
        port_range = self.range_entry.get().strip()
        
        # Validate inputs
        if not self.validate_inputs(ip, port_range):
            return
        
        self.clear_results()
        self.is_scanning = True
        self.scan_button.config(state=tk.DISABLED, text="Scanning...")
        self.progress_var.set(0)
        
        # Start scan in thread
        thread = threading.Thread(target=self.run_scan, args=(ip, port_range))
        thread.daemon = True
        thread.start()
        
    def validate_inputs(self, ip, port_range):
        # Validate IP
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            try:
                socket.gethostbyname(ip)  # Try hostname resolution
            except socket.gaierror:
                messagebox.showerror("Error", "Invalid IP address or hostname")
                return False
        
        # Validate port range
        try:
            if '-' in port_range:
                start_port, end_port = map(int, port_range.split('-'))
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    raise ValueError()
            elif ',' in port_range:
                ports = [int(p.strip()) for p in port_range.split(',')]
                if any(p < 1 or p > 65535 for p in ports):
                    raise ValueError()
            else:
                port = int(port_range)
                if port < 1 or port > 65535:
                    raise ValueError()
        except ValueError:
            messagebox.showerror("Error", "Invalid port range")
            return False
            
        return True
    
    def run_scan(self, ip, port_range):
        nm = nmap.PortScanner()
        scan_type = self.scan_type.get()
        
        try:
            self.status_label.config(text=f"Scanning {ip}...")
            
            # Configure scan arguments based on type
            if scan_type == "tcp_connect":
                arguments = "-sT"
            elif scan_type == "syn_scan":
                arguments = "-sS"
            elif scan_type == "udp_scan":
                arguments = "-sU"
            elif scan_type == "comprehensive":
                arguments = "-sS -sV -O -A"
            else:
                arguments = "-sT"
            
            # Perform scan
            nm.scan(ip, port_range, arguments=arguments)
            
            if ip in nm.all_hosts():
                self.process_scan_results(nm, ip)
            else:
                self.raw_text.insert(tk.END, f"Host {ip} appears to be down or unreachable.\n")
                
        except Exception as e:
            self.raw_text.insert(tk.END, f"Scan error: {str(e)}\n")
        finally:
            self.progress_var.set(100)
            self.status_label.config(text="Scan completed")
            self.is_scanning = False
            self.scan_button.config(state=tk.NORMAL, text="Start Scan")
    
    def process_scan_results(self, nm, ip):
        host_info = nm[ip]
        self.scan_results = {
            'target': ip,
            'timestamp': datetime.now().isoformat(),
            'state': host_info.state(),
            'protocols': {},
            'os': host_info.get('osmatch', []),
            'vulnerabilities': []
        }
        
        # Process each protocol
        for protocol in host_info.all_protocols():
            ports = host_info[protocol].keys()
            self.scan_results['protocols'][protocol] = {}
            
            for port in sorted(ports):
                port_info = host_info[protocol][port]
                state = port_info['state']
                service = port_info.get('name', 'unknown')
                version = port_info.get('version', '')
                product = port_info.get('product', '')
                
                # Add to results tree
                full_version = f"{product} {version}".strip()
                self.results_tree.insert("", tk.END, values=(port, state, service, full_version))
                
                # Store in results
                self.scan_results['protocols'][protocol][port] = {
                    'state': state,
                    'service': service,
                    'version': full_version,
                    'product': product
                }
                
                # Check for vulnerabilities
                self.check_vulnerabilities(port, service, product, version)
        
        # Add raw nmap output
        self.raw_text.insert(tk.END, f"Nmap scan report for {ip}\n")
        self.raw_text.insert(tk.END, f"Host is {host_info.state()}\n\n")
        
        if 'osmatch' in host_info and host_info['osmatch']:
            self.raw_text.insert(tk.END, "OS Detection:\n")
            for os_match in host_info['osmatch']:
                self.raw_text.insert(tk.END, f"  {os_match['name']} (accuracy: {os_match['accuracy']}%)\n")
            self.raw_text.insert(tk.END, "\n")
    
    def check_vulnerabilities(self, port, service, product, version):
        """Check for common vulnerabilities"""
        vulnerabilities = []
        
        # Common vulnerable services and ports
        vuln_checks = {
            21: ["FTP", "Anonymous login possible", "Unencrypted data transfer"],
            23: ["Telnet", "Unencrypted protocol", "Credential sniffing risk"],
            53: ["DNS", "DNS amplification attacks", "Zone transfer possible"],
            80: ["HTTP", "Unencrypted web traffic", "Information disclosure"],
            135: ["RPC", "Remote code execution", "Information disclosure"],
            139: ["NetBIOS", "SMB vulnerabilities", "Information disclosure"],
            445: ["SMB", "EternalBlue vulnerability", "Remote code execution"],
            1433: ["SQL Server", "SQL injection", "Weak authentication"],
            3389: ["RDP", "BlueKeep vulnerability", "Brute force attacks"]
        }
        
        if port in vuln_checks:
            service_name, *risks = vuln_checks[port]
            for risk in risks:
                vuln_msg = f"Port {port} ({service}): {risk}\n"
                self.vuln_text.insert(tk.END, vuln_msg)
                vulnerabilities.append(risk)
        
        # Check for outdated versions (simplified)
        if version and any(old_ver in version.lower() for old_ver in ['2008', '2012', '1.0', '2.0']):
            vuln_msg = f"Port {port} ({service}): Potentially outdated version - {version}\n"
            self.vuln_text.insert(tk.END, vuln_msg)
            vulnerabilities.append(f"Outdated version: {version}")
        
        self.scan_results['vulnerabilities'].extend(vulnerabilities)
    
    def demo_scan(self):
        """Generate demo scan results for presentation"""
        self.clear_results()
        self.progress_var.set(0)
        self.status_label.config(text="Running demo scan...")
        
        # Simulate scanning progress
        for i in range(101):
            self.progress_var.set(i)
            self.window.update_idletasks()
            time.sleep(0.02)
        
        # Add demo results
        demo_results = [
            (22, "open", "ssh", "OpenSSH 7.4"),
            (80, "open", "http", "Apache 2.4.6"),
            (443, "open", "https", "Apache 2.4.6"),
            (3306, "open", "mysql", "MySQL 5.7.25"),
            (4444, "open", "unknown", "Metasploit payload"),
            (8080, "open", "http-proxy", "Jetty 9.4.z"),
            (21, "closed", "ftp", ""),
            (23, "filtered", "telnet", ""),
        ]
        
        for port, state, service, version in demo_results:
            self.results_tree.insert("", tk.END, values=(port, state, service, version))
            
            # Add vulnerabilities for demo
            if port == 4444:
                self.vuln_text.insert(tk.END, f"🚨 CRITICAL: Port {port} - Possible backdoor/malware\n")
            elif port == 22:
                self.vuln_text.insert(tk.END, f"⚠️ WARNING: Port {port} - SSH brute force risk\n")
            elif port == 3306:
                self.vuln_text.insert(tk.END, f"⚠️ WARNING: Port {port} - Database exposed to network\n")
        
        # Add demo raw output
        self.raw_text.insert(tk.END, "Demo Scan Results\n")
        self.raw_text.insert(tk.END, "Target: 192.168.1.100\n")
        self.raw_text.insert(tk.END, "Scan completed in 15.2 seconds\n")
        self.raw_text.insert(tk.END, "8 ports scanned, 6 open, 1 closed, 1 filtered\n")
        
        self.status_label.config(text="Demo scan completed")
    
    def clear_results(self):
        # Clear all result displays
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.vuln_text.delete(1.0, tk.END)
        self.raw_text.delete(1.0, tk.END)
        self.scan_results = {}
    
    def save_report(self):
        if not self.scan_results:
            messagebox.showwarning("Warning", "No scan results to save")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("HTML files", "*.html")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(f"Port Scan Report\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Target: {self.scan_results.get('target', 'Unknown')}\n")
                    f.write("="*50 + "\n\n")
                    
                    # Write results
                    f.write("Open Ports:\n")
                    for item in self.results_tree.get_children():
                        values = self.results_tree.item(item)['values']
                        f.write(f"Port {values[0]}: {values[1]} - {values[2]} {values[3]}\n")
                    
                    f.write("\nVulnerabilities:\n")
                    f.write(self.vuln_text.get(1.0, tk.END))
                    
                messagebox.showinfo("Success", f"Report saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {str(e)}")
    
    def export_json(self):
        if not self.scan_results:
            messagebox.showwarning("Warning", "No scan results to export")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.scan_results, f, indent=2)
                messagebox.showinfo("Success", f"Results exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")
    
    def go_back(self):
        self.window.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()
    scanner = PortScanner(root)
    root.mainloop()
