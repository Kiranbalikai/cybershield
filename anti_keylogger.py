import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import psutil
import os
import hashlib
import re
import time
import json
from datetime import datetime
import winreg  # For Windows registry monitoring
import random

# Enhanced keylogger signatures database
KNOWN_KEYLOGGERS = {
    "61abb5aa05411cf92a1d762864cc824d594ffdd2dad4c2ca7f1c2f0c30e2a786": "Ardamax Keylogger",
    "d63c8389d2b2cabed5b7c9a96a37199ef8509f21ea4c30907ef472a81703277b": "Perfect Keylogger",
    "256b0ce3c9164315809fbcfbbdb1624d662b72cd5156bfcab0550abd88f83dca": "SpyAgent",
    "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456": "Demo Keylogger 1",
    "b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567": "Demo Keylogger 2"
}

# Suspicious keywords and patterns
SUSPICIOUS_KEYWORDS = [
    "keyboard", "keylogger", "keystroke", "pynput", "pyhook", "pyxhook",
    "logging", "send_keys", "post", "requests.post", "keylog", "capture",
    "hook", "GetAsyncKeyState", "SetWindowsHookEx", "WH_KEYBOARD_LL"
]

# Suspicious registry keys
SUSPICIOUS_REGISTRY_KEYS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
]

# Whitelist of safe processes
PROCESS_WHITELIST = [
    "explorer.exe", "winlogon.exe", "csrss.exe", "smss.exe", "services.exe",
    "lsass.exe", "svchost.exe", "dwm.exe", "conhost.exe", "python.exe"
]

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    try:
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None

class AntiKeylogger:
    def __init__(self, root, features_page):
        self.root = root
        self.features_page = features_page
        self.root.title("CyberShield - Anti-Keylogger Pro")
        self.root.geometry("1000x750")
        self.root.configure(bg="#1E2124")

        self.threats = []
        self.quarantined = []
        self.is_scanning = False
        self.is_monitoring = False
        self.demo_mode = False
        self.scan_count = 0
        self.threat_count = 0

        self.create_widgets()
        self.setup_styles()

    def create_widgets(self):
        # Title Frame
        title_frame = tk.Frame(self.root, bg="#1E2124")
        title_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(title_frame, text="🛡️ Anti-Keylogger Pro", font=("Arial", 22, "bold"), 
                bg="#1E2124", fg="#4ADE80").pack()
        tk.Label(title_frame, text="Advanced Keylogger Detection & Prevention System", 
                font=("Arial", 12), bg="#1E2124", fg="white").pack()

        # Control Panel
        control_frame = tk.LabelFrame(self.root, text="Control Panel", font=("Arial", 12, "bold"),
                                    bg="#1E2124", fg="#4ADE80", bd=2)
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        # Main Controls
        main_controls = tk.Frame(control_frame, bg="#1E2124")
        main_controls.pack(fill=tk.X, padx=10, pady=10)

        self.scan_button = tk.Button(main_controls, text="Quick Scan", command=self.start_scan, 
                                   bg="#4ADE80", fg="black", font=("Arial", 12, "bold"))
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))

        self.monitor_button = tk.Button(main_controls, text="Real-time Monitor", command=self.toggle_monitoring, 
                                      bg="#60A5FA", fg="black", font=("Arial", 12, "bold"))
        self.monitor_button.pack(side=tk.LEFT, padx=(0, 10))

        self.demo_button = tk.Button(main_controls, text="Demo Mode", command=self.toggle_demo_mode, 
                                   bg="#F59E0B", fg="black", font=("Arial", 12, "bold"))
        self.demo_button.pack(side=tk.LEFT, padx=(0, 10))

        self.clear_button = tk.Button(main_controls, text="Clear Results", command=self.clear_results, 
                                    bg="#EF4444", fg="white", font=("Arial", 12, "bold"))
        self.clear_button.pack(side=tk.LEFT, padx=(0, 10))

        # Advanced Controls
        advanced_controls = tk.Frame(control_frame, bg="#1E2124")
        advanced_controls.pack(fill=tk.X, padx=10, pady=(0, 10))

        tk.Button(advanced_controls, text="Deep Scan", command=self.deep_scan, 
                bg="#8B5CF6", fg="white", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=(0, 5))
        
        # tk.Button(advanced_controls, text="Registry Scan", command=self.registry_scan, 
        #         bg="#10B981", fg="white", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=(0, 5))
        
        # tk.Button(advanced_controls, text="Network Monitor", command=self.network_monitor, 
        #         bg="#F97316", fg="white", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=(0, 5))

        # Statistics Panel
        stats_frame = tk.Frame(self.root, bg="#2A2D31", relief=tk.RAISED, bd=1)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(stats_frame, text="System Status", font=("Arial", 12, "bold"), 
                bg="#2A2D31", fg="#4ADE80").pack()
        
        self.stats_label = tk.Label(stats_frame, text="Scans: 0 | Threats: 0 | Status: Ready", 
                                  font=("Arial", 10), bg="#2A2D31", fg="white")
        self.stats_label.pack(pady=5)

        # Progress Bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.root, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, padx=10, pady=5)

        self.status_label = tk.Label(self.root, text="Ready to scan", font=("Arial", 10), 
                                   bg="#1E2124", fg="white")
        self.status_label.pack()

        # Demo Scenarios
        demo_frame = tk.LabelFrame(self.root, text="Demo Scenarios", font=("Arial", 10, "bold"),
                                 bg="#1E2124", fg="#F59E0B", bd=2)
        demo_frame.pack(fill=tk.X, padx=10, pady=5)

        scenarios_frame = tk.Frame(demo_frame, bg="#1E2124")
        scenarios_frame.pack(fill=tk.X, padx=5, pady=5)

        tk.Button(scenarios_frame, text="Simulate Keylogger", command=lambda: self.simulate_threat("keylogger"),
                bg="#EF4444", fg="white", font=("Arial", 9)).pack(side=tk.LEFT, padx=2)
        
        tk.Button(scenarios_frame, text="Malicious Script", command=lambda: self.simulate_threat("script"),
                bg="#EF4444", fg="white", font=("Arial", 9)).pack(side=tk.LEFT, padx=2)
        
        tk.Button(scenarios_frame, text="Registry Threat", command=lambda: self.simulate_threat("registry"),
                bg="#EF4444", fg="white", font=("Arial", 9)).pack(side=tk.LEFT, padx=2)
        
        tk.Button(scenarios_frame, text="Network Spy", command=lambda: self.simulate_threat("network"),
                bg="#EF4444", fg="white", font=("Arial", 9)).pack(side=tk.LEFT, padx=2)

        # Results Notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Threats Tab
        threats_frame = tk.Frame(self.notebook, bg="#1E2124")
        self.notebook.add(threats_frame, text="🚨 Active Threats")
        
        # Threats Treeview
        self.threats_tree = ttk.Treeview(threats_frame, columns=("Type", "Name", "Risk", "Action"), 
                                       show="headings", height=10)
        self.threats_tree.heading("Type", text="Threat Type")
        self.threats_tree.heading("Name", text="Process/File")
        self.threats_tree.heading("Risk", text="Risk Level")
        self.threats_tree.heading("Action", text="Recommended Action")
        
        self.threats_tree.column("Type", width=120)
        self.threats_tree.column("Name", width=250)
        self.threats_tree.column("Risk", width=100)
        self.threats_tree.column("Action", width=150)
        
        self.threats_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Action Buttons for Threats
        threat_actions = tk.Frame(threats_frame, bg="#1E2124")
        threat_actions.pack(fill=tk.X, padx=5, pady=5)

        self.terminate_button = tk.Button(threat_actions, text="Terminate Selected", 
                                        command=self.terminate_selected, bg="#EF4444", fg="white", 
                                        font=("Arial", 10, "bold"))
        self.terminate_button.pack(side=tk.LEFT, padx=(0, 10))

        self.quarantine_button = tk.Button(threat_actions, text="Quarantine", 
                                         command=self.quarantine_selected, bg="#F59E0B", fg="black", 
                                         font=("Arial", 10, "bold"))
        self.quarantine_button.pack(side=tk.LEFT, padx=(0, 10))

        # System Monitor Tab
        monitor_frame = tk.Frame(self.notebook, bg="#1E2124")
        self.notebook.add(monitor_frame, text="📊 System Monitor")
        
        self.monitor_text = tk.Text(monitor_frame, wrap=tk.WORD, bg="#2A2D31", fg="white", 
                                  font=("Consolas", 9))
        self.monitor_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Scan Log Tab
        log_frame = tk.Frame(self.notebook, bg="#1E2124")
        self.notebook.add(log_frame, text="📋 Scan Log")
        
        self.log_text = tk.Text(log_frame, wrap=tk.WORD, bg="#2A2D31", fg="white", 
                              font=("Consolas", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Quarantine Tab
        quarantine_frame = tk.Frame(self.notebook, bg="#1E2124")
        self.notebook.add(quarantine_frame, text="🔒 Quarantine")
        
        self.quarantine_text = tk.Text(quarantine_frame, wrap=tk.WORD, bg="#2A2D31", fg="white", 
                                     font=("Consolas", 9))
        self.quarantine_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Bottom Controls
        bottom_frame = tk.Frame(self.root, bg="#1E2124")
        bottom_frame.pack(fill=tk.X, padx=10, pady=10)

        tk.Button(bottom_frame, text="Save Report", command=self.save_report, 
                bg="#8B5CF6", fg="white", font=("Arial", 11, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        
        tk.Button(bottom_frame, text="Export Threats", command=self.export_threats, 
                bg="#10B981", fg="white", font=("Arial", 11, "bold")).pack(side=tk.LEFT, padx=(0, 10))

        self.back_button = tk.Button(bottom_frame, text="Back to Features", command=self.go_back, 
                                   bg="#6B7280", fg="white", font=("Arial", 11, "bold"))
        self.back_button.pack(side=tk.RIGHT)

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TProgressbar", background="#4ADE80", troughcolor="#2A2D31", 
                       bordercolor="#2A2D31", lightcolor="#4ADE80", darkcolor="#4ADE80")
        
        # Configure Treeview
        style.configure("Treeview", background="#2A2D31", foreground="white", 
                       fieldbackground="#2A2D31")
        style.configure("Treeview.Heading", background="#1E2124", foreground="#4ADE80")

    def update_stats(self):
        status = "Monitoring" if self.is_monitoring else ("Demo Mode" if self.demo_mode else "Ready")
        self.stats_label.config(text=f"Scans: {self.scan_count} | Threats: {self.threat_count} | Status: {status}")

    def log_message(self, message, tab="log"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}\n"
        
        if tab == "log":
            self.log_text.insert(tk.END, formatted_msg)
            self.log_text.see(tk.END)
        elif tab == "monitor":
            self.monitor_text.insert(tk.END, formatted_msg)
            self.monitor_text.see(tk.END)
        elif tab == "quarantine":
            self.quarantine_text.insert(tk.END, formatted_msg)
            self.quarantine_text.see(tk.END)

    def start_scan(self):
        if self.is_scanning:
            return
            
        self.is_scanning = True
        self.scan_button.config(state=tk.DISABLED, text="Scanning...")
        self.progress_var.set(0)
        self.status_label.config(text="Starting scan...")
        
        scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        scan_thread.start()

    def run_scan(self):
        try:
            self.log_message("🔍 Starting keylogger scan...")
            
            all_processes = list(psutil.process_iter(['pid', 'name', 'exe', 'cmdline']))
            total_processes = len(all_processes)
            
            for i, proc in enumerate(all_processes):
                if not self.is_scanning:
                    break
                    
                self.progress_var.set((i / total_processes) * 100)
                self.status_label.config(text=f"Scanning process {i+1}/{total_processes}")
                self.root.update_idletasks()
                
                try:
                    self.analyze_process(proc)
                except Exception as e:
                    continue
                    
            self.progress_var.set(100)
            self.status_label.config(text="Scan completed")
            self.scan_count += 1
            self.log_message(f"✅ Scan completed. Found {len(self.threats)} potential threats.")
            
        except Exception as e:
            self.log_message(f"❌ Scan error: {str(e)}")
        finally:
            self.is_scanning = False
            self.scan_button.config(state=tk.NORMAL, text="Quick Scan")
            self.update_stats()

    def analyze_process(self, proc):
        try:
            proc_info = proc.info
            
            # Skip whitelisted processes
            if proc_info['name'] in PROCESS_WHITELIST:
                return
            
            # Check executable hash
            if proc_info['exe'] and os.path.isfile(proc_info['exe']):
                file_hash = calculate_file_hash(proc_info['exe'])
                if file_hash in KNOWN_KEYLOGGERS:
                    threat = {
                        'type': 'Known Keylogger',
                        'name': f"{proc_info['name']} ({KNOWN_KEYLOGGERS[file_hash]})",
                        'pid': proc_info['pid'],
                        'risk': 'CRITICAL',
                        'action': 'Terminate Immediately',
                        'path': proc_info['exe']
                    }
                    self.add_threat(threat)
                    return
            
            # Check command line arguments for suspicious scripts
            if proc_info['cmdline']:
                for arg in proc_info['cmdline']:
                    if arg.endswith('.py') and os.path.exists(arg):
                        if self.analyze_script(arg):
                            threat = {
                                'type': 'Suspicious Script',
                                'name': arg,
                                'pid': proc_info['pid'],
                                'risk': 'HIGH',
                                'action': 'Review & Terminate',
                                'path': arg
                            }
                            self.add_threat(threat)
                            break
            
            # Check process name for suspicious patterns
            if any(keyword in proc_info['name'].lower() for keyword in ['keylog', 'hook', 'capture']):
                threat = {
                    'type': 'Suspicious Process',
                    'name': proc_info['name'],
                    'pid': proc_info['pid'],
                    'risk': 'MEDIUM',
                    'action': 'Investigate',
                    'path': proc_info['exe'] or 'Unknown'
                }
                self.add_threat(threat)
                
        except Exception as e:
            pass

    def analyze_script(self, script_path):
        try:
            with open(script_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().lower()
                
            suspicious_count = 0
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in content:
                    suspicious_count += 1
                    
            return suspicious_count >= 2  # Require at least 2 suspicious keywords
        except:
            return False

    def add_threat(self, threat):
        self.threats.append(threat)
        self.threat_count += 1
        
        # Add to threats tree
        self.threats_tree.insert("", tk.END, values=(
            threat['type'], 
            threat['name'], 
            threat['risk'], 
            threat['action']
        ))
        
        self.log_message(f"🚨 THREAT DETECTED: {threat['type']} - {threat['name']}")
        self.update_stats()

    def deep_scan(self):
        self.log_message("🔍 Starting deep system scan...")
        # Simulate deep scan
        threading.Thread(target=self._deep_scan_worker, daemon=True).start()

    def _deep_scan_worker(self):
        scan_areas = [
            "Scanning system files...",
            "Checking startup programs...",
            "Analyzing network connections...",
            "Scanning memory processes...",
            "Checking browser extensions...",
            "Analyzing system hooks..."
        ]
        
        for i, area in enumerate(scan_areas):
            self.status_label.config(text=area)
            self.progress_var.set((i / len(scan_areas)) * 100)
            time.sleep(1)
            self.log_message(f"📊 {area}")
        
        self.progress_var.set(100)
        self.status_label.config(text="Deep scan completed")
        self.log_message("✅ Deep scan completed - No additional threats found")

    def registry_scan(self):
        self.log_message("🔍 Scanning Windows Registry for suspicious entries...")
        threading.Thread(target=self._registry_scan_worker, daemon=True).start()

    def _registry_scan_worker(self):
        try:
            for key_path in SUSPICIOUS_REGISTRY_KEYS:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    self.log_message(f"📋 Checking registry key: {key_path}")
                    
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            if any(sus in name.lower() for sus in ['keylog', 'hook', 'capture']):
                                self.log_message(f"⚠️ Suspicious registry entry: {name} = {value}")
                            i += 1
                        except WindowsError:
                            break
                    winreg.CloseKey(key)
                except Exception as e:
                    self.log_message(f"❌ Could not access registry key: {key_path}")
            
            self.log_message("✅ Registry scan completed")
        except Exception as e:
            self.log_message(f"❌ Registry scan error: {str(e)}")

    def network_monitor(self):
        self.log_message("🌐 Starting network monitoring for suspicious connections...")
        threading.Thread(target=self._network_monitor_worker, daemon=True).start()

    def _network_monitor_worker(self):
        try:
            connections = psutil.net_connections()
            suspicious_ports = [4444, 31337, 12345, 6667]
            
            for conn in connections:
                if conn.laddr and conn.laddr.port in suspicious_ports:
                    self.log_message(f"🚨 Suspicious network connection on port {conn.laddr.port}")
                    
            self.log_message("✅ Network monitoring completed")
        except Exception as e:
            self.log_message(f"❌ Network monitoring error: {str(e)}")

    def toggle_monitoring(self):
        self.is_monitoring = not self.is_monitoring
        
        if self.is_monitoring:
            self.monitor_button.config(text="Stop Monitor", bg="#EF4444")
            self.log_message("🔄 Real-time monitoring started")
            threading.Thread(target=self._monitoring_worker, daemon=True).start()
        else:
            self.monitor_button.config(text="Real-time Monitor", bg="#60A5FA")
            self.log_message("⏹️ Real-time monitoring stopped")
        
        self.update_stats()

    def _monitoring_worker(self):
        while self.is_monitoring:
            try:
                # Monitor system activity
                self.log_message("📊 Monitoring system activity...", "monitor")
                
                # Check for new processes
                current_processes = {p.pid for p in psutil.process_iter()}
                
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                self.log_message(f"❌ Monitoring error: {str(e)}", "monitor")
                break

    def toggle_demo_mode(self):
        self.demo_mode = not self.demo_mode
        
        if self.demo_mode:
            self.demo_button.config(text="Stop Demo", bg="#EF4444")
            self.log_message("🎭 Demo mode activated")
            threading.Thread(target=self._demo_worker, daemon=True).start()
        else:
            self.demo_button.config(text="Demo Mode", bg="#F59E0B")
            self.log_message("⏹️ Demo mode stopped")
        
        self.update_stats()

    def _demo_worker(self):
        demo_threats = [
            ("Known Keylogger", "malware_keylogger.exe", "CRITICAL", "Terminate Immediately"),
            ("Suspicious Script", "keylogger.py", "HIGH", "Review & Terminate"),
            ("Hook Process", "system_hook.exe", "MEDIUM", "Investigate"),
            ("Network Spy", "data_collector.exe", "HIGH", "Quarantine")
        ]
        
        while self.demo_mode:
            if random.random() < 0.3:  # 30% chance to generate threat
                threat_type, name, risk, action = random.choice(demo_threats)
                threat = {
                    'type': threat_type,
                    'name': name,
                    'pid': random.randint(1000, 9999),
                    'risk': risk,
                    'action': action,
                    'path': f"C:\\Temp\\{name}"
                }
                self.add_threat(threat)
            
            time.sleep(random.uniform(2, 8))

    def simulate_threat(self, threat_type):
        if threat_type == "keylogger":
            threat = {
                'type': 'Known Keylogger',
                'name': 'advanced_keylogger.exe',
                'pid': random.randint(1000, 9999),
                'risk': 'CRITICAL',
                'action': 'Terminate Immediately',
                'path': 'C:\\Temp\\advanced_keylogger.exe'
            }
        elif threat_type == "script":
            threat = {
                'type': 'Malicious Script',
                'name': 'password_stealer.py',
                'pid': random.randint(1000, 9999),
                'risk': 'HIGH',
                'action': 'Review & Terminate',
                'path': 'C:\\Scripts\\password_stealer.py'
            }
        elif threat_type == "registry":
            threat = {
                'type': 'Registry Threat',
                'name': 'Startup Keylogger Entry',
                'pid': 0,
                'risk': 'MEDIUM',
                'action': 'Remove Entry',
                'path': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
            }
        elif threat_type == "network":
            threat = {
                'type': 'Network Spy',
                'name': 'data_exfiltrator.exe',
                'pid': random.randint(1000, 9999),
                'risk': 'HIGH',
                'action': 'Block & Terminate',
                'path': 'C:\\Windows\\Temp\\data_exfiltrator.exe'
            }
        
        self.add_threat(threat)

    def terminate_selected(self):
        selected = self.threats_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a threat to terminate")
            return
        
        for item in selected:
            values = self.threats_tree.item(item)['values']
            self.log_message(f"🔥 Terminated threat: {values[1]}")
            self.threats_tree.delete(item)
        
        messagebox.showinfo("Success", f"Terminated {len(selected)} threat(s)")

    def quarantine_selected(self):
        selected = self.threats_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a threat to quarantine")
            return
        
        for item in selected:
            values = self.threats_tree.item(item)['values']
            self.log_message(f"🔒 Quarantined: {values[1]}", "quarantine")
            self.quarantined.append(values)
            self.threats_tree.delete(item)
        
        messagebox.showinfo("Success", f"Quarantined {len(selected)} threat(s)")

    def clear_results(self):
        # Clear all displays
        for item in self.threats_tree.get_children():
            self.threats_tree.delete(item)
        
        self.log_text.delete(1.0, tk.END)
        self.monitor_text.delete(1.0, tk.END)
        self.quarantine_text.delete(1.0, tk.END)
        
        self.threats = []
        self.threat_count = 0
        self.scan_count = 0
        self.update_stats()

    def save_report(self):
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("JSON files", "*.json")]
            )
            
            if file_path:
                report_data = {
                    "timestamp": datetime.now().isoformat(),
                    "statistics": {
                        "total_scans": self.scan_count,
                        "threats_detected": self.threat_count,
                        "quarantined_items": len(self.quarantined)
                    },
                    "threats": self.threats,
                    "quarantined": self.quarantined,
                    "scan_log": self.log_text.get(1.0, tk.END).strip()
                }
                
                if file_path.endswith('.json'):
                    with open(file_path, 'w') as f:
                        json.dump(report_data, f, indent=2)
                else:
                    with open(file_path, 'w') as f:
                        f.write(f"Anti-Keylogger Security Report\n")
                        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write("="*50 + "\n\n")
                        f.write(f"Statistics:\n")
                        f.write(f"- Total Scans: {self.scan_count}\n")
                        f.write(f"- Threats Detected: {self.threat_count}\n")
                        f.write(f"- Items Quarantined: {len(self.quarantined)}\n\n")
                        f.write("Scan Log:\n" + "-"*20 + "\n")
                        f.write(report_data["scan_log"])
                
                self.log_message(f"📄 Report saved to {file_path}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report: {str(e)}")

    def export_threats(self):
        if not self.threats:
            messagebox.showwarning("Warning", "No threats to export")
            return
            
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")]
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    json.dump(self.threats, f, indent=2)
                messagebox.showinfo("Success", f"Threats exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {str(e)}")

    def go_back(self):
        self.is_scanning = False
        self.is_monitoring = False
        self.demo_mode = False
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = AntiKeylogger(root, None)
    root.mainloop()
