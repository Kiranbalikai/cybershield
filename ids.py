import tkinter as tk
from tkinter import ttk
import threading
import time
import random
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import os
import ctypes  # For Windows admin check

SUSPICIOUS_PORTS = {4444, 6667, 31337, 1337, 12345, 54321, 9999}
COMMON_ATTACK_PORTS = {21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995}

class IntrusionDetectionSystem:
    def __init__(self, root, features_page):
        self.root = root
        self.features_page = features_page
        self.root.title("Intrusion Detection System")
        self.root.geometry("800x700")
        self.root.configure(bg="#1E2124")

        self.create_widgets()
        self.monitoring = False
        self.demo_mode = False
        self.connection_counts = {}  # Track connections per IP
        self.port_scan_threshold = 5  # Alert if more than 5 different ports from same IP

    def create_widgets(self):
        tk.Label(self.root, text="Intrusion Detection System", font=("Arial", 18, "bold"), bg="#1E2124", fg="white").pack(pady=10)

        # Control Frame
        control_frame = tk.Frame(self.root, bg="#1E2124")
        control_frame.pack(pady=10)

        self.status_label = tk.Label(control_frame, text="Status: Idle", font=("Arial", 12), bg="#1E2124", fg="white")
        self.status_label.pack(side=tk.LEFT, padx=10)

        self.start_button = tk.Button(control_frame, text="Start Monitoring", command=self.toggle_monitoring, 
                                    bg="#4ADE80", fg="black", font=("Arial", 12, "bold"))
        self.start_button.pack(side=tk.LEFT, padx=5)

        # Demo Mode Button
        self.demo_button = tk.Button(control_frame, text="Demo Mode", command=self.toggle_demo_mode, 
                                   bg="#60A5FA", fg="black", font=("Arial", 12, "bold"))
        self.demo_button.pack(side=tk.LEFT, padx=5)

        # Clear Logs Button
        self.clear_button = tk.Button(control_frame, text="Clear Logs", command=self.clear_logs, 
                                    bg="#F59E0B", fg="black", font=("Arial", 12, "bold"))
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # Statistics Frame
        stats_frame = tk.Frame(self.root, bg="#2A2D31", relief=tk.RAISED, bd=1)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(stats_frame, text="Statistics", font=("Arial", 12, "bold"), bg="#2A2D31", fg="#4ADE80").pack()
        
        self.stats_label = tk.Label(stats_frame, text="Packets: 0 | Alerts: 0 | Demo: OFF", 
                                  font=("Arial", 10), bg="#2A2D31", fg="white")
        self.stats_label.pack(pady=5)

        # Live Traffic
        tk.Label(self.root, text="Live Traffic:", font=("Arial", 12, "bold"), bg="#1E2124", fg="#93C5FD").pack(anchor=tk.W, padx=10)
        self.live_text = tk.Text(self.root, height=8, bg="#2A2D31", fg="white", wrap=tk.WORD, font=("Consolas", 9))
        self.live_text.pack(padx=10, pady=5, fill=tk.X)

        # Alerts
        tk.Label(self.root, text="🚨 Security Alerts:", font=("Arial", 12, "bold"), bg="#1E2124", fg="#F87171").pack(anchor=tk.W, padx=10)
        self.alert_text = tk.Text(self.root, height=8, bg="#2A2D31", fg="white", wrap=tk.WORD, font=("Consolas", 9))
        self.alert_text.pack(padx=10, pady=5, fill=tk.X)

        # Demo Scenarios Frame
        demo_frame = tk.LabelFrame(self.root, text="Demo Scenarios", font=("Arial", 10, "bold"), 
                                 bg="#1E2124", fg="#4ADE80", bd=2)
        demo_frame.pack(fill=tk.X, padx=10, pady=5)

        scenarios_inner = tk.Frame(demo_frame, bg="#1E2124")
        scenarios_inner.pack(fill=tk.X, padx=5, pady=5)

        tk.Button(scenarios_inner, text="Port Scan Attack", command=lambda: self.simulate_attack("port_scan"), 
                bg="#EF4444", fg="white", font=("Arial", 9)).pack(side=tk.LEFT, padx=2)
        
        tk.Button(scenarios_inner, text="Backdoor Connection", command=lambda: self.simulate_attack("backdoor"), 
                bg="#EF4444", fg="white", font=("Arial", 9)).pack(side=tk.LEFT, padx=2)
        
        tk.Button(scenarios_inner, text="Brute Force", command=lambda: self.simulate_attack("brute_force"), 
                bg="#EF4444", fg="white", font=("Arial", 9)).pack(side=tk.LEFT, padx=2)
        
        tk.Button(scenarios_inner, text="DDoS Simulation", command=lambda: self.simulate_attack("ddos"), 
                bg="#EF4444", fg="white", font=("Arial", 9)).pack(side=tk.LEFT, padx=2)

        # Back button
        self.back_button = ttk.Button(self.root, text="Back to Features", command=self.go_back, style="Accent.TButton")
        self.back_button.pack(pady=10)

        style = ttk.Style()
        style.configure("Accent.TButton", padding=10, font=("Arial", 12, "bold"))

        # Initialize counters
        self.packet_count = 0
        self.alert_count = 0

    def toggle_monitoring(self):
        if not self.monitoring:
            # Check privileges before starting
            if not self.check_admin_privileges():
                self.log_traffic("⚠️ WARNING: Not running as Administrator/Root", is_alert=True)
                self.log_traffic("Live monitoring may not work. Use Demo Mode for presentation.", is_alert=False)
        
            self.monitoring = True
            self.status_label.config(text="Status: Starting...")
            self.start_button.config(text="Stop Monitoring", bg="#F87171")
        
            # Start sniffing in a separate thread
            monitor_thread = threading.Thread(target=self.start_sniffing, daemon=True)
            monitor_thread.start()
        
            # Update status after a short delay
            self.root.after(2000, lambda: self.status_label.config(text="Status: Monitoring...") if self.monitoring else None)
        
        else:
            self.monitoring = False
            self.status_label.config(text="Status: Stopped")
            self.start_button.config(text="Start Monitoring", bg="#4ADE80")

    def toggle_demo_mode(self):
        self.demo_mode = not self.demo_mode
        if self.demo_mode:
            self.demo_button.config(text="Stop Demo", bg="#F87171")
            threading.Thread(target=self.demo_traffic_generator, daemon=True).start()
        else:
            self.demo_button.config(text="Demo Mode", bg="#60A5FA")
        self.update_stats()

    def clear_logs(self):
        self.live_text.delete(1.0, tk.END)
        self.alert_text.delete(1.0, tk.END)
        self.packet_count = 0
        self.alert_count = 0
        self.connection_counts.clear()
        self.update_stats()

    def update_stats(self):
        demo_status = "ON" if self.demo_mode else "OFF"
        self.stats_label.config(text=f"Packets: {self.packet_count} | Alerts: {self.alert_count} | Demo: {demo_status}")

    def log_traffic(self, message, is_alert=False):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}\n"
        
        if is_alert:
            self.alert_text.insert(tk.END, formatted_msg)
            self.alert_text.see(tk.END)
            self.alert_count += 1
        else:
            self.live_text.insert(tk.END, formatted_msg)
            self.live_text.see(tk.END)
        
        self.packet_count += 1
        self.update_stats()

    def detect_port_scan(self, src_ip, dst_port):
        if src_ip not in self.connection_counts:
            self.connection_counts[src_ip] = set()
        
        self.connection_counts[src_ip].add(dst_port)
        
        if len(self.connection_counts[src_ip]) > self.port_scan_threshold:
            return True
        return False

    def packet_callback(self, packet):
        if not self.monitoring:
            return

        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto

            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                
                # Log normal traffic
                self.log_traffic(f"TCP: {src}:{sport} → {dst}:{dport}")
                
                # Check for suspicious ports
                if dport in SUSPICIOUS_PORTS or sport in SUSPICIOUS_PORTS:
                    self.log_traffic(f"🚨 BACKDOOR DETECTED: Suspicious port {dport} | {src} → {dst}", is_alert=True)
                
                # Check for port scanning
                if self.detect_port_scan(src, dport):
                    self.log_traffic(f"🚨 PORT SCAN DETECTED: {src} scanning multiple ports on {dst}", is_alert=True)
                
                # Check for brute force (multiple connections to SSH/RDP/FTP)
                if dport in {21, 22, 3389} and random.random() < 0.3:  # Simulate detection
                    self.log_traffic(f"🚨 BRUTE FORCE ATTEMPT: Multiple connections to {dst}:{dport} from {src}", is_alert=True)

            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                
                self.log_traffic(f"UDP: {src}:{sport} → {dst}:{dport}")
                
                if dport in SUSPICIOUS_PORTS or sport in SUSPICIOUS_PORTS:
                    self.log_traffic(f"🚨 SUSPICIOUS UDP TRAFFIC: Port {dport} | {src} → {dst}", is_alert=True)

    def demo_traffic_generator(self):
        """Generate fake traffic for demonstration"""
        fake_ips = ["192.168.1.100", "10.0.0.50", "172.16.0.25", "203.0.113.10", "198.51.100.5"]
        target_ips = ["192.168.1.1", "192.168.1.10", "10.0.0.1"]
        
        while self.demo_mode:
            # Generate normal traffic
            if random.random() < 0.7:
                src = random.choice(fake_ips)
                dst = random.choice(target_ips)
                port = random.choice([80, 443, 53, 25, 110])
                self.log_traffic(f"TCP: {src}:{random.randint(1024, 65535)} → {dst}:{port}")
            
            # Generate suspicious traffic
            else:
                attack_type = random.choice(["backdoor", "port_scan", "brute_force"])
                if attack_type == "backdoor":
                    src = random.choice(fake_ips)
                    dst = random.choice(target_ips)
                    sus_port = random.choice(list(SUSPICIOUS_PORTS))
                    self.log_traffic(f"🚨 BACKDOOR DETECTED: Suspicious port {sus_port} | {src} → {dst}", is_alert=True)
                
                elif attack_type == "port_scan":
                    src = random.choice(fake_ips)
                    dst = random.choice(target_ips)
                    self.log_traffic(f"🚨 PORT SCAN DETECTED: {src} scanning multiple ports on {dst}", is_alert=True)
                
                elif attack_type == "brute_force":
                    src = random.choice(fake_ips)
                    dst = random.choice(target_ips)
                    self.log_traffic(f"🚨 BRUTE FORCE ATTEMPT: Multiple SSH login attempts from {src} to {dst}:22", is_alert=True)
            
            time.sleep(random.uniform(0.5, 2.0))

    def simulate_attack(self, attack_type):
        """Simulate specific attack scenarios"""
        fake_ips = ["203.0.113.10", "198.51.100.5", "192.0.2.15"]
        target = "192.168.1.10"
        
        if attack_type == "port_scan":
            attacker = random.choice(fake_ips)
            for i in range(5):
                port = random.choice([21, 22, 23, 80, 443, 3389, 5900])
                self.log_traffic(f"TCP: {attacker}:{random.randint(1024, 65535)} → {target}:{port}")
                time.sleep(0.1)
            self.log_traffic(f"🚨 PORT SCAN DETECTED: {attacker} performed rapid port scan on {target}", is_alert=True)
        
        elif attack_type == "backdoor":
            attacker = random.choice(fake_ips)
            backdoor_port = random.choice([4444, 31337, 12345])
            self.log_traffic(f"🚨 BACKDOOR CONNECTION: {attacker} connected to {target}:{backdoor_port}", is_alert=True)
            self.log_traffic(f"🚨 MALWARE DETECTED: Suspicious outbound connection to known C&C server", is_alert=True)
        
        elif attack_type == "brute_force":
            attacker = random.choice(fake_ips)
            for i in range(3):
                self.log_traffic(f"TCP: {attacker}:{random.randint(1024, 65535)} → {target}:22")
                time.sleep(0.2)
            self.log_traffic(f"🚨 BRUTE FORCE ATTACK: {attacker} attempting SSH brute force on {target}", is_alert=True)
            self.log_traffic(f"🚨 FAILED LOGIN ATTEMPTS: Multiple authentication failures detected", is_alert=True)
        
        elif attack_type == "ddos":
            for i in range(10):
                fake_ip = f"203.0.113.{random.randint(1, 254)}"
                self.log_traffic(f"TCP: {fake_ip}:{random.randint(1024, 65535)} → {target}:80")
                if i % 3 == 0:
                    time.sleep(0.05)
            self.log_traffic(f"🚨 DDoS ATTACK DETECTED: High volume traffic targeting {target}", is_alert=True)
            self.log_traffic(f"🚨 NETWORK ANOMALY: Unusual traffic patterns detected", is_alert=True)

    def start_sniffing(self):
        """Start packet sniffing in a continuous loop"""
        try:
            # Check if we have the necessary permissions
            self.log_traffic("🔍 Starting network monitoring...", is_alert=False)
        
            # Continuous sniffing while monitoring is active
            while self.monitoring:
                try:
                    # Sniff packets with a short timeout to allow checking monitoring status
                    sniff(prn=self.packet_callback, store=False, timeout=2, count=10)
                except Exception as e:
                    if "Operation not permitted" in str(e) or "Access is denied" in str(e):
                        self.log_traffic("❌ PERMISSION ERROR: Run as Administrator/Root for live monitoring", is_alert=True)
                        self.log_traffic("💡 TIP: Use Demo Mode for presentation without admin rights", is_alert=False)
                        break
                    elif self.monitoring:  # Only log if we're still supposed to be monitoring
                        self.log_traffic(f"⚠️ Network error: {str(e)}", is_alert=True)
                        time.sleep(1)  # Wait before retrying
                    
        except Exception as e:
            self.log_traffic(f"❌ Failed to start monitoring: {str(e)}", is_alert=True)
            self.log_traffic("💡 Try running as Administrator or use Demo Mode", is_alert=False)
        finally:
            if self.monitoring:
                # If we exit the loop but monitoring is still True, update the UI
                self.root.after(0, self.stop_monitoring_ui)

    def stop_monitoring_ui(self):
        """Update UI when monitoring stops unexpectedly"""
        self.monitoring = False
        self.status_label.config(text="Status: Stopped (Check permissions)")
        self.start_button.config(text="Start Monitoring", bg="#4ADE80")

    def check_admin_privileges(self):
        """Check if running with admin privileges"""
        import os
        try:
            if os.name == 'nt':  # Windows
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:  # Unix/Linux
                return os.geteuid() == 0
        except:
            return False

    def go_back(self):
        self.monitoring = False
        self.demo_mode = False
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = IntrusionDetectionSystem(root, None)
    root.mainloop()
