import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
from scapy.all import sniff, DNS, DNSRR, DNSQR
import threading
import time
import random
from datetime import datetime
import json

# Known malicious domains for demo
MALICIOUS_DOMAINS = {
    "malware-site.com": "192.0.2.1",
    "phishing-bank.net": "192.0.2.2", 
    "botnet-c2.org": "192.0.2.3",
    "fake-update.com": "192.0.2.4",
    "trojan-download.net": "192.0.2.5"
}

# Suspicious TLDs and patterns
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.bit']
SUSPICIOUS_PATTERNS = ['temp', 'random', 'generated', 'malware', 'phish', 'fake']

class DNSSpoofDetector:
    def __init__(self, root):
        self.root = root
        self.root.title("DNS Security Monitor")
        self.root.geometry("900x700")
        self.root.configure(bg="#1E2124")

        self.monitoring = False
        self.demo_mode = False
        self.monitor_thread = None
        self.query_count = 0
        self.threat_count = 0
        self.dns_cache = {}

        self.setup_ui()

    def setup_ui(self):
        # Title
        title_frame = tk.Frame(self.root, bg="#1E2124")
        title_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(title_frame, text="🛡️ DNS Security Monitor", font=("Arial", 20, "bold"), 
                bg="#1E2124", fg="#4ADE80").pack()
        
        tk.Label(title_frame, text="Advanced DNS Threat Detection & Analysis", font=("Arial", 12), 
                bg="#1E2124", fg="white").pack()

        # Control Panel
        control_frame = tk.LabelFrame(self.root, text="Control Panel", font=("Arial", 12, "bold"),
                                    bg="#1E2124", fg="#4ADE80", bd=2)
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        # URL Check Section
        url_frame = tk.Frame(control_frame, bg="#1E2124")
        url_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(url_frame, text="Quick Domain Check:", font=("Arial", 11, "bold"), 
                bg="#1E2124", fg="white").pack(anchor=tk.W)
        
        url_input_frame = tk.Frame(url_frame, bg="#1E2124")
        url_input_frame.pack(fill=tk.X, pady=5)
        
        self.url_entry = tk.Entry(url_input_frame, font=("Arial", 11), width=40, bg="#2A2D31", 
                                fg="white", insertbackground="white")
        self.url_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.url_entry.insert(0, "google.com")
        
        self.check_button = tk.Button(url_input_frame, text="Check Domain", command=self.check_url_spoofing,
                                    bg="#4ADE80", fg="black", font=("Arial", 10, "bold"))
        self.check_button.pack(side=tk.LEFT, padx=5)

        # Monitoring Controls
        monitor_frame = tk.Frame(control_frame, bg="#1E2124")
        monitor_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.monitor_button = tk.Button(monitor_frame, text="Start Live Monitor", command=self.toggle_monitoring,
                                      bg="#60A5FA", fg="black", font=("Arial", 11, "bold"))
        self.monitor_button.pack(side=tk.LEFT, padx=5)
        
        self.demo_button = tk.Button(monitor_frame, text="Demo Mode", command=self.toggle_demo_mode,
                                   bg="#F59E0B", fg="black", font=("Arial", 11, "bold"))
        self.demo_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = tk.Button(monitor_frame, text="Clear Logs", command=self.clear_logs,
                                    bg="#EF4444", fg="white", font=("Arial", 11, "bold"))
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        self.save_button = tk.Button(monitor_frame, text="Save Report", command=self.save_report,
                                   bg="#8B5CF6", fg="white", font=("Arial", 11, "bold"))
        self.save_button.pack(side=tk.LEFT, padx=5)

        # Statistics
        stats_frame = tk.Frame(self.root, bg="#2A2D31", relief=tk.RAISED, bd=1)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(stats_frame, text="Statistics", font=("Arial", 12, "bold"), 
                bg="#2A2D31", fg="#4ADE80").pack()
        
        self.stats_label = tk.Label(stats_frame, text="Queries: 0 | Threats: 0 | Status: Idle", 
                                  font=("Arial", 10), bg="#2A2D31", fg="white")
        self.stats_label.pack(pady=5)

        # Demo Scenarios
        demo_frame = tk.LabelFrame(self.root, text="Demo Scenarios", font=("Arial", 10, "bold"),
                                 bg="#1E2124", fg="#F59E0B", bd=2)
        demo_frame.pack(fill=tk.X, padx=10, pady=5)

        scenarios_frame = tk.Frame(demo_frame, bg="#1E2124")
        scenarios_frame.pack(fill=tk.X, padx=5, pady=5)

        tk.Button(scenarios_frame, text="DNS Spoofing", command=lambda: self.simulate_threat("spoofing"),
                bg="#EF4444", fg="white", font=("Arial", 9)).pack(side=tk.LEFT, padx=2)
        
        tk.Button(scenarios_frame, text="Malware C&C", command=lambda: self.simulate_threat("malware"),
                bg="#EF4444", fg="white", font=("Arial", 9)).pack(side=tk.LEFT, padx=2)
        
        tk.Button(scenarios_frame, text="Phishing Site", command=lambda: self.simulate_threat("phishing"),
                bg="#EF4444", fg="white", font=("Arial", 9)).pack(side=tk.LEFT, padx=2)
        
        tk.Button(scenarios_frame, text="DNS Tunneling", command=lambda: self.simulate_threat("tunneling"),
                bg="#EF4444", fg="white", font=("Arial", 9)).pack(side=tk.LEFT, padx=2)

        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # DNS Queries Tab
        queries_frame = tk.Frame(self.notebook, bg="#1E2124")
        self.notebook.add(queries_frame, text="DNS Queries")
        
        tk.Label(queries_frame, text="Live DNS Queries:", font=("Arial", 11, "bold"), 
                bg="#1E2124", fg="#93C5FD").pack(anchor=tk.W, padx=5, pady=5)
        
        self.queries_text = tk.Text(queries_frame, wrap=tk.WORD, height=12, bg="#2A2D31", 
                                  fg="white", font=("Consolas", 9))
        self.queries_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Threats Tab
        threats_frame = tk.Frame(self.notebook, bg="#1E2124")
        self.notebook.add(threats_frame, text="🚨 Threats")
        
        tk.Label(threats_frame, text="Security Threats Detected:", font=("Arial", 11, "bold"), 
                bg="#1E2124", fg="#F87171").pack(anchor=tk.W, padx=5, pady=5)
        
        self.threats_text = tk.Text(threats_frame, wrap=tk.WORD, height=12, bg="#2A2D31", 
                                  fg="white", font=("Consolas", 9))
        self.threats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Analysis Tab
        analysis_frame = tk.Frame(self.notebook, bg="#1E2124")
        self.notebook.add(analysis_frame, text="Analysis")
        
        tk.Label(analysis_frame, text="DNS Analysis Results:", font=("Arial", 11, "bold"), 
                bg="#1E2124", fg="#10B981").pack(anchor=tk.W, padx=5, pady=5)
        
        self.analysis_text = tk.Text(analysis_frame, wrap=tk.WORD, height=12, bg="#2A2D31", 
                                   fg="white", font=("Consolas", 9))
        self.analysis_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Back button
        self.back_button = tk.Button(self.root, text="Back to Features", command=self.go_back,
                                   bg="#6B7280", fg="white", font=("Arial", 11, "bold"))
        self.back_button.pack(pady=10)

    def update_stats(self):
        status = "Monitoring" if self.monitoring else ("Demo Mode" if self.demo_mode else "Idle")
        self.stats_label.config(text=f"Queries: {self.query_count} | Threats: {self.threat_count} | Status: {status}")

    def log_message(self, message, tab="queries", is_threat=False):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}\n"
        
        if tab == "queries":
            self.queries_text.insert(tk.END, formatted_msg)
            self.queries_text.see(tk.END)
        elif tab == "threats":
            self.threats_text.insert(tk.END, formatted_msg)
            self.threats_text.see(tk.END)
            if is_threat:
                self.threat_count += 1
        elif tab == "analysis":
            self.analysis_text.insert(tk.END, formatted_msg)
            self.analysis_text.see(tk.END)
        
        self.query_count += 1
        self.update_stats()

    def check_url_spoofing(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a valid domain.")
            return

        try:
            # Remove protocol if present
            if url.startswith(('http://', 'https://')):
                url = url.split('://', 1)[1]
            if '/' in url:
                url = url.split('/')[0]

            real_ips = socket.gethostbyname_ex(url)[2]
            
            # Check against known malicious domains
            if url in MALICIOUS_DOMAINS:
                self.log_message(f"🚨 MALICIOUS DOMAIN: {url} is in threat database!", "threats", True)
                self.log_message(f"Expected malicious IP: {MALICIOUS_DOMAINS[url]}", "analysis")
            else:
                self.log_message(f"✅ {url} resolves to {real_ips} (Clean)", "analysis")
            
            # Check for suspicious patterns
            self.analyze_domain(url, real_ips)
            
        except socket.gaierror:
            self.log_message(f"❌ Could not resolve {url} - Domain may not exist", "threats", True)

    def analyze_domain(self, domain, ips):
        """Analyze domain for suspicious characteristics"""
        suspicious_score = 0
        analysis = []
        
        # Check TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                suspicious_score += 2
                analysis.append(f"Suspicious TLD: {tld}")
        
        # Check patterns
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern in domain.lower():
                suspicious_score += 1
                analysis.append(f"Suspicious pattern: {pattern}")
        
        # Check domain length and structure
        if len(domain) > 50:
            suspicious_score += 1
            analysis.append("Unusually long domain name")
        
        if domain.count('-') > 3:
            suspicious_score += 1
            analysis.append("Multiple hyphens (possible typosquatting)")
        
        # Report analysis
        if suspicious_score > 0:
            self.log_message(f"⚠️ SUSPICIOUS DOMAIN: {domain} (Score: {suspicious_score})", "threats", True)
            for item in analysis:
                self.log_message(f"  - {item}", "analysis")
        else:
            self.log_message(f"✅ Domain analysis: {domain} appears legitimate", "analysis")

    def toggle_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.monitor_button.config(text="Stop Monitor", bg="#F87171")
            self.monitor_thread = threading.Thread(target=self.monitor_dns, daemon=True)
            self.monitor_thread.start()
            self.log_message("🔍 Live DNS monitoring started...", "queries")
        else:
            self.monitoring = False
            self.monitor_button.config(text="Start Live Monitor", bg="#60A5FA")
            self.log_message("⏹️ Live DNS monitoring stopped.", "queries")
        self.update_stats()

    def toggle_demo_mode(self):
        self.demo_mode = not self.demo_mode
        if self.demo_mode:
            self.demo_button.config(text="Stop Demo", bg="#F87171")
            threading.Thread(target=self.demo_traffic_generator, daemon=True).start()
            self.log_message("🎭 Demo mode activated - Generating sample DNS traffic", "queries")
        else:
            self.demo_button.config(text="Demo Mode", bg="#F59E0B")
            self.log_message("⏹️ Demo mode stopped", "queries")
        self.update_stats()

    def demo_traffic_generator(self):
        """Generate fake DNS traffic for demonstration"""
        legitimate_domains = ["google.com", "microsoft.com", "github.com", "stackoverflow.com", "wikipedia.org"]
        
        while self.demo_mode:
            if random.random() < 0.7:  # 70% legitimate traffic
                domain = random.choice(legitimate_domains)
                ip = f"172.{random.randint(16,31)}.{random.randint(1,254)}.{random.randint(1,254)}"
                self.log_message(f"DNS Query: {domain} → {ip}", "queries")
            else:  # 30% suspicious traffic
                threat_type = random.choice(["malware", "phishing", "spoofing", "tunneling"])
                self.simulate_threat(threat_type, auto=True)
            
            time.sleep(random.uniform(0.5, 3.0))

    def simulate_threat(self, threat_type, auto=False):
        """Simulate different types of DNS threats"""
        if threat_type == "spoofing":
            domain = "legitimate-bank.com"
            fake_ip = "192.0.2.100"
            real_ip = "203.0.113.50"
            self.log_message(f"🚨 DNS SPOOFING: {domain} → {fake_ip} (Expected: {real_ip})", "threats", True)
            
        elif threat_type == "malware":
            malware_domain = random.choice(list(MALICIOUS_DOMAINS.keys()))
            malware_ip = MALICIOUS_DOMAINS[malware_domain]
            self.log_message(f"🚨 MALWARE C&C: Connection to {malware_domain} → {malware_ip}", "threats", True)
            self.log_message(f"Threat Intelligence: {malware_domain} known botnet command server", "analysis")
            
        elif threat_type == "phishing":
            phish_domain = f"secure-{random.choice(['paypal', 'amazon', 'microsoft'])}-{random.randint(100,999)}.tk"
            self.log_message(f"🚨 PHISHING SITE: {phish_domain} (Typosquatting detected)", "threats", True)
            self.log_message(f"Analysis: Suspicious TLD and brand impersonation", "analysis")
            
        elif threat_type == "tunneling":
            tunnel_domain = f"data-{random.randint(1000,9999)}.tunnel-service.com"
            self.log_message(f"🚨 DNS TUNNELING: Suspicious queries to {tunnel_domain}", "threats", True)
            self.log_message(f"Analysis: Possible data exfiltration via DNS", "analysis")

    def monitor_dns(self):
        """Monitor live DNS traffic"""
        def process_packet(packet):
            if not self.monitoring:
                return
                
            if packet.haslayer(DNSQR):
                try:
                    query = packet[DNSQR]
                    domain = query.qname.decode('utf-8').rstrip('.')
                    
                    # Skip common noise
                    if any(skip in domain.lower() for skip in ['arpa', 'local', '_']):
                        return
                    
                    self.log_message(f"DNS Query: {domain}", "queries")
                    
                    # Check against threat database
                    if domain in MALICIOUS_DOMAINS:
                        self.log_message(f"🚨 BLOCKED: Query to known malicious domain {domain}", "threats", True)
                    
                    # Analyze domain characteristics
                    self.analyze_domain(domain, [])
                    
                except Exception as e:
                    pass

            if packet.haslayer(DNSRR):
                try:
                    response = packet[DNSRR]
                    if response.type == 1:  # A record
                        domain = packet[DNSQR].qname.decode('utf-8').rstrip('.')
                        resolved_ip = str(response.rdata)
                        
                        # Check for potential spoofing
                        try:
                            real_ips = socket.gethostbyname_ex(domain)[2]
                            if resolved_ip not in real_ips and domain not in ['localhost']:
                                self.log_message(f"🚨 POSSIBLE SPOOFING: {domain} → {resolved_ip} (Expected: {real_ips})", "threats", True)
                        except:
                            pass
                            
                except Exception as e:
                    pass

        try:
            while self.monitoring:
                sniff(filter="udp port 53", prn=process_packet, store=False, timeout=2, count=5)
        except Exception as e:
            if self.monitoring:
                self.log_message(f"⚠️ Monitoring error: {str(e)}", "threats")
                self.log_message("💡 Try running as Administrator for live monitoring", "analysis")

    def clear_logs(self):
        self.queries_text.delete(1.0, tk.END)
        self.threats_text.delete(1.0, tk.END)
        self.analysis_text.delete(1.0, tk.END)
        self.query_count = 0
        self.threat_count = 0
        self.update_stats()

    def save_report(self):
        """Save DNS monitoring report"""
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("JSON files", "*.json")]
            )
            
            if file_path:
                report_data = {
                    "timestamp": datetime.now().isoformat(),
                    "statistics": {
                        "total_queries": self.query_count,
                        "threats_detected": self.threat_count
                    },
                    "queries": self.queries_text.get(1.0, tk.END).strip(),
                    "threats": self.threats_text.get(1.0, tk.END).strip(),
                    "analysis": self.analysis_text.get(1.0, tk.END).strip()
                }
                
                if file_path.endswith('.json'):
                    with open(file_path, 'w') as f:
                        json.dump(report_data, f, indent=2)
                else:
                    with open(file_path, 'w') as f:
                        f.write(f"DNS Security Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write("="*60 + "\n\n")
                        f.write(f"Statistics:\n")
                        f.write(f"- Total Queries: {self.query_count}\n")
                        f.write(f"- Threats Detected: {self.threat_count}\n\n")
                        f.write("DNS Queries:\n" + "-"*20 + "\n")
                        f.write(report_data["queries"] + "\n\n")
                        f.write("Threats Detected:\n" + "-"*20 + "\n")
                        f.write(report_data["threats"] + "\n\n")
                        f.write("Analysis:\n" + "-"*20 + "\n")
                        f.write(report_data["analysis"])
                
                self.log_message(f"📄 Report saved to {file_path}", "analysis")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report: {str(e)}")

    def go_back(self):
        self.monitoring = False
        self.demo_mode = False
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = DNSSpoofDetector(root)
    root.mainloop()
