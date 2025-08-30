import tkinter as tk
from tkinter import ttk
import port_scanner
import anti_keylogger
import dns_monitor
import ids

class FeaturesPage:
    def __init__(self, root, welcome_screen):
        self.root = root
        self.welcome_screen = welcome_screen
        self.root.title("CyberShield - Security Tools")
        self.root.geometry("1000x650")
        
        # Colors
        self.bg_color = "#1E2124"
        self.card_bg = "#2A2D31"
        self.accent_color = "#4ADE80"
        self.text_color = "#FFFFFF"
        
        # Main frame
        self.main_frame = tk.Frame(root, bg=self.bg_color)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid
        self.main_frame.grid_columnconfigure(0, weight=1)
        for i in range(4):
            self.main_frame.grid_rowconfigure(i, weight=1)
        
        self.create_header()
        self.create_feature_cards()
        self.create_footer()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def create_header(self):
        # Simple header
        header_frame = tk.Frame(self.main_frame, bg=self.bg_color)
        header_frame.grid(row=0, column=0, sticky="ew", padx=30, pady=(30, 20))
        
        tk.Label(
            header_frame,
            text="CyberShield Security Tools",
            font=("Arial", 28, "bold"),
            bg=self.bg_color,
            fg=self.text_color
        ).pack()
        
    def create_feature_cards(self):
        # Cards container
        cards_frame = tk.Frame(self.main_frame, bg=self.bg_color)
        cards_frame.grid(row=1, column=0, sticky="nsew", padx=50, pady=20)
        
        # Configure grid for 2x2 layout
        for i in range(2):
            cards_frame.grid_columnconfigure(i, weight=1)
            cards_frame.grid_rowconfigure(i, weight=1)
        
        # Feature definitions
        features = [
            {
                "icon": "🔍",
                "title": "Intrusion Detection System",
                "description": "Monitor network traffic for\nsuspicious activities and threats",
                "row": 0,
                "col": 0,
                "action": "Intrusion Detection System"
            },
            {
                "icon": "🌐",
                "title": "DNS Security Monitor",
                "description": "Analyze DNS queries and detect\nmalicious domain activities",
                "row": 0,
                "col": 1,
                "action": "DNS Traffic Analyzer"
            },
            {
                "icon": "🛡️",
                "title": "Anti-Keylogger",
                "description": "Detect and prevent keylogging\nthreats on your system",
                "row": 1,
                "col": 0,
                "action": "Anti-Keylogger"
            },
            {
                "icon": "🔐",
                "title": "Port Scanner",
                "description": "Scan network ports and identify\nsecurity vulnerabilities",
                "row": 1,
                "col": 1,
                "action": "Network Port Scanner"
            }
        ]
        
        for feature in features:
            self.create_feature_card(cards_frame, feature)
    
    def create_feature_card(self, parent, feature):
        # Card frame
        card = tk.Frame(parent, bg=self.card_bg, relief=tk.RAISED, bd=2)
        card.grid(
            row=feature["row"], 
            column=feature["col"], 
            padx=20, 
            pady=20, 
            sticky="nsew", 
            ipadx=30, 
            ipady=30
        )
        
        # Icon
        tk.Label(
            card,
            text=feature["icon"],
            font=("Arial", 48),
            bg=self.card_bg,
            fg=self.accent_color
        ).pack(pady=(10, 15))
        
        # Title
        tk.Label(
            card,
            text=feature["title"],
            font=("Arial", 16, "bold"),
            bg=self.card_bg,
            fg=self.text_color
        ).pack(pady=(0, 10))
        
        # Description
        tk.Label(
            card,
            text=feature["description"],
            font=("Arial", 12),
            bg=self.card_bg,
            fg=self.text_color,
            justify=tk.CENTER
        ).pack(pady=(0, 20))
        
        # Launch button
        launch_btn = tk.Button(
            card,
            text="Launch",
            font=("Arial", 12, "bold"),
            bg=self.accent_color,
            fg="black",
            relief="flat",
            padx=25,
            pady=10,
            command=lambda t=feature["action"]: self.launch_feature(t),
            cursor="hand2"
        )
        launch_btn.pack()
    
    def create_footer(self):
        # Footer with back button
        footer_frame = tk.Frame(self.main_frame, bg=self.bg_color)
        footer_frame.grid(row=2, column=0, sticky="ew", padx=30, pady=30)
        
        # Back button
        self.back_button = tk.Button(
            footer_frame,
            text="← Back to Welcome",
            font=("Arial", 14, "bold"),
            bg=self.card_bg,
            fg=self.text_color,
            relief="flat",
            padx=20,
            pady=10,
            command=self.go_back,
            cursor="hand2"
        )
        self.back_button.pack()
    
    def go_back(self):
        self.welcome_screen.deiconify()
        self.root.destroy()
        
    def on_closing(self):
        self.welcome_screen.destroy()

    def launch_feature(self, title):
        if title == "Network Port Scanner":
            port_scanner.PortScanner(self.root)
        elif title == "Anti-Keylogger":
            anti_keylogger_window = tk.Toplevel(self.root)
            anti_keylogger.AntiKeylogger(anti_keylogger_window, self)
        elif title == "DNS Traffic Analyzer":
           dns_window = tk.Toplevel(self.root)
           dns_monitor.DNSSpoofDetector(dns_window)
        elif title == "Intrusion Detection System":
            ids_window = tk.Toplevel(self.root)
            ids.IntrusionDetectionSystem(ids_window, self)

if __name__ == "__main__":
    root = tk.Tk()
    app = FeaturesPage(root, root)
    root.mainloop()
