import tkinter as tk
from tkinter import ttk
import port_scanner

class FeaturesPage:
    def __init__(self, root, welcome_screen):
        self.root = root
        self.welcome_screen = welcome_screen
        self.root.title("CyberShield - Features")
        self.root.geometry("1200x700")
        
        # Configure colors
        self.bg_color = "#1E2124"
        self.card_bg = "#2A2D31"
        self.accent_color = "#4ADE80"
        self.text_color = "#FFFFFF"
        
        # Main frame
        self.main_frame = tk.Frame(root, bg=self.bg_color)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid for responsiveness
        self.main_frame.grid_columnconfigure(0, weight=1)
        for i in range(5):
            self.main_frame.grid_rowconfigure(i, weight=1)
        
        # Title
        self.title_label = tk.Label(
            self.main_frame,
            text="CyberShield Features",
            font=("Arial", 28, "bold"),
            bg=self.bg_color,
            fg=self.text_color
        )
        self.title_label.grid(row=0, column=0, pady=(30, 20))
        
        # Create feature cards container
        self.cards_frame = tk.Frame(self.main_frame, bg=self.bg_color)
        self.cards_frame.grid(row=1, column=0, sticky="nsew", padx=50, pady=(0, 30))
        
        # Configure grid for cards
        for i in range(2):
            self.cards_frame.grid_columnconfigure(i, weight=1)
        for i in range(2):
            self.cards_frame.grid_rowconfigure(i, weight=1)
        
        # Feature cards
        self.create_feature_card(
            "🔍 IDS",
            "Intrusion Detection System",
            "Monitor network traffic for suspicious activities\nand security policy violations",
            0, 0
        )
        
        self.create_feature_card(
            "🌐 DNS Security",
            "DNS Traffic Analyzer",
            "Analyze and monitor DNS queries for\nmalicious domain detection",
            0, 1
        )
        
        self.create_feature_card(
            "🛡️ Firewall",
            "Advanced Firewall",
            "Configure and manage network access\nwith powerful filtering rules",
            1, 0
        )
        
        self.create_feature_card(
            "🔐 Port Scanner",
            "Network Port Scanner",
            "Scan and analyze open ports for\npotential security vulnerabilities",
            1, 1
        )
        
        # Back button
        self.back_button = ttk.Button(
            self.main_frame,
            text="Back to Welcome",
            command=self.go_back,
            style="Accent.TButton"
        )
        self.back_button.grid(row=3, column=0, pady=(10, 30))
        
        # Style the button
        style = ttk.Style()
        style.configure(
            "Accent.TButton",
            padding=10,
            font=("Arial", 12, "bold")
        )
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def create_feature_card(self, icon, title, description, row, col):
        card = tk.Frame(
            self.cards_frame,
            bg=self.card_bg,
            padx=20,
            pady=20
        )
        card.grid(row=row, column=col, padx=20, pady=20, sticky="nsew")
        
        # Configure grid for card contents
        card.grid_columnconfigure(0, weight=1)
        for i in range(4):
            card.grid_rowconfigure(i, weight=1)
        
        # Icon
        icon_label = tk.Label(
            card,
            text=icon,
            font=("Arial", 48),
            bg=self.card_bg,
            fg=self.accent_color
        )
        icon_label.grid(row=0, column=0, pady=(10, 5))
        
        # Title
        title_label = tk.Label(
            card,
            text=title,
            font=("Arial", 18, "bold"),
            bg=self.card_bg,
            fg=self.text_color
        )
        title_label.grid(row=1, column=0, pady=(5, 10))
        
        # Description
        desc_label = tk.Label(
            card,
            text=description,
            font=("Arial", 12),
            bg=self.card_bg,
            fg=self.text_color,
            justify=tk.CENTER,
            wraplength=250
        )
        desc_label.grid(row=2, column=0, pady=(0, 10))
        
        # Launch button
        launch_btn = ttk.Button(
            card,
            text="Launch",
            style="Accent.TButton",
            command=self.launch_feature if title != "Network Port Scanner" else self.launch_port_scanner
        )
        launch_btn.grid(row=3, column=0, pady=(10, 5))
        
    def go_back(self):
        self.welcome_screen.deiconify()  # Show the welcome screen
        self.root.destroy()  # Close the features page
        
    def on_closing(self):
        self.welcome_screen.destroy()  # Close the entire application

    def run(self):
        # Center the window on the screen
        self.center_window(1200, 700)
        self.root.mainloop()

    def center_window(self, width, height):
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        center_x = int(screen_width/2 - width/2)
        center_y = int(screen_height/2 - height/2)
        self.root.geometry(f'{width}x{height}+{center_x}+{center_y}')

    def launch_feature(self):
        # Placeholder for other features
        pass

    def launch_port_scanner(self):
        port_scanner.PortScanner(self.root)
