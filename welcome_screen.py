import tkinter as tk
from tkinter import ttk
import features_page

class WelcomeScreen:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberShield")
        self.root.geometry("1200x700")
        
        # Configure the dark theme colors
        self.bg_color = "#1E2124"
        self.accent_color = "#4ADE80"
        self.text_color = "#FFFFFF"
        self.exit_color = "#FF4C4C"  # Red color for Exit button
        
        # Configure the main frame
        self.main_frame = tk.Frame(root, bg=self.bg_color)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid for responsiveness
        self.main_frame.grid_columnconfigure(0, weight=1)
        for i in range(7):  # Adjusted for the additional Exit button
            self.main_frame.grid_rowconfigure(i, weight=1)
        
        # Logo aligned with welcome text
        self.logo_text = tk.Label(
            self.main_frame,
            text="🛡️",
            font=("Arial", 72),
            bg=self.bg_color,
            fg=self.accent_color
        )
        self.logo_text.grid(row=0, column=0, pady=(30, 10), padx=(120, 0))
        
        # Welcome text
        self.welcome_label = tk.Label(
            self.main_frame,
            text="Welcome to CyberShield",
            font=("Arial", 36, "bold"),
            bg=self.bg_color,
            fg=self.text_color
        )
        self.welcome_label.grid(row=1, column=0, pady=(0, 10))
        
        # Tagline
        self.tagline_label = tk.Label(
            self.main_frame,
            text=" Cybersecurity Suite for Comprehensive Protection",
            font=("Arial", 20),
            bg=self.bg_color,
            fg=self.text_color
        )
        self.tagline_label.grid(row=2, column=0, pady=(0, 20))
        
        # Descriptive content
        self.description_label = tk.Label(
            self.main_frame,
            text=(
                "CyberShield is your ultimate cybersecurity solution, "
                "offering tools to protect your network. "
                "With  intrusion detection systems, firewall security, "
                "and DNS monitoring, CyberShield ensures "
                "comprehensive protection for your enterprise. Dive into our "
                "suite of tools designed for robust network security and analysis."
            ),
            font=("Arial", 16),
            bg=self.bg_color,
            fg=self.text_color,
            wraplength=1000,
            justify="center"
        )
        self.description_label.grid(row=3, column=0, pady=(10, 30))
        
        # Style the buttons
        style = ttk.Style()
        style.configure(
            "Accent.TButton",
            padding=15,
            font=("Arial", 16, "bold")
        )
        
        # Get Started button
        self.start_button = ttk.Button(
            self.main_frame,
            text="Get Started",
            style="Accent.TButton",
            command=self.open_features_page
        )
        self.start_button.grid(row=4, column=0, pady=(20, 10))
        
        # Exit button
        self.exit_button = tk.Button(
           self.main_frame,
            text="Exit",
            font=("Arial", 14, "bold"),  # Reduced font size
            bg=self.exit_color,
            fg=self.text_color,
            relief="flat",
            width=10,  # Fixed width for a rectangular shape
            height=1,  # Fixed height for a compact look
            command=self.root.quit
        )
        self.exit_button.grid(row=5, column=0, pady=(10, 30))
        
    def open_features_page(self):
        self.root.withdraw()  # Hide the welcome screen
        features_window = tk.Toplevel()
        features_page.FeaturesPage(features_window, self.root)

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

if __name__ == "__main__":
    root = tk.Tk()
    app = WelcomeScreen(root)
    app.run()
