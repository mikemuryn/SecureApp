"""
Main Application Interface
SecureApp GUI using tkinter
"""

import json
import logging
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from app.auth.authentication import AuthenticationManager
from app.auth.session_manager import SessionManager
from app.encryption.file_crypto import FileEncryption
from app.models.database import DatabaseManager
from app.utils.audit_logger import AuditLogger
from app.utils.file_manager import FileAccessManager

# Import our modules
from config.settings import *  # noqa: F403, F405

logger = logging.getLogger(__name__)


class SecureApp:
    """Main application class"""

    def __init__(self):
        # Initialize theme preference and set BEFORE creating window
        self.theme_pref_file = BASE_DIR / ".theme_preference.json"  # noqa: F405
        self.current_theme = self._load_theme_preference()

        # Apply theme before creating root window (ensures dark mode default)
        ctk.set_appearance_mode(self.current_theme)

        # Create root window after theme is set
        self.root = ctk.CTk()
        self.root.title("SecureApp")
        self.root.geometry("1000x700")

        # Initialize components
        self.db_manager = DatabaseManager(DATABASE_URL)  # noqa: F405
        self.auth_manager = AuthenticationManager(self.db_manager)
        self.session_manager = SessionManager(SESSION_TIMEOUT)  # noqa: F405
        self.audit_logger = AuditLogger(LOG_FILE, self.db_manager)  # noqa: F405
        self.file_manager = FileAccessManager(
            self.db_manager, FileEncryption, self.audit_logger
        )

        # Current user
        self.current_user = None
        self.current_session = None

        # File search filter
        self.file_search_filter = ""

        # Setup logging
        self._setup_logging()

        # Initialize database
        self._initialize_database()

        # Show login screen
        self.show_login_screen()

    def _load_theme_preference(self) -> str:
        """Load theme preference from file"""
        try:
            if self.theme_pref_file.exists():
                with open(self.theme_pref_file, "r") as f:
                    data = json.load(f)
                    return data.get("theme", "dark")
        except Exception:
            pass
        return "dark"  # Default to dark mode

    def _save_theme_preference(self, theme: str) -> None:
        """Save theme preference to file"""
        try:
            with open(self.theme_pref_file, "w") as f:
                json.dump({"theme": theme}, f)
        except Exception as e:
            logger.error(f"Failed to save theme preference: {e}")

    def _setup_logging(self):
        """Setup application logging"""
        logging.basicConfig(
            level=getattr(logging, LOG_LEVEL),  # noqa: F405
            format=LOG_FORMAT,  # noqa: F405
            handlers=[
                logging.FileHandler(LOG_FILE),
                logging.StreamHandler(),
            ],  # noqa: F405
        )

    def _initialize_database(self):
        """Initialize database tables"""
        try:
            self.db_manager.create_tables()

            # Create default admin user if none exists
            session = self.db_manager.get_session()
            try:
                from app.models.database import User

                admin_exists = session.query(User).filter(User.role == "admin").first()

                if not admin_exists:
                    success = self.auth_manager.create_user(
                        "admin", "admin@secure-trading.com", "Admin123!", "admin"
                    )
                    if success:
                        logger.info("Default admin user created")
                    else:
                        logger.warning("Failed to create default admin user")

            finally:
                self.db_manager.close_session(session)

        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            messagebox.showerror("Error", f"Database initialization failed: {e}")

    def show_login_screen(self):
        """Show login screen"""
        # Clear existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()

        # Login frame
        login_frame = ctk.CTkFrame(self.root)
        login_frame.pack(expand=True, fill="both", padx=50, pady=50)

        # Title
        title_label = ctk.CTkLabel(
            login_frame, text="SecureApp", font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(pady=30)

        # Username entry
        username_label = ctk.CTkLabel(login_frame, text="Username:")
        username_label.pack(pady=(20, 5))

        self.username_entry = ctk.CTkEntry(login_frame, width=300, height=35)
        self.username_entry.pack(pady=5)

        # Password entry
        password_label = ctk.CTkLabel(login_frame, text="Password:")
        password_label.pack(pady=(20, 5))

        # Password frame with entry and show/hide button
        password_frame = ctk.CTkFrame(login_frame)
        password_frame.pack(pady=5)

        self.password_entry = ctk.CTkEntry(
            password_frame, width=250, height=35, show="*"
        )
        self.password_entry.pack(side="left", padx=(0, 5))

        self.show_password_var = tk.BooleanVar()
        self.show_password_checkbox = ctk.CTkCheckBox(
            password_frame,
            text="Show",
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
            width=50,
        )
        self.show_password_checkbox.pack(side="right")

        # Login button
        login_button = ctk.CTkButton(
            login_frame, text="Login", command=self.handle_login, width=300, height=40
        )
        login_button.pack(pady=30)

        # Forgot password link
        forgot_password_button = ctk.CTkButton(
            login_frame,
            text="Forgot Password?",
            command=self.show_password_recovery,
            width=300,
            height=30,
            fg_color="transparent",
            text_color="lightblue",
        )
        forgot_password_button.pack(pady=5)

        # Bind Enter key to login
        self.root.bind("<Return>", lambda e: self.handle_login())

        # Focus on username entry
        self.username_entry.focus()

    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")

    def toggle_new_password_visibility(self):
        """Toggle new password visibility"""
        if self.show_new_password_var.get():
            self.new_password_entry.configure(show="")
        else:
            self.new_password_entry.configure(show="*")

    def show_password_dialog(self, title: str, prompt: str) -> str:
        """Show a password dialog with show/hide option"""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x200")
        dialog.transient(self.root)
        dialog.grab_set()

        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (400 // 2)
        y = (dialog.winfo_screenheight() // 2) - (200 // 2)
        dialog.geometry(f"400x200+{x}+{y}")

        result = {"password": ""}

        # Prompt label
        prompt_label = ctk.CTkLabel(dialog, text=prompt, font=ctk.CTkFont(size=14))
        prompt_label.pack(pady=20)

        # Password frame
        password_frame = ctk.CTkFrame(dialog)
        password_frame.pack(pady=10)

        password_entry = ctk.CTkEntry(password_frame, width=250, height=35, show="*")
        password_entry.pack(side="left", padx=(0, 5))

        show_password_var = tk.BooleanVar()
        show_password_checkbox = ctk.CTkCheckBox(
            password_frame,
            text="Show",
            variable=show_password_var,
            command=lambda: self.toggle_dialog_password_visibility(
                password_entry, show_password_var
            ),
            width=50,
        )
        show_password_checkbox.pack(side="right")

        # Buttons frame
        buttons_frame = ctk.CTkFrame(dialog)
        buttons_frame.pack(pady=20)

        def on_ok():
            result["password"] = password_entry.get()
            dialog.destroy()

        def on_cancel():
            dialog.destroy()

        ok_button = ctk.CTkButton(buttons_frame, text="OK", command=on_ok, width=100)
        ok_button.pack(side="left", padx=10)

        cancel_button = ctk.CTkButton(
            buttons_frame, text="Cancel", command=on_cancel, width=100
        )
        cancel_button.pack(side="right", padx=10)

        # Focus on password entry
        password_entry.focus()

        # Bind Enter key
        password_entry.bind("<Return>", lambda e: on_ok())

        # Wait for dialog to close
        dialog.wait_window()

        return result["password"]

    def toggle_dialog_password_visibility(self, password_entry, show_var):
        """Toggle password visibility in dialog"""
        if show_var.get():
            password_entry.configure(show="")
        else:
            password_entry.configure(show="*")

    def handle_login(self):
        """Handle login attempt"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return

        # Authenticate user
        success, message = self.auth_manager.authenticate_user(username, password)

        if success:
            # Create session
            user = self.auth_manager.get_user_by_username(username)
            session_token = self.session_manager.create_session(username, user.role)

            self.current_user = user
            self.current_session = session_token

            # Log successful login
            self.audit_logger.log_login_attempt(username, True)

            # Show main interface
            self.show_main_interface()
        else:
            # Log failed login
            self.audit_logger.log_login_attempt(username, False)
            messagebox.showerror("Login Failed", message)

    def show_main_interface(self):
        """Show main application interface"""
        # Clear existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()

        # Main frame
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(fill="both", expand=True)

        # Header frame
        header_frame = ctk.CTkFrame(main_frame)
        header_frame.pack(fill="x", padx=10, pady=10)

        # Welcome label
        welcome_label = ctk.CTkLabel(
            header_frame,
            text=f"Welcome, {self.current_user.username} ({self.current_user.role})",
            font=ctk.CTkFont(size=18, weight="bold"),
        )
        welcome_label.pack(side="left", padx=20, pady=10)

        # Theme toggle button
        self.theme_button = ctk.CTkButton(
            header_frame,
            text="☀️" if self.current_theme == "dark" else "🌙",
            command=self.toggle_theme,
            width=50,
        )
        self.theme_button.pack(side="right", padx=10, pady=10)

        # Logout button
        logout_button = ctk.CTkButton(
            header_frame, text="Logout", command=self.handle_logout, width=100
        )
        logout_button.pack(side="right", padx=20, pady=10)

        # Setup keyboard shortcuts
        self._setup_keyboard_shortcuts()

        # Status bar
        self.status_bar = ctk.CTkLabel(
            main_frame, text="Ready", anchor="w", font=ctk.CTkFont(size=12)
        )
        self.status_bar.pack(side="bottom", fill="x", padx=10, pady=5)
        self._update_status_bar()

        # Content frame
        content_frame = ctk.CTkFrame(main_frame)
        content_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Create notebook for tabs
        self.notebook = ttk.Notebook(content_frame)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # File Management tab
        self.create_file_management_tab()

        # User Management tab (admin only)
        if self.current_user.role == "admin":
            self.create_user_management_tab()

        # Audit Log tab (admin only)
        if self.current_user.role == "admin":
            self.create_audit_log_tab()

    def create_file_management_tab(self):
        """Create file management tab"""
        file_frame = ctk.CTkFrame(self.notebook)
        self.notebook.add(file_frame, text="File Management")

        # Upload section
        upload_frame = ctk.CTkFrame(file_frame)
        upload_frame.pack(fill="x", padx=10, pady=10)

        upload_label = ctk.CTkLabel(
            upload_frame, text="Upload File", font=ctk.CTkFont(size=16, weight="bold")
        )
        upload_label.pack(pady=10)

        upload_button = ctk.CTkButton(
            upload_frame,
            text="Select File to Upload",
            command=self.handle_file_upload,
            width=200,
        )
        upload_button.pack(pady=10)

        # File list section
        list_frame = ctk.CTkFrame(file_frame)
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)

        list_label = ctk.CTkLabel(
            list_frame,
            text="All Files" if self.current_user.role == "admin" else "Your Files",
            font=ctk.CTkFont(size=16, weight="bold"),
        )
        list_label.pack(pady=10)

        # Search/filter section
        search_frame = ctk.CTkFrame(list_frame)
        search_frame.pack(fill="x", padx=10, pady=5)

        search_label = ctk.CTkLabel(search_frame, text="Search:")
        search_label.pack(side="left", padx=10, pady=5)

        self.search_entry = ctk.CTkEntry(
            search_frame, placeholder_text="Type to search files...", width=300
        )
        self.search_entry.pack(side="left", padx=10, pady=5)
        self.search_entry.bind("<KeyRelease>", self._on_search_changed)

        clear_search_button = ctk.CTkButton(
            search_frame, text="Clear", command=self._clear_search, width=80
        )
        clear_search_button.pack(side="left", padx=10, pady=5)

        # File list treeview
        if self.current_user.role == "admin":
            columns = (
                "ID",
                "Filename",
                "Owner",
                "Size",
                "Created",
                "Last Accessed",
                "Access Count",
            )
        else:
            columns = (
                "ID",
                "Filename",
                "Size",
                "Created",
                "Last Accessed",
                "Access Count",
            )

        self.file_tree = ttk.Treeview(
            list_frame, columns=columns, show="headings", height=10
        )

        for col in columns:
            self.file_tree.heading(col, text=col)
            self.file_tree.column(col, width=120)

        # Scrollbar for file list
        file_scrollbar = ttk.Scrollbar(
            list_frame, orient="vertical", command=self.file_tree.yview
        )
        self.file_tree.configure(yscrollcommand=file_scrollbar.set)

        self.file_tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        file_scrollbar.pack(side="right", fill="y", pady=10)

        # File operations buttons
        operations_frame = ctk.CTkFrame(file_frame)
        operations_frame.pack(fill="x", padx=10, pady=10)

        download_button = ctk.CTkButton(
            operations_frame,
            text="Download Selected",
            command=self.handle_file_download,
            width=150,
        )
        download_button.pack(side="left", padx=10, pady=10)

        delete_button = ctk.CTkButton(
            operations_frame,
            text="Delete Selected",
            command=self.handle_file_delete,
            width=150,
        )
        delete_button.pack(side="left", padx=10, pady=10)

        refresh_button = ctk.CTkButton(
            operations_frame,
            text="Refresh List",
            command=self.refresh_file_list,
            width=150,
        )
        refresh_button.pack(side="right", padx=10, pady=10)

        # Advanced operations buttons
        advanced_frame = ctk.CTkFrame(file_frame)
        advanced_frame.pack(fill="x", padx=10, pady=10)

        tag_button = ctk.CTkButton(
            advanced_frame,
            text="Manage Tags",
            command=self.handle_file_tags,
            width=120,
        )
        tag_button.pack(side="left", padx=5, pady=5)

        share_button = ctk.CTkButton(
            advanced_frame,
            text="Share File",
            command=self.handle_file_share,
            width=120,
        )
        share_button.pack(side="left", padx=5, pady=5)

        version_button = ctk.CTkButton(
            advanced_frame,
            text="View Versions",
            command=self.handle_file_versions,
            width=120,
        )
        version_button.pack(side="left", padx=5, pady=5)

        export_button = ctk.CTkButton(
            advanced_frame,
            text="Export List",
            command=self.handle_export_file_list,
            width=120,
        )
        export_button.pack(side="left", padx=5, pady=5)

        if self.current_user.role == "admin":
            backup_button = ctk.CTkButton(
                advanced_frame,
                text="Create Backup",
                command=self.handle_backup,
                width=120,
            )
            backup_button.pack(side="left", padx=5, pady=5)

        # Load initial file list
        self.refresh_file_list()

        # Setup drag and drop
        self._setup_drag_drop(file_frame)

    def create_settings_tab(self):
        """Create settings tab for all users"""
        settings_frame = ctk.CTkFrame(self.notebook)
        self.notebook.add(settings_frame, text="Settings")

        # Password settings
        password_frame = ctk.CTkFrame(settings_frame)
        password_frame.pack(fill="x", padx=10, pady=10)

        password_label = ctk.CTkLabel(
            password_frame,
            text="Password Recovery",
            font=ctk.CTkFont(size=16, weight="bold"),
        )
        password_label.pack(pady=10)

        # Recovery question section
        recovery_frame = ctk.CTkFrame(password_frame)
        recovery_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(recovery_frame, text="Recovery Question:").grid(
            row=0, column=0, padx=10, pady=5, sticky="w"
        )
        self.recovery_question_entry = ctk.CTkEntry(recovery_frame, width=300)
        self.recovery_question_entry.grid(row=0, column=1, padx=10, pady=5)

        ctk.CTkLabel(recovery_frame, text="Recovery Answer:").grid(
            row=1, column=0, padx=10, pady=5, sticky="w"
        )
        self.recovery_answer_entry = ctk.CTkEntry(recovery_frame, width=300, show="*")
        self.recovery_answer_entry.grid(row=1, column=1, padx=10, pady=5)

        # Load existing recovery question
        user = self.auth_manager.get_user_by_username(self.current_user.username)
        if user and user.recovery_question:
            self.recovery_question_entry.insert(0, user.recovery_question)

        set_recovery_button = ctk.CTkButton(
            recovery_frame,
            text="Set Recovery Question",
            command=self.handle_set_recovery_question,
            width=200,
        )
        set_recovery_button.grid(row=2, column=1, padx=10, pady=20)

        # Change password section
        change_pass_frame = ctk.CTkFrame(password_frame)
        change_pass_frame.pack(fill="x", padx=20, pady=10)

        change_pass_label = ctk.CTkLabel(
            change_pass_frame,
            text="Change Password",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        change_pass_label.pack(pady=10)

        ctk.CTkLabel(change_pass_frame, text="Current Password:").grid(
            row=0, column=0, padx=10, pady=5, sticky="w"
        )
        self.current_pass_entry = ctk.CTkEntry(change_pass_frame, width=250, show="*")
        self.current_pass_entry.grid(row=0, column=1, padx=10, pady=5)

        ctk.CTkLabel(change_pass_frame, text="New Password:").grid(
            row=1, column=0, padx=10, pady=5, sticky="w"
        )
        self.new_pass_change_entry = ctk.CTkEntry(
            change_pass_frame, width=250, show="*"
        )
        self.new_pass_change_entry.grid(row=1, column=1, padx=10, pady=5)

        ctk.CTkLabel(change_pass_frame, text="Confirm New Password:").grid(
            row=2, column=0, padx=10, pady=5, sticky="w"
        )
        self.confirm_pass_entry = ctk.CTkEntry(change_pass_frame, width=250, show="*")
        self.confirm_pass_entry.grid(row=2, column=1, padx=10, pady=5)

        change_pass_button = ctk.CTkButton(
            change_pass_frame,
            text="Change Password",
            command=self.handle_change_password,
            width=200,
        )
        change_pass_button.grid(row=3, column=1, padx=10, pady=20)

    def handle_set_recovery_question(self) -> None:
        """Handle setting recovery question"""
        question = self.recovery_question_entry.get().strip()
        answer = self.recovery_answer_entry.get().strip()

        if not question or not answer:
            self._show_error("Missing Information", "Please fill in all fields.")
            return

        try:
            self.status_bar.configure(text="Setting recovery question...")
            success, message = self.auth_manager.set_recovery_question(
                self.current_user.username, question, answer
            )
            if success:
                self._show_success("Recovery Question Set", message)
            else:
                self._show_error("Error", message)
        except Exception as e:
            logger.error(f"Set recovery question error: {e}")
            self._show_error("Error", f"An error occurred: {str(e)}")
        finally:
            self.status_bar.configure(text="Ready")

    def handle_change_password(self) -> None:
        """Handle password change"""
        current_pass = self.current_pass_entry.get()
        new_pass = self.new_pass_change_entry.get()
        confirm_pass = self.confirm_pass_entry.get()

        if not all([current_pass, new_pass, confirm_pass]):
            self._show_error("Missing Information", "Please fill in all fields.")
            return

        if new_pass != confirm_pass:
            self._show_error("Error", "New passwords do not match.")
            return

        try:
            self.status_bar.configure(text="Changing password...")
            success, message = self.auth_manager.change_password(
                self.current_user.username, current_pass, new_pass
            )
            if success:
                self._show_success("Password Changed", message)
                self.current_pass_entry.delete(0, tk.END)
                self.new_pass_change_entry.delete(0, tk.END)
                self.confirm_pass_entry.delete(0, tk.END)
            else:
                self._show_error("Error", message)
        except Exception as e:
            logger.error(f"Change password error: {e}")
            self._show_error("Error", f"An error occurred: {str(e)}")
        finally:
            self.status_bar.configure(text="Ready")

    def create_user_management_tab(self):
        """Create user management tab (admin only)"""
        user_frame = ctk.CTkFrame(self.notebook)
        self.notebook.add(user_frame, text="User Management")

        # Create user section
        create_frame = ctk.CTkFrame(user_frame)
        create_frame.pack(fill="x", padx=10, pady=10)

        create_label = ctk.CTkLabel(
            create_frame,
            text="Create New User",
            font=ctk.CTkFont(size=16, weight="bold"),
        )
        create_label.pack(pady=10)

        # User creation form
        form_frame = ctk.CTkFrame(create_frame)
        form_frame.pack(fill="x", padx=20, pady=10)

        # Username
        ctk.CTkLabel(form_frame, text="Username:").grid(
            row=0, column=0, padx=10, pady=5, sticky="w"
        )
        self.new_username_entry = ctk.CTkEntry(form_frame, width=200)
        self.new_username_entry.grid(row=0, column=1, padx=10, pady=5)

        # Email
        ctk.CTkLabel(form_frame, text="Email:").grid(
            row=1, column=0, padx=10, pady=5, sticky="w"
        )
        self.new_email_entry = ctk.CTkEntry(form_frame, width=200)
        self.new_email_entry.grid(row=1, column=1, padx=10, pady=5)

        # Password
        ctk.CTkLabel(form_frame, text="Password:").grid(
            row=2, column=0, padx=10, pady=5, sticky="w"
        )

        # Password frame with entry and show/hide button
        password_frame = ctk.CTkFrame(form_frame)
        password_frame.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

        self.new_password_entry = ctk.CTkEntry(password_frame, width=150, show="*")
        self.new_password_entry.pack(side="left", padx=(0, 5))

        self.show_new_password_var = tk.BooleanVar()
        self.show_new_password_checkbox = ctk.CTkCheckBox(
            password_frame,
            text="Show",
            variable=self.show_new_password_var,
            command=self.toggle_new_password_visibility,
            width=50,
        )
        self.show_new_password_checkbox.pack(side="right")

        # Role
        ctk.CTkLabel(form_frame, text="Role:").grid(
            row=3, column=0, padx=10, pady=5, sticky="w"
        )
        self.new_role_var = tk.StringVar(value="user")
        role_combo = ctk.CTkComboBox(
            form_frame,
            values=["user", "admin", "readonly"],
            variable=self.new_role_var,
            width=200,
        )
        role_combo.grid(row=3, column=1, padx=10, pady=5)

        # Create button
        create_user_button = ctk.CTkButton(
            form_frame, text="Create User", command=self.handle_create_user, width=150
        )
        create_user_button.grid(row=4, column=1, padx=10, pady=20)

    def create_audit_log_tab(self):
        """Create audit log tab (admin only)"""
        log_frame = ctk.CTkFrame(self.notebook)
        self.notebook.add(log_frame, text="Audit Log")

        # Log display
        log_text = ctk.CTkTextbox(log_frame, height=400)
        log_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Refresh button
        refresh_log_button = ctk.CTkButton(
            log_frame,
            text="Refresh Log",
            command=lambda: self.refresh_audit_log(log_text),
            width=150,
        )
        refresh_log_button.pack(pady=10)

        # Load initial log
        self.refresh_audit_log(log_text)

    def toggle_theme(self) -> None:
        """Toggle between dark and light theme"""
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        ctk.set_appearance_mode(self.current_theme)
        self._save_theme_preference(self.current_theme)
        # Update theme button icon
        if hasattr(self, "theme_button"):
            self.theme_button.configure(
                text="☀️" if self.current_theme == "dark" else "🌙"
            )
        self._update_status_bar()

    def _setup_keyboard_shortcuts(self) -> None:
        """Setup keyboard shortcuts for main interface"""
        self.root.bind("<Control-u>", lambda e: self.handle_file_upload())
        self.root.bind("<Control-d>", lambda e: self.handle_file_download())
        self.root.bind("<Control-f>", lambda e: self.search_entry.focus())
        self.root.bind("<Control-q>", lambda e: self.handle_logout())
        self.root.bind("<F5>", lambda e: self.refresh_file_list())
        self.root.bind("<Delete>", lambda e: self.handle_file_delete())
        self.root.bind("<Escape>", lambda e: self._handle_escape())

    def _handle_escape(self) -> None:
        """Handle Escape key - close dialogs or clear selection"""
        # Try to find active toplevel and close it
        for widget in self.root.winfo_children():
            if isinstance(widget, tk.Toplevel) or isinstance(widget, ctk.CTkToplevel):
                widget.destroy()
                return
        # Clear file selection
        for item in self.file_tree.selection():
            self.file_tree.selection_remove(item)

    def _on_search_changed(self, event=None) -> None:
        """Handle search text change"""
        self.file_search_filter = self.search_entry.get().lower()
        self.refresh_file_list()

    def _clear_search(self) -> None:
        """Clear search filter"""
        self.search_entry.delete(0, tk.END)
        self.file_search_filter = ""
        self.refresh_file_list()

    def _setup_drag_drop(self, parent_frame) -> None:
        """Setup drag and drop for file upload"""
        # Enable drag and drop on the upload frame
        upload_frame = None
        for widget in parent_frame.winfo_children():
            if isinstance(widget, ctk.CTkFrame):
                for child in widget.winfo_children():
                    if isinstance(child, ctk.CTkLabel) and "Upload" in str(
                        child.cget("text")
                    ):
                        upload_frame = widget
                        break

        if upload_frame:
            # Bind drag and drop events
            upload_frame.bind(
                "<Button-1>", lambda e: self._on_drag_enter(e, upload_frame)
            )
            upload_frame.bind(
                "<B1-Motion>", lambda e: self._on_drag_over(e, upload_frame)
            )
            upload_frame.bind("<ButtonRelease-1>", lambda e: self._on_drop(e))

            # Make frame accept drops
            upload_frame.configure(cursor="hand2")

    def _on_drag_enter(self, event, frame) -> None:
        """Handle drag enter"""
        frame.configure(fg_color=("gray75", "gray25"))

    def _on_drag_over(self, event, frame) -> None:
        """Handle drag over"""
        pass

    def _on_drop(self, event) -> None:
        """Handle file drop"""
        # Reset frame color
        for widget in self.root.winfo_children():
            for child in widget.winfo_children():
                if isinstance(child, ctk.CTkFrame):
                    for subchild in child.winfo_children():
                        if isinstance(subchild, ctk.CTkLabel) and "Upload" in str(
                            subchild.cget("text")
                        ):
                            child.configure(fg_color=None)

        # Use file dialog as fallback (true drag-drop requires more complex handling)
        self.handle_file_upload()

    def _update_status_bar(self) -> None:
        """Update status bar with current information"""
        if not hasattr(self, "status_bar") or not self.current_user:
            return

        try:
            session_time = ""
            if self.current_session:
                is_valid, session_info = self.session_manager.validate_session(
                    self.current_session
                )
                if is_valid and session_info:
                    created_at = session_info.get("created_at")
                    if created_at:
                        elapsed = datetime.utcnow() - created_at
                        minutes = int(elapsed.total_seconds() / 60)
                        session_time = f" | Session: {minutes}m"

            # Get file count
            files = self.file_manager.list_user_files(self.current_user.username)
            file_count = len(files)
            if self.file_search_filter:
                file_count = sum(
                    1
                    for f in files
                    if self.file_search_filter in f.get("filename", "").lower()
                )

            status_text = (
                f"User: {self.current_user.username} ({self.current_user.role})"
                f" | Files: {file_count}"
                f"{session_time}"
                f" | Theme: {self.current_theme.capitalize()}"
            )
            self.status_bar.configure(text=status_text)
        except Exception as e:
            logger.error(f"Error updating status bar: {e}")
            self.status_bar.configure(text="Ready")

    def handle_file_upload(self, file_paths=None):
        """Handle file upload - supports multiple files"""
        if file_paths is None:
            file_path = filedialog.askopenfilename(
                title="Select file to upload", filetypes=[("All files", "*.*")]
            )
            if not file_path:
                return
            file_paths = [file_path]

        for file_path in file_paths:
            file_path = Path(file_path) if isinstance(file_path, str) else file_path

            if not file_path.exists():
                self._show_error(
                    "File Not Found", f"The file '{file_path.name}' does not exist."
                )
                continue

            # Get password for encryption
            password = self.show_password_dialog(
                "File Encryption", f"Enter your password to encrypt '{file_path.name}':"
            )
            if not password:
                continue

            # Upload file
            try:
                self.status_bar.configure(text=f"Uploading {file_path.name}...")
                success, message = self.file_manager.upload_file(
                    file_path, self.current_user.username, password
                )

                if success:
                    self._show_success(
                        "File Uploaded", f"'{file_path.name}' uploaded successfully!"
                    )
                    self.refresh_file_list()
                    self._update_status_bar()
                else:
                    self._show_error(
                        "Upload Failed",
                        f"Failed to upload '{file_path.name}': {message}",
                    )
            except Exception as e:
                logger.error(f"Upload error: {e}")
                self._show_error(
                    "Upload Error",
                    f"An error occurred while uploading '{file_path.name}': {str(e)}",
                )
            finally:
                self.status_bar.configure(text="Ready")

    def handle_file_download(self):
        """Handle file download"""
        selection = self.file_tree.selection()
        if not selection:
            self._show_warning("No File Selected", "Please select a file to download.")
            return

        item = self.file_tree.item(selection[0])
        file_id = item["values"][0]  # Assuming ID is first column

        # Get password for decryption
        password = self.show_password_dialog(
            "File Decryption", "Enter your password for file decryption:"
        )
        if not password:
            return

        # Download file
        success, temp_path, message = self.file_manager.download_file(
            file_id, self.current_user.username, password
        )

        if success:
            # Ask where to save
            filename = temp_path.name if temp_path else "file"
            save_path = filedialog.asksaveasfilename(
                title="Save file as", initialfilename=filename
            )

            if save_path:
                try:
                    import shutil

                    self.status_bar.configure(text=f"Saving {filename}...")
                    shutil.move(str(temp_path), save_path)
                    self._show_success("File Downloaded", f"File saved to: {save_path}")
                except Exception as e:
                    logger.error(f"Save error: {e}")
                    self._show_error("Save Failed", f"Failed to save file: {str(e)}")
                finally:
                    self.status_bar.configure(text="Ready")

            # Clean up temp file
            if temp_path and temp_path.exists():
                temp_path.unlink()
        else:
            self._show_error("Download Failed", f"Could not download file: {message}")

    def handle_file_delete(self):
        """Handle file deletion"""
        selection = self.file_tree.selection()
        if not selection:
            self._show_warning("No File Selected", "Please select a file to delete.")
            return

        item = self.file_tree.item(selection[0])
        file_id = item["values"][0]
        filename = item["values"][1] if len(item["values"]) > 1 else "this file"

        if messagebox.askyesno(
            "Confirm Deletion",
            (
                f"Are you sure you want to delete '{filename}'?\n\n"
                "This action cannot be undone."
            ),
        ):
            try:
                self.status_bar.configure(text=f"Deleting {filename}...")
                success, message = self.file_manager.delete_file(
                    file_id, self.current_user.username
                )

                if success:
                    self._show_success(
                        "File Deleted", f"'{filename}' has been deleted."
                    )
                    self.refresh_file_list()
                    self._update_status_bar()
                else:
                    self._show_error(
                        "Delete Failed", f"Could not delete file: {message}"
                    )
            except Exception as e:
                logger.error(f"Delete error: {e}")
                self._show_error("Delete Error", f"An error occurred: {str(e)}")
            finally:
                self.status_bar.configure(text="Ready")

    def _show_success(self, title: str, message: str) -> None:
        """Show success message"""
        messagebox.showinfo(title, message)

    def _show_error(self, title: str, message: str) -> None:
        """Show error message with better formatting"""
        messagebox.showerror(title, message)

    def _show_warning(self, title: str, message: str) -> None:
        """Show warning message"""
        messagebox.showwarning(title, message)

    def refresh_file_list(self):
        """Refresh file list with search filter"""
        # Clear existing items
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)

        # Get user files
        files = self.file_manager.list_user_files(self.current_user.username)

        # Filter files if search is active
        if self.file_search_filter:
            files = [
                f
                for f in files
                if self.file_search_filter in f.get("filename", "").lower()
            ]

        # Add files to tree
        for file_info in files:
            if self.current_user.role == "admin":
                self.file_tree.insert(
                    "",
                    "end",
                    values=(
                        file_info["id"],
                        file_info["filename"],
                        file_info["owner"],
                        f"{file_info['size']:,} bytes",
                        file_info["created_at"].strftime("%Y-%m-%d %H:%M"),
                        (
                            file_info["last_accessed"].strftime("%Y-%m-%d %H:%M")
                            if file_info["last_accessed"]
                            else "Never"
                        ),
                        file_info["access_count"],
                    ),
                )
            else:
                self.file_tree.insert(
                    "",
                    "end",
                    values=(
                        file_info["id"],
                        file_info["filename"],
                        f"{file_info['size']:,} bytes",
                        file_info["created_at"].strftime("%Y-%m-%d %H:%M"),
                        (
                            file_info["last_accessed"].strftime("%Y-%m-%d %H:%M")
                            if file_info["last_accessed"]
                            else "Never"
                        ),
                        file_info["access_count"],
                    ),
                )

        # Update status bar after refresh
        self._update_status_bar()

    def handle_create_user(self):
        """Handle user creation"""
        username = self.new_username_entry.get().strip()
        email = self.new_email_entry.get().strip()
        password = self.new_password_entry.get()
        role = self.new_role_var.get()

        if not all([username, email, password]):
            self._show_error(
                "Missing Information", "Please fill in all required fields."
            )
            return

        try:
            self.status_bar.configure(text=f"Creating user {username}...")
            success = self.auth_manager.create_user(username, email, password, role)

            if success:
                self._show_success(
                    "User Created", f"User '{username}' has been created successfully."
                )
                # Clear form
                self.new_username_entry.delete(0, tk.END)
                self.new_email_entry.delete(0, tk.END)
                self.new_password_entry.delete(0, tk.END)
            else:
                self._show_error(
                    "Creation Failed",
                    "Failed to create user. The username or email may already exist.",
                )
        except Exception as e:
            logger.error(f"User creation error: {e}")
            self._show_error(
                "Error", f"An error occurred while creating user: {str(e)}"
            )
        finally:
            self.status_bar.configure(text="Ready")

    def refresh_audit_log(self, log_text):
        """Refresh audit log display"""
        events = self.audit_logger.get_recent_events(24)  # Last 24 hours

        log_text.delete("1.0", tk.END)

        for event in events:
            status = "SUCCESS" if event["success"] else "FAILED"
            log_entry = (
                f"{event['timestamp']} - {event['username']} - "
                f"{event['action']} - {event['resource']} - {status}\n"
            )
            log_text.insert(tk.END, log_entry)

    def show_password_recovery(self) -> None:
        """Show password recovery dialog"""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Password Recovery")
        dialog.geometry("500x400")
        dialog.transient(self.root)
        dialog.grab_set()

        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (dialog.winfo_screenheight() // 2) - (400 // 2)
        dialog.geometry(f"500x400+{x}+{y}")

        # Username entry
        ctk.CTkLabel(dialog, text="Username:", font=ctk.CTkFont(size=12)).pack(
            pady=(20, 5)
        )
        username_entry = ctk.CTkEntry(dialog, width=300)
        username_entry.pack(pady=5)

        # Get recovery question
        def get_recovery_question():
            username = username_entry.get().strip()
            if not username:
                messagebox.showerror("Error", "Please enter username")
                return

            user = self.auth_manager.get_user_by_username(username)
            if not user:
                messagebox.showerror("Error", "User not found")
                return

            if not user.recovery_question:
                messagebox.showerror(
                    "Error",
                    "Recovery question not set. Please contact administrator.",
                )
                return

            # Show recovery question
            question_label.configure(text=f"Question: {user.recovery_question}")
            answer_entry.pack(pady=5)
            reset_button.pack(pady=10)

        # Recovery question label
        question_label = ctk.CTkLabel(dialog, text="", font=ctk.CTkFont(size=12))
        question_label.pack(pady=10)

        # Recovery answer entry (initially hidden)
        answer_entry = ctk.CTkEntry(dialog, width=300, placeholder_text="Answer")

        # Get question button
        get_question_button = ctk.CTkButton(
            dialog,
            text="Get Recovery Question",
            command=get_recovery_question,
            width=200,
        )
        get_question_button.pack(pady=10)

        # Reset password function
        def reset_password():
            username = username_entry.get().strip()
            answer = answer_entry.get().strip()

            if not username or not answer:
                messagebox.showerror("Error", "Please fill in all fields")
                return

            success, message, reset_token = self.auth_manager.request_password_reset(
                username, answer
            )

            if not success:
                messagebox.showerror("Password Recovery Failed", message)
                return

            # Show new password dialog
            new_password_dialog = ctk.CTkToplevel(dialog)
            new_password_dialog.title("Set New Password")
            new_password_dialog.geometry("400x250")
            new_password_dialog.transient(dialog)
            new_password_dialog.grab_set()

            ctk.CTkLabel(
                new_password_dialog,
                text="Enter New Password:",
                font=ctk.CTkFont(size=12),
            ).pack(pady=(20, 5))
            new_pass_entry = ctk.CTkEntry(
                new_password_dialog, width=250, show="*", height=35
            )
            new_pass_entry.pack(pady=5)

            ctk.CTkLabel(
                new_password_dialog,
                text="Confirm New Password:",
                font=ctk.CTkFont(size=12),
            ).pack(pady=(10, 5))
            confirm_pass_entry = ctk.CTkEntry(
                new_password_dialog, width=250, show="*", height=35
            )
            confirm_pass_entry.pack(pady=5)

            def set_new_password():
                new_pass = new_pass_entry.get()
                confirm_pass = confirm_pass_entry.get()

                if new_pass != confirm_pass:
                    messagebox.showerror("Error", "Passwords do not match")
                    return

                success, message = self.auth_manager.reset_password(
                    username, reset_token, new_pass
                )

                if success:
                    messagebox.showinfo("Success", "Password reset successfully!")
                    new_password_dialog.destroy()
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", message)

            ctk.CTkButton(
                new_password_dialog,
                text="Reset Password",
                command=set_new_password,
                width=200,
            ).pack(pady=20)

        # Reset button (initially hidden)
        reset_button = ctk.CTkButton(
            dialog, text="Reset Password", command=reset_password, width=200
        )

    def handle_file_tags(self) -> None:
        """Handle file tagging"""
        selection = self.file_tree.selection()
        if not selection:
            self._show_warning(
                "No File Selected", "Please select a file to manage tags."
            )
            return

        item = self.file_tree.item(selection[0])
        file_id = item["values"][0]
        filename = item["values"][1] if len(item["values"]) > 1 else "Unknown"

        # Create tag management dialog
        dialog = ctk.CTkToplevel(self.root)
        dialog.title(f"Manage Tags - {filename}")
        dialog.geometry("400x500")
        dialog.transient(self.root)
        dialog.grab_set()

        # Current tags
        ctk.CTkLabel(
            dialog, text="Current Tags:", font=ctk.CTkFont(size=12, weight="bold")
        ).pack(pady=(20, 10))

        tags_frame = ctk.CTkScrollableFrame(dialog, height=150)
        tags_frame.pack(fill="both", expand=True, padx=20, pady=10)

        def refresh_tags():
            for widget in tags_frame.winfo_children():
                widget.destroy()

            tags = self.file_manager.get_file_tags(file_id)
            if not tags:
                ctk.CTkLabel(tags_frame, text="No tags").pack(pady=5)
            else:
                for tag in tags:
                    tag_row = ctk.CTkFrame(tags_frame)
                    tag_row.pack(fill="x", pady=2)

                    ctk.CTkLabel(tag_row, text=tag["name"], width=200).pack(
                        side="left", padx=5
                    )

                    def remove_tag(tag_name=tag["name"]):
                        success, message = self.file_manager.remove_file_tag(
                            file_id, tag_name
                        )
                        if success:
                            self._show_success("Tag Removed", message)
                            refresh_tags()
                        else:
                            self._show_error("Error", message)

                    ctk.CTkButton(
                        tag_row, text="Remove", command=remove_tag, width=80
                    ).pack(side="right", padx=5)

        refresh_tags()

        # Add new tag
        ctk.CTkLabel(
            dialog, text="Add New Tag:", font=ctk.CTkFont(size=12, weight="bold")
        ).pack(pady=(20, 10))

        tag_input_frame = ctk.CTkFrame(dialog)
        tag_input_frame.pack(fill="x", padx=20, pady=5)

        tag_entry = ctk.CTkEntry(
            tag_input_frame, placeholder_text="Tag name", width=200
        )
        tag_entry.pack(side="left", padx=5)

        def add_tag():
            tag_name = tag_entry.get().strip()
            if not tag_name:
                self._show_warning("Error", "Please enter a tag name")
                return

            success, message = self.file_manager.add_file_tag(
                file_id, self.current_user.username, tag_name
            )
            if success:
                self._show_success("Tag Added", message)
                tag_entry.delete(0, tk.END)
                refresh_tags()
            else:
                self._show_error("Error", message)

        ctk.CTkButton(tag_input_frame, text="Add", command=add_tag, width=80).pack(
            side="right", padx=5
        )

        # Close button
        ctk.CTkButton(dialog, text="Close", command=dialog.destroy, width=200).pack(
            pady=20
        )

    def handle_file_share(self) -> None:
        """Handle file sharing"""
        selection = self.file_tree.selection()
        if not selection:
            self._show_warning("No File Selected", "Please select a file to share.")
            return

        item = self.file_tree.item(selection[0])
        file_id = item["values"][0]
        filename = item["values"][1] if len(item["values"]) > 1 else "Unknown"

        # Get all users
        session = self.db_manager.get_session()
        try:
            from app.models.database import User

            all_users = session.query(User).all()
            user_list = [
                u.username
                for u in all_users
                if u.username != self.current_user.username
            ]
        finally:
            self.db_manager.close_session(session)

        if not user_list:
            self._show_warning("No Users", "No other users available to share with.")
            return

        # Create share dialog
        dialog = ctk.CTkToplevel(self.root)
        dialog.title(f"Share File - {filename}")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()

        ctk.CTkLabel(
            dialog, text=f"Share: {filename}", font=ctk.CTkFont(size=14, weight="bold")
        ).pack(pady=(20, 10))

        ctk.CTkLabel(dialog, text="Share with:", font=ctk.CTkFont(size=12)).pack(pady=5)
        user_combo = ctk.CTkComboBox(dialog, values=user_list, width=250)
        user_combo.pack(pady=5)

        ctk.CTkLabel(dialog, text="Permission:", font=ctk.CTkFont(size=12)).pack(pady=5)
        perm_var = tk.StringVar(value="read")
        perm_combo = ctk.CTkComboBox(
            dialog, values=["read", "write", "admin"], variable=perm_var, width=250
        )
        perm_combo.pack(pady=5)

        def share_file():
            shared_with = user_combo.get()
            permission = perm_var.get()

            if not shared_with:
                self._show_warning("Error", "Please select a user")
                return

            success, message = self.file_manager.share_file(
                file_id, self.current_user.username, shared_with, permission
            )
            if success:
                self._show_success("File Shared", message)
                dialog.destroy()
            else:
                self._show_error("Error", message)

        ctk.CTkButton(dialog, text="Share", command=share_file, width=200).pack(pady=20)

    def handle_file_versions(self) -> None:
        """Handle file versioning"""
        selection = self.file_tree.selection()
        if not selection:
            self._show_warning(
                "No File Selected", "Please select a file to view versions."
            )
            return

        item = self.file_tree.item(selection[0])
        file_id = item["values"][0]
        filename = item["values"][1] if len(item["values"]) > 1 else "Unknown"

        versions = self.file_manager.list_file_versions(file_id)

        # Create versions dialog
        dialog = ctk.CTkToplevel(self.root)
        dialog.title(f"File Versions - {filename}")
        dialog.geometry("600x400")
        dialog.transient(self.root)
        dialog.grab_set()

        ctk.CTkLabel(
            dialog,
            text=f"Versions for: {filename}",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(pady=(20, 10))

        if not versions:
            ctk.CTkLabel(dialog, text="No versions available").pack(pady=20)
        else:
            # Versions list
            versions_frame = ctk.CTkScrollableFrame(dialog, height=250)
            versions_frame.pack(fill="both", expand=True, padx=20, pady=10)

            for version in versions:
                version_frame = ctk.CTkFrame(versions_frame)
                version_frame.pack(fill="x", pady=2)

                version_text = (
                    f"Version {version['version_number']} - "
                    f"{version['created_at'].strftime('%Y-%m-%d %H:%M')} - "
                    f"{version['created_by']}"
                )
                ctk.CTkLabel(version_frame, text=version_text, width=400).pack(
                    side="left", padx=5
                )

                if version.get("notes"):
                    ctk.CTkLabel(
                        version_frame, text=f"({version['notes']})", width=150
                    ).pack(side="left", padx=5)

        ctk.CTkButton(dialog, text="Close", command=dialog.destroy, width=200).pack(
            pady=20
        )

    def handle_export_file_list(self) -> None:
        """Export file list to CSV"""
        export_path = filedialog.asksaveasfilename(
            title="Export File List",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )

        if export_path:
            try:
                self.status_bar.configure(text="Exporting file list...")
                success, message = self.file_manager.export_file_list(
                    self.current_user.username, Path(export_path)
                )
                if success:
                    self._show_success("Export Successful", message)
                else:
                    self._show_error("Export Failed", message)
            except Exception as e:
                logger.error(f"Export error: {e}")
                self._show_error("Export Error", f"An error occurred: {str(e)}")
            finally:
                self.status_bar.configure(text="Ready")

    def handle_backup(self) -> None:
        """Create system backup"""
        if self.current_user.role != "admin":
            self._show_error("Access Denied", "Admin access required")
            return

        backup_path = filedialog.askdirectory(title="Select Backup Location")
        if backup_path:
            try:
                self.status_bar.configure(text="Creating backup...")
                success, message = self.file_manager.export_backup(Path(backup_path))
                if success:
                    self._show_success("Backup Successful", message)
                else:
                    self._show_error("Backup Failed", message)
            except Exception as e:
                logger.error(f"Backup error: {e}")
                self._show_error("Backup Error", f"An error occurred: {str(e)}")
            finally:
                self.status_bar.configure(text="Ready")

    def handle_logout(self):
        """Handle user logout"""
        if self.current_session:
            self.session_manager.destroy_session(self.current_session)
            self.audit_logger.log_logout(self.current_user.username)

        self.current_user = None
        self.current_session = None

        self.show_login_screen()

    def run(self):
        """Run the application"""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            logger.info("Application interrupted by user")
        finally:
            # Cleanup
            if self.current_session:
                self.session_manager.destroy_session(self.current_session)
            self.file_manager.cleanup_temp_files()


if __name__ == "__main__":
    app = SecureApp()
    app.run()
