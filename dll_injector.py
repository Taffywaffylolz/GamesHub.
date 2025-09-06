import sys
import os
import ctypes
import psutil
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QLineEdit,
    QFileDialog,
    QMessageBox,
    QGroupBox,
    QPlainTextEdit,
    QProgressBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QAction,
    QToolBar,
)
from PyQt5.QtCore import Qt, QTimer, QDateTime
from PyQt5.QtGui import QFont


def is_windows_platform() -> bool:
    return sys.platform.startswith("win32")


# Windows-only handles (guarded)
if is_windows_platform():
    kernel32 = ctypes.windll.kernel32
else:
    kernel32 = None  # type: ignore[assignment]


class DLLInjector(QMainWindow):
    """Main application window for DLL injection and diagnostics (safe build)."""

    def __init__(self) -> None:
        super().__init__()

        self.target_process_name = ""
        self.target_pid = None  # type: ignore[assignment]
        self.dll_path = ""

        self.setWindowTitle("Advanced DLL Injector & Memory Editor (Safe)")
        self.setGeometry(60, 60, 1200, 800)
        self.setMinimumSize(1100, 720)

        self.apply_theme()
        self.create_menu_bar()
        self.create_toolbar()
        self.create_central_tabs()
        self.create_status_bar()

        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self._tick)
        self.update_timer.start(1000)

        self.log_message("Application initialized.")
        self.refresh_processes()

    # --------------------------- UI SETUP ---------------------------
    def apply_theme(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow { background-color: #1e1e1e; color: #d4d4d4; }
            QToolBar { background-color: #2d2d30; border: none; }
            QToolBar QToolButton { padding: 6px 10px; }
            QTabWidget::pane { border: 1px solid #3e3e42; background: #1e1e1e; }
            QTabBar::tab { background: #2d2d30; padding: 8px 16px; margin-right: 2px; }
            QTabBar::tab:selected { background: #1e1e1e; }
            QPushButton { background: #0e639c; color: white; border: 1px solid #0e639c; border-radius: 3px; padding: 6px 12px; }
            QPushButton:hover { background: #1177bb; border-color: #1177bb; }
            QLineEdit, QPlainTextEdit { background: #1e1e1e; color: #d4d4d4; border: 1px solid #3e3e42; border-radius: 3px; padding: 6px; }
            QTableWidget { background: #1e1e1e; color: #d4d4d4; border: 1px solid #3e3e42; }
            QProgressBar { background: #1e1e1e; border: 1px solid #3e3e42; border-radius: 3px; text-align: center; }
            QProgressBar::chunk { background: #0e639c; }
            """
        )

    def create_menu_bar(self) -> None:
        menubar = self.menuBar()
        file_menu = menubar.addMenu("&File")

        open_action = QAction("&Open Process", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self._focus_process_tab)
        file_menu.addAction(open_action)

        file_menu.addSeparator()
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        tools_menu = menubar.addMenu("&Tools")
        refresh_action = QAction("&Refresh Processes", self)
        refresh_action.setShortcut("F5")
        refresh_action.triggered.connect(self.refresh_processes)
        tools_menu.addAction(refresh_action)

        help_menu = menubar.addMenu("&Help")
        about_action = QAction("&About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def create_toolbar(self) -> None:
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)

        attach_action = QAction("🔗 Attach", self)
        attach_action.triggered.connect(self.attach_selected_process)
        toolbar.addAction(attach_action)

        inject_action = QAction("💉 Inject", self)
        inject_action.triggered.connect(self.inject_dll)
        toolbar.addAction(inject_action)

        toolbar.addSeparator()

        refresh_action = QAction("🔄 Refresh", self)
        refresh_action.triggered.connect(self.refresh_processes)
        toolbar.addAction(refresh_action)

        self.addToolBar(toolbar)

    def create_central_tabs(self) -> None:
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self._create_process_tab()
        self._create_injector_tab()
        self._create_keyauth_tab()

    def create_status_bar(self) -> None:
        self.status_label = QLabel("Ready")
        self.statusBar().addWidget(self.status_label)

    # ------------------------ PROCESS MANAGER ------------------------
    def _create_process_tab(self) -> None:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        controls = QHBoxLayout()
        self.attach_btn = QPushButton("🔗 Attach Process")
        self.attach_btn.clicked.connect(self.attach_selected_process)
        controls.addWidget(self.attach_btn)

        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self.refresh_processes)
        controls.addWidget(self.refresh_btn)

        controls.addStretch()
        layout.addLayout(controls)

        self.process_table = QTableWidget(0, 5)
        self.process_table.setHorizontalHeaderLabels(["PID", "Name", "CPU %", "Memory (MB)", "Status"])
        self.process_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.process_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.process_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.process_table.setSortingEnabled(True)
        layout.addWidget(self.process_table)

        log_group = QGroupBox("Activity Log")
        log_layout = QVBoxLayout(log_group)
        self.log_area = QPlainTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setMaximumHeight(180)
        self.log_area.setFont(QFont("Consolas", 10))
        log_layout.addWidget(self.log_area)
        layout.addWidget(log_group)

        self.tabs.addTab(widget, "Process Manager")

    def refresh_processes(self) -> None:
        self.process_table.setRowCount(0)
        try:
            processes = list(psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "status"]))
            self.process_table.setRowCount(len(processes))
            for row, proc in enumerate(sorted(processes, key=lambda p: (p.info.get("name") or "").lower())):
                pid = proc.info.get("pid")
                name = proc.info.get("name") or "?"
                cpu = proc.info.get("cpu_percent") or 0.0
                mem = proc.info.get("memory_info").rss / 1024 / 1024 if proc.info.get("memory_info") else 0.0
                status = proc.info.get("status") or "?"

                self.process_table.setItem(row, 0, QTableWidgetItem(str(pid)))
                self.process_table.setItem(row, 1, QTableWidgetItem(name))
                self.process_table.setItem(row, 2, QTableWidgetItem(f"{cpu:.1f}"))
                self.process_table.setItem(row, 3, QTableWidgetItem(f"{mem:.1f}"))
                self.process_table.setItem(row, 4, QTableWidgetItem(status))

            self.log_message(f"Found {len(processes)} running processes")
            self.status_label.setText("Process list refreshed")
        except Exception as exc:
            self.log_message(f"Error refreshing processes: {exc}")

    def attach_selected_process(self) -> None:
        row = self.process_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Warning", "Select a process first.")
            return
        pid_item = self.process_table.item(row, 0)
        name_item = self.process_table.item(row, 1)
        if not pid_item or not name_item:
            QMessageBox.warning(self, "Warning", "Invalid selection.")
            return
        self.target_pid = int(pid_item.text())
        self.target_process_name = name_item.text()
        self.status_label.setText(f"Attached to: {self.target_process_name} (PID {self.target_pid})")
        self.log_message(f"Attached to process: {self.target_process_name} (PID {self.target_pid})")

    # ---------------------------- INJECTOR ---------------------------
    def _create_injector_tab(self) -> None:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        group = QGroupBox("DLL Injection")
        g_layout = QVBoxLayout(group)

        path_row = QHBoxLayout()
        self.dll_path_edit = QLineEdit()
        self.dll_path_edit.setPlaceholderText("Select DLL file to inject...")
        path_row.addWidget(self.dll_path_edit)
        browse_btn = QPushButton("📁 Browse")
        browse_btn.clicked.connect(self._browse_dll)
        path_row.addWidget(browse_btn)
        g_layout.addLayout(path_row)

        actions_row = QHBoxLayout()
        self.inject_btn = QPushButton("💉 Inject DLL")
        self.inject_btn.clicked.connect(self.inject_dll)
        actions_row.addWidget(self.inject_btn)
        actions_row.addStretch()
        g_layout.addLayout(actions_row)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        g_layout.addWidget(self.progress_bar)

        layout.addWidget(group)
        self.tabs.addTab(widget, "DLL Injector")

    def _browse_dll(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Select DLL File", "", "DLL Files (*.dll);;All Files (*)")
        if file_path:
            self.dll_path = file_path
            self.dll_path_edit.setText(file_path)
            self.status_label.setText("DLL selected")

    def inject_dll(self) -> None:
        if not self.target_process_name or not self.target_pid:
            QMessageBox.warning(self, "Warning", "Attach to a process first.")
            return
        if not self.dll_path or not os.path.exists(self.dll_path):
            QMessageBox.warning(self, "Warning", "Select a valid DLL file.")
            return
        if not is_windows_platform():
            QMessageBox.information(
                self,
                "Not Supported",
                "DLL injection is available on Windows only in this safe build.",
            )
            return

        # Placeholder UX only
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.log_message(f"Starting injection of {os.path.basename(self.dll_path)} into {self.target_process_name}")
        self.progress_bar.setValue(100)
        QMessageBox.information(self, "Info", "Injection routine is stubbed in this safe build.")
        self.progress_bar.setVisible(False)

    # ---------------------- KEYAUTH DIAGNOSTICS TAB ------------------
    def _create_keyauth_tab(self) -> None:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        group = QGroupBox("Keyauth Diagnostics")
        g_layout = QVBoxLayout(group)

        file_row = QHBoxLayout()
        self.ka_file_edit = QLineEdit()
        self.ka_file_edit.setPlaceholderText("Select an executable or file to analyze...")
        file_row.addWidget(self.ka_file_edit)
        browse_btn = QPushButton("📁 Browse")
        browse_btn.clicked.connect(self._browse_keyauth_file)
        file_row.addWidget(browse_btn)
        g_layout.addLayout(file_row)

        actions_row = QHBoxLayout()
        detect_btn = QPushButton("🔍 Detect Key System")
        detect_btn.clicked.connect(self._detect_keyauth)
        actions_row.addWidget(detect_btn)

        patch_btn = QPushButton("⚠️ Patch (Disabled)")
        patch_btn.setEnabled(False)
        patch_btn.setToolTip("Patching or bypassing authentication is not supported.")
        actions_row.addWidget(patch_btn)
        actions_row.addStretch()
        g_layout.addLayout(actions_row)

        self.ka_result = QPlainTextEdit()
        self.ka_result.setReadOnly(True)
        self.ka_result.setPlaceholderText("Results will appear here...")
        self.ka_result.setMaximumHeight(220)
        g_layout.addWidget(self.ka_result)

        layout.addWidget(group)
        self.tabs.addTab(widget, "Keyauth Diagnostics")

    def _browse_keyauth_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)")
        if file_path:
            self.ka_file_edit.setText(file_path)

    def _detect_keyauth(self) -> None:
        path = self.ka_file_edit.text().strip()
        if not path:
            QMessageBox.warning(self, "Warning", "Select a file first.")
            return
        if not os.path.exists(path) or not os.path.isfile(path):
            QMessageBox.critical(self, "Error", "File does not exist.")
            return

        # Heuristic, non-invasive scan for indicative strings
        try:
            found_markers = []
            markers = [
                b"keyauth",
                b"KeyAuth",
                b"KEYAUTH",
                b"license",
                b"auth",
            ]
            with open(path, "rb") as f:
                data = f.read()
                for marker in markers:
                    if marker in data:
                        found_markers.append(marker.decode(errors="ignore"))

            if found_markers:
                self.ka_result.setPlainText(
                    "Possible key system indicators found:\n" + "\n".join(f"- {m}" for m in found_markers)
                )
                self.log_message(f"Key system indicators detected in '{os.path.basename(path)}'.")
            else:
                self.ka_result.setPlainText("No obvious key system indicators found.")
                self.log_message("No key system indicators found.")
        except Exception as exc:
            QMessageBox.critical(self, "Error", f"Failed to analyze file: {exc}")

    # ---------------------------- HELPERS ----------------------------
    def _focus_process_tab(self) -> None:
        self.tabs.setCurrentIndex(0)

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About",
            (
                "Advanced DLL Injector & Memory Editor (Safe)\n\n"
                "This build provides diagnostics and UI only.\n"
                "Windows-only features are guarded to avoid issues on Linux."
            ),
        )

    def log_message(self, message: str) -> None:
        current_time = QDateTime.currentDateTime().toString("hh:mm:ss")
        text = f"[{current_time}] {message}"
        if hasattr(self, "log_area") and self.log_area is not None:
            self.log_area.appendPlainText(text)
            sb = self.log_area.verticalScrollBar()
            sb.setValue(sb.maximum())
        self.status_label.setText(message)

    def _tick(self) -> None:
        # Reserved for periodic updates (e.g., process info refresh)
        pass


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("DLL Injector (Safe)")
    app.setApplicationVersion("2.1")
    app.setStyle("Fusion")

    window = DLLInjector()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

