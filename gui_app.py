#!/usr/bin/env python3
"""
Lightweight PySide6 GUI for building migration discovery workbooks.
Runs build_workbook in a worker thread; UI stays responsive. Cancel via cancel_event.
"""
import sys
import threading
import traceback
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

# Import after Qt so we can show a message if deps missing
try:
    from build_migration_workbook import (
        BuildResult,
        CancelledError,
        build_workbook,
    )
except Exception as e:
    print(f"Failed to import build_migration_workbook: {e}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)


class Worker(QObject):
    """Runs build_workbook in a background thread. Communicate only via Qt signals."""

    progress = Signal(int, int, str)  # done, total, current_file (or status)
    log = Signal(str)
    status = Signal(str)
    finished = Signal(object)   # BuildResult
    failed = Signal(str, str)   # user_msg, traceback_text

    def __init__(self, input_folder: str, output_path: str, **build_kwargs):
        super().__init__()
        self.input_folder = input_folder
        self.output_path = output_path
        self.build_kwargs = build_kwargs
        self.cancel_event = threading.Event()

    def run(self):
        self.cancel_event.clear()
        self._current_activity = ""

        def status_cb(msg: str) -> None:
            self._current_activity = msg
            self.status.emit(msg)

        def log_cb(msg: str) -> None:
            self.log.emit(msg)

        def progress_cb(done: int, total: int) -> None:
            self.progress.emit(done, total, self._current_activity)

        try:
            result = build_workbook(
                self.input_folder,
                self.output_path,
                cancel_event=self.cancel_event,
                progress_cb=progress_cb,
                log_cb=log_cb,
                status_cb=status_cb,
                **self.build_kwargs,
            )
            self.finished.emit(result)
        except CancelledError:
            # Result may be partial; emit cancelled result if we have one, else minimal
            self.finished.emit(
                BuildResult(
                    workbook_path=None,
                    report_path=None,
                    warnings=0,
                    errors=0,
                    cancelled=True,
                )
            )
        except Exception as e:
            tb = traceback.format_exc()
            self.failed.emit(str(e), tb)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Migration Discovery Workbook Builder")
        self.worker = None
        self.thread = None
        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # --- Paths ---
        path_group = QGroupBox("Paths")
        path_layout = QGridLayout(path_group)
        path_layout.addWidget(QLabel("Input folder:"), 0, 0)
        self.input_edit = QLineEdit()
        self.input_edit.setPlaceholderText("Folder containing discovery JSON files")
        path_layout.addWidget(self.input_edit, 0, 1)
        self.input_btn = QPushButton("Browse…")
        self.input_btn.clicked.connect(self._pick_input_folder)
        path_layout.addWidget(self.input_btn, 0, 2)

        path_layout.addWidget(QLabel("Output file:"), 1, 0)
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("Path to .xlsx workbook")
        path_layout.addWidget(self.output_edit, 1, 1)
        self.output_btn = QPushButton("Browse…")
        self.output_btn.clicked.connect(self._pick_output_file)
        path_layout.addWidget(self.output_btn, 1, 2)

        layout.addWidget(path_group)

        # --- Options ---
        opt_group = QGroupBox("Options")
        opt_layout = QVBoxLayout(opt_group)
        self.check_sanitize = QCheckBox("Emit sanitize report when issues found (--debug)")
        self.check_sanitize.setChecked(False)
        opt_layout.addWidget(self.check_sanitize)
        self.check_validate_only = QCheckBox("Validate only (no Excel output)")
        self.check_validate_only.setChecked(False)
        opt_layout.addWidget(self.check_validate_only)
        self.check_include_sourcefile = QCheckBox("Include SourceFile in every sheet")
        self.check_include_sourcefile.setChecked(False)
        opt_layout.addWidget(self.check_include_sourcefile)
        self.check_fail_fast = QCheckBox("Fail fast (stop on first issue)")
        self.check_fail_fast.setChecked(False)
        opt_layout.addWidget(self.check_fail_fast)
        layout.addWidget(opt_group)

        # --- Buttons ---
        btn_layout = QVBoxLayout()
        self.run_btn = QPushButton("Run")
        self.run_btn.clicked.connect(self._on_run)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self._on_cancel)
        self.cancel_btn.setEnabled(False)
        btn_layout.addWidget(self.run_btn)
        btn_layout.addWidget(self.cancel_btn)
        layout.addLayout(btn_layout)

        # --- Progress ---
        layout.addWidget(QLabel("Progress"))
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # indeterminate until we get progress
        layout.addWidget(self.progress_bar)

        # --- Status ---
        self.status_label = QLabel("Ready.")
        layout.addWidget(self.status_label)

        # --- Log ---
        layout.addWidget(QLabel("Log"))
        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMinimumHeight(120)
        layout.addWidget(self.log_text)

    def _pick_input_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select input folder")
        if folder:
            self.input_edit.setText(folder)

    def _pick_output_file(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save workbook as",
            "",
            "Excel (*.xlsx);;All files (*)",
        )
        if path:
            self.output_edit.setText(path)

    def _on_run(self):
        input_folder = self.input_edit.text().strip()
        output_path = self.output_edit.text().strip()
        if not input_folder:
            self.status_label.setText("Please select an input folder.")
            return
        if not output_path and not self.check_validate_only.isChecked():
            self.status_label.setText("Please select an output file (or use Validate only).")
            return
        if not output_path:
            output_path = str(Path(input_folder) / "validate_output.xlsx")  # dummy for validate_only

        self.log_text.clear()
        self.log_text.appendPlainText("Starting…")
        self.status_label.setText("Running…")
        self.run_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setValue(0)

        build_kwargs = {
            "validate_only": self.check_validate_only.isChecked(),
            "sanitize": self.check_sanitize.isChecked(),
            "include_sourcefile": self.check_include_sourcefile.isChecked(),
            "fail_fast": self.check_fail_fast.isChecked(),
        }

        self.thread = QThread()
        self.worker = Worker(input_folder, output_path, **build_kwargs)
        self.worker.moveToThread(self.thread)

        self.worker.progress.connect(self._on_progress)
        self.worker.log.connect(self._on_log)
        self.worker.status.connect(self._on_status)
        self.worker.finished.connect(self._on_finished)
        self.worker.failed.connect(self._on_failed)

        self.thread.started.connect(self.worker.run)
        self.thread.start()

    @Slot(int, int, str)
    def _on_progress(self, done: int, total: int, current_file: str):
        if total > 0:
            self.progress_bar.setRange(0, total)
            self.progress_bar.setValue(done)
        if current_file:
            self.status_label.setText(current_file)

    @Slot(str)
    def _on_log(self, message: str):
        self.log_text.appendPlainText(message)

    @Slot(str)
    def _on_status(self, message: str):
        self.status_label.setText(message)

    @Slot(object)
    def _on_finished(self, result: BuildResult):
        self.thread.quit()
        self.thread.wait()
        self.run_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)

        if result.cancelled:
            self.status_label.setText("Cancelled.")
            self.log_text.appendPlainText("Cancelled by user.")
        else:
            summary = f"Done. Warnings: {result.warnings}, Errors: {result.errors}"
            if result.workbook_path:
                summary += f" — {result.workbook_path}"
            self.status_label.setText(summary)
            self.log_text.appendPlainText(summary)

    @Slot(str, str)
    def _on_failed(self, user_msg: str, tb: str):
        self.thread.quit()
        self.thread.wait()
        self.run_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"Error: {user_msg[:80]}…" if len(user_msg) > 80 else f"Error: {user_msg}")
        self.log_text.appendPlainText("--- Error ---")
        self.log_text.appendPlainText(user_msg)
        self.log_text.appendPlainText(tb)

    def _on_cancel(self):
        """Set cancel_event so build_workbook stops (checked each file/sheet iteration)."""
        if self.worker and self.worker.cancel_event:
            self.worker.cancel_event.set()
            self.status_label.setText("Cancelling…")


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.resize(640, 520)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
