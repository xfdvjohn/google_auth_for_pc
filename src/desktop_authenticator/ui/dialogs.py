"""Dialogs: unlock / create vault, add / edit account."""

from __future__ import annotations

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..qr import QRDecodeError, decode_qr_from_bytes, decode_qr_from_file
from ..totp import normalize_secret, parse_otpauth_uri
from ..vault import Account


class UnlockDialog(QDialog):
    """Prompt for the master password. If vault_exists=False, asks to create one."""

    def __init__(self, vault_exists: bool, parent=None):
        super().__init__(parent)
        self.vault_exists = vault_exists
        self.setWindowTitle(
            "Unlock vault" if vault_exists else "Create vault"
        )
        self.setModal(True)

        layout = QVBoxLayout(self)
        if vault_exists:
            layout.addWidget(QLabel("Enter your master password to unlock the vault."))
        else:
            layout.addWidget(
                QLabel(
                    "No vault found. Create a new one by choosing a master password.\n"
                    "This password encrypts your TOTP secrets on disk — if you "
                    "forget it, the secrets cannot be recovered."
                )
            )

        form = QFormLayout()
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Master password:", self.pw)
        if not vault_exists:
            self.pw2 = QLineEdit()
            self.pw2.setEchoMode(QLineEdit.EchoMode.Password)
            form.addRow("Confirm password:", self.pw2)
        else:
            self.pw2 = None
        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._on_ok)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.password: str | None = None
        self.pw.setFocus()

    def _on_ok(self) -> None:
        pw = self.pw.text()
        if not pw:
            QMessageBox.warning(self, "Password required", "Please enter a password.")
            return
        if self.pw2 is not None:
            if pw != self.pw2.text():
                QMessageBox.warning(self, "Mismatch", "Passwords do not match.")
                return
            if len(pw) < 8:
                QMessageBox.warning(
                    self, "Weak password", "Use at least 8 characters."
                )
                return
        self.password = pw
        self.accept()


class AccountDialog(QDialog):
    """Add or edit an account. Three tabs: manual entry, otpauth URI paste, QR scan."""

    def __init__(self, parent=None, existing: Account | None = None):
        super().__init__(parent)
        self.setWindowTitle("Edit account" if existing else "Add account")
        self.setModal(True)
        self.resize(420, 340)
        self._result: Account | None = None

        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        self.tabs.addTab(self._build_manual_tab(existing), "Manual entry")
        self.tabs.addTab(self._build_uri_tab(), "Paste otpauth URI")
        self.tabs.addTab(self._build_qr_tab(), "Scan QR code")

        if existing is not None:
            # Editing: disable the URI/QR tabs to avoid confusion.
            self.tabs.setTabEnabled(1, False)
            self.tabs.setTabEnabled(2, False)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._on_ok)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _build_manual_tab(self, existing: Account | None) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        self.issuer = QLineEdit(existing.issuer if existing else "")
        self.issuer.setPlaceholderText("e.g. Google, GitHub, AWS")
        self.name = QLineEdit(existing.name if existing else "")
        self.name.setPlaceholderText("e.g. alice@example.com")
        self.secret = QLineEdit(existing.secret if existing else "")
        self.secret.setPlaceholderText("Base32 secret (spaces allowed)")
        self.secret.setEchoMode(QLineEdit.EchoMode.Password)

        self.digits = QSpinBox()
        self.digits.setRange(6, 8)
        self.digits.setValue(existing.digits if existing else 6)

        self.period = QSpinBox()
        self.period.setRange(15, 120)
        self.period.setSingleStep(15)
        self.period.setValue(existing.period if existing else 30)

        self.algorithm = QComboBox()
        self.algorithm.addItems(["SHA1", "SHA256", "SHA512"])
        if existing:
            idx = self.algorithm.findText(existing.algorithm)
            if idx >= 0:
                self.algorithm.setCurrentIndex(idx)

        form.addRow("Issuer:", self.issuer)
        form.addRow("Account name:", self.name)
        form.addRow("Secret:", self.secret)
        form.addRow("Digits:", self.digits)
        form.addRow("Period (s):", self.period)
        form.addRow("Algorithm:", self.algorithm)
        return w

    def _build_uri_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.addWidget(
            QLabel(
                "Paste the full otpauth:// URI shown by the service\n"
                "(e.g. otpauth://totp/Google:alice@example.com?secret=...&issuer=Google)"
            )
        )
        self.uri = QPlainTextEdit()
        self.uri.setPlaceholderText("otpauth://totp/...")
        layout.addWidget(self.uri)
        return w

    def _build_qr_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.addWidget(
            QLabel(
                "Import an account by scanning a QR code image.\n"
                "Load a saved screenshot, or paste an image copied to the clipboard."
            )
        )

        btn_row = QHBoxLayout()
        load_btn = QPushButton("Load image file...")
        load_btn.clicked.connect(self._scan_qr_from_file)
        paste_btn = QPushButton("Paste image from clipboard")
        paste_btn.clicked.connect(self._scan_qr_from_clipboard)
        btn_row.addWidget(load_btn)
        btn_row.addWidget(paste_btn)
        btn_row.addStretch(1)
        layout.addLayout(btn_row)

        self.qr_status = QLabel("No QR code scanned yet.")
        self.qr_status.setWordWrap(True)
        self.qr_status.setStyleSheet("color: #555; padding-top: 8px;")
        layout.addWidget(self.qr_status)
        layout.addStretch(1)
        return w

    def _scan_qr_from_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select QR code image",
            "",
            "Images (*.png *.jpg *.jpeg *.bmp *.gif *.webp);;All files (*.*)",
        )
        if not path:
            return
        try:
            uri = decode_qr_from_file(path)
        except QRDecodeError as e:
            self._set_qr_error(str(e))
            return
        self._apply_qr_payload(uri)

    def _scan_qr_from_clipboard(self) -> None:
        cb = QGuiApplication.clipboard()
        qimg = cb.image()
        if qimg.isNull():
            self._set_qr_error(
                "Clipboard has no image. Copy the QR code screenshot and try again."
            )
            return
        ba = QByteArray()
        buf = QBuffer(ba)
        buf.open(QIODevice.OpenModeFlag.WriteOnly)
        qimg.save(buf, "PNG")
        try:
            uri = decode_qr_from_bytes(bytes(ba))
        except QRDecodeError as e:
            self._set_qr_error(str(e))
            return
        self._apply_qr_payload(uri)

    def _apply_qr_payload(self, payload: str) -> None:
        try:
            acc = parse_otpauth_uri(payload)
        except ValueError as e:
            self._set_qr_error(
                f"QR code decoded but is not a valid otpauth URI: {e}"
            )
            return
        self._populate_manual_fields(acc)
        self.qr_status.setStyleSheet("color: #2e7d32; padding-top: 8px;")
        label = f"{acc.issuer}: {acc.name}" if acc.issuer else acc.name
        self.qr_status.setText(
            f"Imported {label!r}. Review the fields on 'Manual entry' and click OK."
        )
        self.tabs.setCurrentIndex(0)

    def _set_qr_error(self, message: str) -> None:
        self.qr_status.setStyleSheet("color: #c62828; padding-top: 8px;")
        self.qr_status.setText(message)

    def _populate_manual_fields(self, acc: Account) -> None:
        self.issuer.setText(acc.issuer)
        self.name.setText(acc.name)
        self.secret.setText(acc.secret)
        self.digits.setValue(acc.digits)
        self.period.setValue(acc.period)
        idx = self.algorithm.findText(acc.algorithm)
        if idx >= 0:
            self.algorithm.setCurrentIndex(idx)

    def _on_ok(self) -> None:
        try:
            if self.tabs.currentIndex() == 1:
                text = self.uri.toPlainText().strip()
                if not text:
                    raise ValueError("Paste an otpauth:// URI first.")
                acc = parse_otpauth_uri(text)
            else:
                acc = Account(
                    issuer=self.issuer.text().strip(),
                    name=self.name.text().strip(),
                    secret=normalize_secret(self.secret.text()),
                    digits=self.digits.value(),
                    period=self.period.value(),
                    algorithm=self.algorithm.currentText(),
                )
                if not acc.name and not acc.issuer:
                    raise ValueError("Provide at least an issuer or account name.")
        except ValueError as e:
            QMessageBox.warning(self, "Invalid input", str(e))
            return
        self._result = acc
        self.accept()

    def result_account(self) -> Account | None:
        return self._result
