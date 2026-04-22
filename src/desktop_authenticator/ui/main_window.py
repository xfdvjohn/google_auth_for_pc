"""Main window: account list with live TOTP codes."""

from __future__ import annotations

import time

from PySide6.QtCore import Qt, QTimer, QRectF
from PySide6.QtGui import QAction, QColor, QGuiApplication, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from ..totp import current_code, seconds_remaining
from ..vault import Account, Vault
from .dialogs import AccountDialog


class AccountRow(QWidget):
    """One row: issuer/name on left, big code + countdown ring on right."""

    def __init__(self, account: Account, parent=None):
        super().__init__(parent)
        self.account = account
        self._code = ""
        self._remaining = 0.0

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)

        left = QVBoxLayout()
        self.issuer_label = QLabel()
        self.issuer_label.setStyleSheet("font-weight: 600; font-size: 13px;")
        self.name_label = QLabel()
        self.name_label.setStyleSheet("color: #666; font-size: 11px;")
        left.addWidget(self.issuer_label)
        left.addWidget(self.name_label)
        layout.addLayout(left, stretch=1)

        self.code_label = QLabel()
        self.code_label.setStyleSheet(
            "font-family: 'Consolas','Menlo',monospace;"
            "font-size: 26px; font-weight: 600; letter-spacing: 4px;"
        )
        layout.addWidget(self.code_label)

        self.ring = CountdownRing()
        layout.addWidget(self.ring)

        self.refresh()

    def refresh(self) -> None:
        issuer = self.account.issuer or "(no issuer)"
        name = self.account.name or ""
        self.issuer_label.setText(issuer)
        self.name_label.setText(name)
        try:
            code = current_code(self.account)
        except Exception as e:
            code = "------"
            self.name_label.setText(f"{name}  ERROR: {e}")
        # Pretty-print as "123 456"
        if len(code) == 6:
            pretty = f"{code[:3]} {code[3:]}"
        elif len(code) == 8:
            pretty = f"{code[:4]} {code[4:]}"
        else:
            pretty = code
        self._code = code
        self.code_label.setText(pretty)
        self._remaining = seconds_remaining(self.account)
        self.ring.set_progress(self._remaining / self.account.period, self._remaining)

    def current_code_plain(self) -> str:
        return self._code


class CountdownRing(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(44, 44)
        self._fraction = 1.0
        self._seconds = 0.0

    def set_progress(self, fraction: float, seconds: float) -> None:
        self._fraction = max(0.0, min(1.0, fraction))
        self._seconds = seconds
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(3, 3, self.width() - 6, self.height() - 6)

        pen_bg = QPen(QColor("#e0e0e0"), 3)
        p.setPen(pen_bg)
        p.drawEllipse(rect)

        color = QColor("#2e7d32") if self._fraction > 0.25 else QColor("#c62828")
        pen_fg = QPen(color, 3, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        p.setPen(pen_fg)
        span = int(-360 * 16 * self._fraction)
        p.drawArc(rect, 90 * 16, span)

        p.setPen(QColor("#333"))
        p.drawText(
            self.rect(),
            Qt.AlignmentFlag.AlignCenter,
            str(int(self._seconds) + 1),
        )


class MainWindow(QMainWindow):
    def __init__(self, vault: Vault):
        super().__init__()
        self.vault = vault
        self.setWindowTitle("Desktop Authenticator")
        self.resize(520, 560)

        self._build_toolbar()

        central = QWidget()
        self.setCentralWidget(central)
        v = QVBoxLayout(central)
        v.setContentsMargins(0, 0, 0, 0)

        self.list = QListWidget()
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.list.itemClicked.connect(self._copy_current)
        self.list.setStyleSheet(
            "QListWidget::item { border-bottom: 1px solid #eee; }"
            "QListWidget::item:selected { background: #e3f2fd; color: black; }"
        )
        v.addWidget(self.list)

        self.status = QLabel("Click a row to copy the code.")
        self.status.setStyleSheet("padding: 6px 10px; color: #555;")
        v.addWidget(self.status)

        self._reload_list()

        self.timer = QTimer(self)
        self.timer.setInterval(500)
        self.timer.timeout.connect(self._tick)
        self.timer.start()

    def _build_toolbar(self) -> None:
        tb = QToolBar()
        tb.setMovable(False)
        self.addToolBar(tb)

        add = QAction("Add", self)
        add.triggered.connect(self._add_account)
        tb.addAction(add)

        edit = QAction("Edit", self)
        edit.triggered.connect(self._edit_account)
        tb.addAction(edit)

        delete = QAction("Delete", self)
        delete.triggered.connect(self._delete_account)
        tb.addAction(delete)

        tb.addSeparator()

        copy = QAction("Copy code", self)
        copy.triggered.connect(self._copy_current)
        tb.addAction(copy)

    def _reload_list(self) -> None:
        self.list.clear()
        for acc in self.vault.data.accounts:
            item = QListWidgetItem()
            row = AccountRow(acc)
            item.setSizeHint(row.sizeHint())
            self.list.addItem(item)
            self.list.setItemWidget(item, row)

    def _tick(self) -> None:
        for i in range(self.list.count()):
            w = self.list.itemWidget(self.list.item(i))
            if isinstance(w, AccountRow):
                w.refresh()

    def _selected_index(self) -> int:
        row = self.list.currentRow()
        return row if row >= 0 else -1

    def _selected_row_widget(self) -> AccountRow | None:
        idx = self._selected_index()
        if idx < 0:
            return None
        w = self.list.itemWidget(self.list.item(idx))
        return w if isinstance(w, AccountRow) else None

    def _add_account(self) -> None:
        dlg = AccountDialog(self)
        if dlg.exec() == dlg.DialogCode.Accepted:
            accs = dlg.result_accounts()
            if not accs:
                return
            self.vault.data.accounts.extend(accs)
            self.vault.save()
            self._reload_list()
            if len(accs) == 1:
                self.status.setText(f"Added {accs[0].issuer or accs[0].name}.")
            else:
                self.status.setText(f"Added {len(accs)} accounts.")

    def _edit_account(self) -> None:
        idx = self._selected_index()
        if idx < 0:
            return
        existing = self.vault.data.accounts[idx]
        dlg = AccountDialog(self, existing=existing)
        if dlg.exec() == dlg.DialogCode.Accepted:
            accs = dlg.result_accounts()
            if not accs:
                return
            self.vault.data.accounts[idx] = accs[0]
            self.vault.save()
            self._reload_list()
            self.list.setCurrentRow(idx)
            self.status.setText("Account updated.")

    def _delete_account(self) -> None:
        idx = self._selected_index()
        if idx < 0:
            return
        acc = self.vault.data.accounts[idx]
        label = f"{acc.issuer}: {acc.name}" if acc.issuer else acc.name
        ok = QMessageBox.question(
            self,
            "Delete account",
            f"Delete {label!r}? The secret will be removed from the vault.",
        )
        if ok == QMessageBox.StandardButton.Yes:
            del self.vault.data.accounts[idx]
            self.vault.save()
            self._reload_list()
            self.status.setText("Deleted.")

    def _copy_current(self) -> None:
        w = self._selected_row_widget()
        if w is None:
            return
        QGuiApplication.clipboard().setText(w.current_code_plain())
        self.status.setText(
            f"Copied code for {w.account.issuer or w.account.name} to clipboard."
        )
