"""Application entry point."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication, QMessageBox

from .ui.dialogs import UnlockDialog
from .ui.main_window import MainWindow
from .vault import InvalidPassword, Vault, default_vault_path


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Desktop Authenticator")

    vault_path = default_vault_path()
    vault: Vault | None = None

    while vault is None:
        exists = vault_path.exists()
        dlg = UnlockDialog(vault_exists=exists)
        if dlg.exec() != dlg.DialogCode.Accepted:
            return 0
        pw = dlg.password
        assert pw is not None
        try:
            if exists:
                vault = Vault.load(vault_path, pw)
            else:
                vault = Vault.create(vault_path, pw)
        except InvalidPassword:
            QMessageBox.critical(
                None,
                "Wrong password",
                "The master password is incorrect. Try again.",
            )
        except Exception as e:
            QMessageBox.critical(None, "Vault error", str(e))
            return 1

    window = MainWindow(vault)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
