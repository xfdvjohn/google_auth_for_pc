# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Dependency management is via [uv](https://github.com/astral-sh/uv). Python >=3.12 is required.

```powershell
uv sync                        # create .venv/ and install pinned deps from uv.lock
uv run desktop-authenticator   # launch the GUI (entry point = desktop_authenticator.app:main)
uv run python -m desktop_authenticator.app   # equivalent
```

There is **no test suite, linter config, or formatter** wired into the project. Do not invent `pytest`/`ruff` invocations — if you add tests or lint, add the tooling to `pyproject.toml` first.

Build a standalone Windows `.exe` (must run on Windows — PyInstaller is OS-bound):

```powershell
uv run --with pyinstaller pyinstaller --noconfirm --windowed --onefile ^
    --name DesktopAuthenticator src/desktop_authenticator/app.py
```

## Architecture

Three layers, all synchronous and single-process. No network I/O anywhere.

**Vault (`vault.py`)** — the persistence + crypto boundary. `Vault.load` / `Vault.create` are the only ways to get a `Vault` instance; both take the master password, which is held on the instance (`self._password`) for the lifetime of the session so that `save()` can re-encrypt on every mutation. Each `save()` generates a **fresh salt and nonce** and runs PBKDF2 (600k iterations) again, then writes atomically via `path.tmp` → `os.replace`. Format is a JSON header with base64-encoded salt/nonce/AES-GCM-ciphertext; the plaintext is itself a JSON blob of `Account` dicts. `default_vault_path()` resolves to `%APPDATA%\DesktopAuthenticator\vault.json` on Windows, `$XDG_CONFIG_HOME/DesktopAuthenticator/vault.json` elsewhere.

**TOTP (`totp.py`)** — pure functions over `Account`. `normalize_secret` is the single choke point for Base32 validation and is called by both the manual-entry dialog and `parse_otpauth_uri`; any new entry path must go through it. `current_code` / `seconds_remaining` are called every tick from the UI and must stay cheap. Two URI parsers live here: `parse_otpauth_uri(uri) -> Account` for the single-account `otpauth://totp/...` form, and `parse_migration_uri(uri) -> list[Account]` for Google Authenticator's `otpauth-migration://offline?data=...` export format (base64-wrapped protobuf, hand-decoded with a tiny varint reader — no `protobuf` dep). `parse_import_uri(uri) -> list[Account]` is the dispatcher the UI calls; migration payloads' raw-bytes secrets are re-encoded to Base32 before going through `normalize_secret`.

**QR (`qr.py`)** — thin wrapper around OpenCV's `QRCodeDetector`. `decode_qr_from_bytes` / `decode_qr_from_file` return the raw QR payload as a string; the caller hands it to `parse_otpauth_uri`. File reading goes through `Path.read_bytes` → `cv2.imdecode` to avoid `cv2.imread`'s Unicode-path problems on Windows. Adds `opencv-python-headless` + `numpy` to the dependency list — both are required at runtime.

**UI (`ui/`, PySide6)** — `app.main` runs an unlock/create loop (`UnlockDialog`) until a `Vault` is constructed, then hands it to `MainWindow`. `MainWindow` owns a 500 ms `QTimer` that calls `AccountRow.refresh()` on every visible row — each row recomputes its code and countdown fraction independently. **Mutations (`_add_account`, `_edit_account`, `_delete_account`) mutate `vault.data.accounts` in place, then call `vault.save()`, then `_reload_list()`.** The save-then-reload order matters: if you skip `save()`, changes are lost on the next launch; if you skip `_reload_list()`, the UI desyncs from the data. `AccountDialog` has three tabs (manual / otpauth URI / QR scan); the URI and QR tabs are disabled when editing an existing account because they would overwrite the whole record. Both the URI and QR paths go through `parse_import_uri`, so a migration payload (Google Authenticator export) can arrive via either one. The dialog's result API is `result_accounts() -> list[Account]` — a single `otpauth://totp/` scan populates the manual tab for review; a multi-account migration scan stays on the QR tab, shows a bulleted preview, and commits the entire list on OK. `MainWindow._add_account` extends `vault.data.accounts` with every returned account; `_edit_account` only uses the first (edit mode yields exactly one).

## Things to be careful about

- The master password lives in `Vault._password` in memory for the whole session — any logging or serialization of a `Vault` instance would leak it. Do not add `__repr__` / `__str__` that dump fields.
- `Account.secret` is plaintext Base32 inside the running process (needed by `pyotp`). Treat it the same way — never log it, never send it over any channel.
- `save()` rewrites the entire vault with new crypto material. There is no incremental write path and no migration scaffolding; bumping `VAULT_VERSION` requires a load-time upgrade branch.
- `pyotp.TOTP(...).now()` is called inside `normalize_secret` purely as a decode check. If you refactor validation, keep an equivalent end-to-end decode test or malformed secrets will surface only at display time.
