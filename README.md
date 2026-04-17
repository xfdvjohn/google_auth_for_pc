# Desktop Authenticator

A Windows desktop TOTP authenticator, functionally equivalent to Google Authenticator on Android. Generates the same 6-digit codes for any site that supports TOTP (Google, GitHub, AWS, Microsoft, etc.).

Secrets are stored on disk in an AES-GCM-encrypted vault that is unlocked with a master password at startup.

## Features

- Add TOTP accounts by **manual entry** (issuer, account name, Base32 secret), by pasting an `otpauth://totp/...` URI, or by **scanning a QR code image** (load from file or paste from clipboard).
- Live 6- or 8-digit codes with a per-row 30-second countdown ring.
- Encrypted local vault: AES-GCM with a key derived from your master password via PBKDF2-SHA256 (600 000 iterations).
- Edit / delete accounts. Click a row and press **Copy code** (or double-click) to put the current code on the clipboard.

## Requirements

- Windows 10 or 11 (the code is cross-platform; it also runs on macOS/Linux during development).
- [uv](https://github.com/astral-sh/uv) for dependency management. Install with:
  ```powershell
  winget install --id=astral-sh.uv
  ```

## Run from source

```powershell
cd google_auth
uv sync
uv run desktop-authenticator
```

`uv sync` creates `.venv/` and installs pinned dependencies from `pyproject.toml` / `uv.lock`.

On first launch you will be prompted to choose a master password (min. 8 characters). The encrypted vault is stored at:

- **Windows:** `%APPDATA%\DesktopAuthenticator\vault.json`
- **macOS/Linux:** `~/.config/DesktopAuthenticator/vault.json`

Back this file up if you want to keep your accounts — there is **no cloud sync**, and if you lose the master password the secrets cannot be recovered.

## Adding an account

When a site shows you a QR code for 2-factor setup, most sites also offer a "Can't scan the code?" link that reveals either:

1. The **secret key** (a Base32 string like `JBSW Y3DP EHPK 3PXP`), or
2. The full **otpauth URI** (`otpauth://totp/Google:you@example.com?secret=...&issuer=Google`), or
3. The **QR code itself** — save the image (or screenshot it) and import via **Add → Scan QR code**.

Paste either of the first two via **Add → Manual entry** or **Add → Paste otpauth URI**; the third via **Add → Scan QR code** (load an image file, or copy the QR to your clipboard and click *Paste image from clipboard*). Compare the first generated 6-digit code against the site's "enter code to confirm" field — if it matches, you're set up.

## Building a single-file `.exe` for Windows

Run on a Windows machine (PyInstaller produces a binary for the OS it runs on):

```powershell
uv sync
uv run --with pyinstaller pyinstaller ^
    --noconfirm --windowed --onefile ^
    --name DesktopAuthenticator ^
    src/desktop_authenticator/app.py
```

The resulting `dist\DesktopAuthenticator.exe` is self-contained and can be copied anywhere.

## Project layout

```
src/desktop_authenticator/
    app.py              # entry point (desktop-authenticator script)
    vault.py            # AES-GCM encrypted vault
    totp.py             # TOTP code generation + otpauth URI parsing
    qr.py               # QR code image decoding (OpenCV)
    ui/
        dialogs.py      # unlock / add / edit dialogs (incl. QR scan tab)
        main_window.py  # account list, live codes, countdown
```

## Security notes

- The master password never leaves memory; only a PBKDF2-derived key encrypts the vault.
- Secrets are held in plaintext in process memory while the app is running (required to generate codes).
- The clipboard is not auto-cleared after copy. Clear it manually for sensitive codes.
- This app has no network access and makes no outbound connections.
