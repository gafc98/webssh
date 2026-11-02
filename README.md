# WebSSH

A small Python web app for opening an SSH terminal and browsing files on one Debian host over SFTP.

## Requirements

- Python 3.10 or newer
- SSH and SFTP enabled on the Debian system
- The SSH server's host key present in your `known_hosts` file

The app connects only to the host configured by `SSH_HOST`. It verifies SSH host keys using the current user's default `known_hosts` file, or the file specified by `SSH_KNOWN_HOSTS`. Do not disable host-key verification.

## Run locally

In PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:SSH_HOST = "192.168.1.50"
$env:SSH_PORT = "22"
$env:WEBSSH_SESSION_SECRET = (python -c "import secrets; print(secrets.token_urlsafe(32))")
$env:WEBSSH_COOKIE_SECURE = "0"
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. Set `WEBSSH_COOKIE_SECURE=0` only for local HTTP testing on a trusted machine. For deployment, use HTTPS and leave secure cookies enabled. Set `WEBSSH_SESSION_SECRET` to a persistent random secret, and set `SSH_KNOWN_HOSTS` if the host-key file is not in the default location.

## Secure access

Do not expose the app directly to the public internet. Access it over a VPN/private network or through a properly configured HTTPS reverse proxy. The app forwards the signed-in user's SSH privileges, so use a non-root Debian account and protect access to the web server. The app does not persist the SSH password; it passes it to AsyncSSH to establish the connection and retains active SSH connections in memory. Sessions disconnect after 30 minutes idle or when the app exits. Run one Uvicorn worker because session state is not shared between worker processes.

The terminal UI loads xterm.js from jsDelivr, so browsers need access to that CDN. Files can be uploaded up to 100 MB each.
