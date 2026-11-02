# WebSSH

A Python web app which runs on a Debian SBC and provides a browser terminal and file manager for that same machine. It uses Linux PAM to check the local account password, starts the shell as the account running the app, and accesses files with that account's normal OS permissions. There is no SSH server connection or SSH host/port setting.

## Requirements

- Debian with Python 3.10 or newer
- A non-root Linux user account with an interactive shell and password
- PAM support and a pseudo-terminal

The login name must match the Linux account running the WebSSH process. This avoids claiming one user's identity while running the shell/files as another. The app deliberately refuses to run as root.

## Install and run

Run as the Linux account whose files and shell you want to access:

```bash
sudo apt update
sudo apt install python3-venv
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and set `WEBSSH_SESSION_SECRET` to a unique random value. Generate one with:

```bash
python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Then start the app:

```bash
WEBSSH_COOKIE_SECURE=false python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` on the SBC for local testing. For remote use, leave `WEBSSH_COOKIE_SECURE=true`, put the app behind an HTTPS reverse proxy, and connect over a VPN/private network; configure the proxy to forward to `127.0.0.1:8000`. The secure cookie setting requires HTTPS in the browser. Disable it only for local HTTP testing on the SBC itself.

The `.env` file is optional: settings can also be supplied as environment variables. `.env` is ignored by Git.

## Security

Do not expose this service directly to the public internet. The terminal runs arbitrary commands with the WebSSH service account's full permissions, and the file manager accesses files with those same permissions. Use a dedicated non-root account if you want to limit access. PAM checks the password locally; it is not saved. Session records and terminal processes are held in memory and idle sessions expire after 30 minutes. Run a single Uvicorn worker because session state is process-local.

The browser terminal and JetBrains Mono font load from jsDelivr, so clients need access to that CDN. Files can be uploaded up to 100 MB each.
