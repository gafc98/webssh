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

Then start and stop the app with:

```bash
chmod +x *.sh
./start_services.sh
./stop_services.sh
```

or run it in the foreground:

```bash
WEBSSH_COOKIE_SECURE=false python -m uvicorn webssh.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` on the SBC for local testing. For remote use, leave `WEBSSH_COOKIE_SECURE=true`, put the app behind an HTTPS reverse proxy, and connect over a VPN/private network; configure the proxy to forward to `127.0.0.1:8000`. The secure cookie setting requires HTTPS in the browser. Disable it only for local HTTP testing on the SBC itself.

The `.env` file is optional: settings can also be supplied as environment variables. `.env` is ignored by Git. See [.env.example](.env.example) for all settings (idle timeout, upload limit, terminal limits, sign-in lockout, audit log).

## Features

- **Terminal tabs:** open up to 8 shells (`WEBSSH_MAX_TERMINALS`). Shells keep running for 5 minutes after the browser disconnects (`WEBSSH_TERMINAL_GRACE_SECONDS`); reloading the page reattaches and replays recent output.
- **File manager:** browse, upload (asks before replacing), download, create folders, rename, delete, and move/copy via cut/copy and "Paste here".
- **System stats:** CPU, memory, disk (home filesystem) and SoC temperature in the header.
- **Updates:** when the install is a git checkout with an upstream branch, the header shows the current commit and an "Update available" button when commits are behind. It runs `update.sh` (`git pull --ff-only`, reinstall requirements if changed, restart) and logs to `update.log`. It refuses to update when there are local changes or commits. Disable with `WEBSSH_ALLOW_UPDATE=false`.

## Project layout

```
webssh/
  main.py          FastAPI app, middleware, page route
  config.py        settings from .env / environment
  security.py      CSRF, sign-in throttling, audit log
  sessions.py      in-memory sessions and terminal lifecycle
  terminal.py      PTY wrapper with scrollback and reattach
  sysinfo.py       /proc and /sys readers for stats
  updater.py       git status and update launcher
  routes/          auth, files, terminals, system endpoints
  templates/       index.html
  static/          css, js, and vendored xterm.js + font
start_services.sh  start WebSSH in the background
stop_services.sh   stop it
update.sh          git pull and restart
```

## Security

Do not expose this service directly to the public internet. The terminal runs arbitrary commands with the WebSSH service account's full permissions, and the file manager accesses files with those same permissions. Use a dedicated non-root account if you want to limit access. PAM checks the password locally; it is not saved. Session records and terminal processes are held in memory and idle sessions expire after 30 minutes. Run a single Uvicorn worker because session state is process-local.

Failed sign-ins are throttled per client IP: after 3 failures each further failure doubles the lockout, up to 15 minutes. Uvicorn trusts `X-Forwarded-For` from `127.0.0.1` by default, so a reverse proxy on the same host passes the real client IP; a proxy elsewhere needs `--forwarded-allow-ips`.

Sign-ins, sign-outs, file changes, downloads, terminal open/close and updates are written to the log with the client IP. Set `WEBSSH_AUDIT_LOG=audit.log` to also write them to a separate file.

xterm.js and the JetBrains Mono font are bundled under `webssh/static/vendor`, so no CDN access is needed. Files can be uploaded up to 100 MB each (`WEBSSH_MAX_UPLOAD_MB`).
