# Web-SSH

Web-SSH serves interactive Linux terminal sessions in a responsive browser UI. It is one Go binary with an embedded frontend and SQLite-like local storage, designed for a single trusted machine.

The first account created on a new installation becomes the administrator. After that, registration is invite-only.

## Install

On Ubuntu 22.04+ or a similar systemd Linux host:

```bash
curl -fsSL https://raw.githubusercontent.com/GWBailang553/web-ssh/v0.1.2/install.sh |
  bash -s -- --host your-hostname.example.com
```

The installer:

- downloads and checksum-verifies the latest Linux release;
- installs the binary under `~/.local/bin`;
- creates a self-signed certificate under `~/.config/web-ssh`;
- installs and starts a `systemd --user` service;
- attempts to enable user lingering so the service survives logout.

Open `https://your-hostname.example.com:8443`. Browsers display a warning until the self-signed certificate is trusted.

To test without installing a service:

```bash
curl -fsSL https://raw.githubusercontent.com/GWBailang553/web-ssh/v0.1.2/install.sh |
  bash -s -- --host 203.0.113.10 --foreground
```

## First use

Open the site while no users exist and create the first account. It is the sole initial administrator. Use **Admin** in the web UI to issue a one-time invitation for each additional account.

Passwords must be 16–128 characters, must not start or end with whitespace, and are checked against a small common-password blocklist. Login attempts are rate-limited and an account locks for 15 minutes after five failures.

Each account can keep two PTY sessions open. Disconnecting the browser closes the associated shell immediately. Every account has the same Linux permissions as the user that installed the service; sessions may use `sudo` if that user can.

## Security model

This is a remote-shell product, not a sandbox. The web login is therefore the boundary between the internet and the installer user's OS account. Use a strong password, restrict the listening port with a firewall or VPN, and keep the host patched.

The application does not record terminal input or output. It records authentication, lockout, user/invite administration, session open/close, IP address, and user agent for 90 days.

## Configuration

The service passes these environment variables if set:

| Variable | Default |
| --- | --- |
| `WEB_SSH_LISTEN` | `0.0.0.0:8443` |
| `WEB_SSH_DATABASE` | `~/.local/share/web-ssh/web-ssh.db` |
| `WEB_SSH_CERT` | `~/.config/web-ssh/cert.pem` |
| `WEB_SSH_KEY` | `~/.config/web-ssh/key.pem` |
| `WEB_SSH_SHELL` | `$SHELL` or `/bin/bash` |
| `WEB_SSH_MAX_TERMINALS` | `2` |

Useful commands:

```bash
systemctl --user status web-ssh
journalctl --user -u web-ssh -f
~/.local/bin/web-ssh cert-renew --host host.example.com
```

## Development

```bash
go test ./...
go vet ./...
shellcheck install.sh
./scripts/build-release.sh v0.1.2
```

## License

MIT. The embedded xterm.js bundle is MIT licensed; see `internal/server/assets/vendor/TERM-LICENSE`.
