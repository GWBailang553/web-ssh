#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPO="GWBailang553/web-ssh"
readonly DEFAULT_PORT=8443

VERSION=""
LISTEN_HOST="0.0.0.0"
PORT="$DEFAULT_PORT"
HOSTS=()
FOREGROUND=0
NO_START=0
TEMP_DIR=""

usage() {
  cat <<'EOF'
Usage: install.sh [options]

Install Web-SSH from a checksum-verified GitHub release and configure a user systemd unit.

Options:
  --host HOST          Certificate SAN; may be repeated. Accepts DNS names or IPs.
  --listen ADDRESS     Bind address (default: 0.0.0.0).
  --port PORT          HTTPS port (default: 8443).
  --version VERSION    Release tag, such as v0.1.0 (default: latest).
  --foreground         Run in the foreground; useful without a user systemd bus.
  --no-start           Install files but do not start the service.
  -h, --help           Show this help.
EOF
}

die() {
  printf 'install.sh: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
    rm -rf -- "$TEMP_DIR"
  fi
}
trap cleanup EXIT

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

parse_args() {
  while (($#)); do
    case "$1" in
      --host)
        [[ $# -ge 2 ]] || die "--host requires a value"
        [[ "$2" =~ ^[A-Za-z0-9._:-]+$ ]] ||
          die "--host contains unsupported characters"
        HOSTS+=("$2")
        shift 2
        ;;
      --listen)
        [[ $# -ge 2 ]] || die "--listen requires a value"
        LISTEN_HOST="$2"
        shift 2
        ;;
      --port)
        [[ $# -ge 2 ]] || die "--port requires a value"
        PORT="$2"
        shift 2
        ;;
      --version)
        [[ $# -ge 2 ]] || die "--version requires a value"
        VERSION="$2"
        shift 2
        ;;
      --foreground)
        FOREGROUND=1
        shift
        ;;
      --no-start)
        NO_START=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown option: $1"
        ;;
    esac
  done
  [[ "$PORT" =~ ^[0-9]+$ ]] || die "port must be numeric"
  ((PORT >= 1 && PORT <= 65535)) || die "port must be between 1 and 65535"
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)
      printf 'amd64'
      ;;
    aarch64|arm64)
      printf 'arm64'
      ;;
    *)
      die "unsupported architecture: $(uname -m); supported: amd64, arm64"
      ;;
  esac
}

resolved_version() {
  if [[ -n "$VERSION" ]]; then
    printf '%s' "$VERSION"
    return
  fi
  curl -fsSL --retry 3 "https://api.github.com/repos/$REPO/releases/latest" |
    sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' |
    head -n 1
}

download_release() {
  local arch="$1" version="$2" base archive
  [[ -n "$version" ]] || die "could not determine latest release; pass --version"
  base="https://github.com/$REPO/releases/download/$version"
  archive="web-ssh_${version#v}_linux_${arch}.tar.gz"
  TEMP_DIR="$(mktemp -d)"
  curl -fsSL --retry 3 "$base/$archive" -o "$TEMP_DIR/$archive"
  curl -fsSL --retry 3 "$base/checksums.txt" -o "$TEMP_DIR/checksums.txt"
  (
    cd "$TEMP_DIR"
    grep "  $archive\$" checksums.txt > selected-checksum.txt
    [[ -s selected-checksum.txt ]] || die "release checksum is missing for $archive"
    sha256sum --check --strict selected-checksum.txt
    tar -xzf "$archive"
    [[ -x web-ssh ]] || die "release archive does not contain executable web-ssh"
  )
}

install_files() {
  local bin_dir="$HOME/.local/bin"
  local config_dir="$HOME/.config/web-ssh"
  local data_dir="$HOME/.local/share/web-ssh"
  local unit_dir="$HOME/.config/systemd/user"
  local host_csv host_arg=""

  mkdir -p "$bin_dir" "$config_dir" "$data_dir" "$unit_dir"
  chmod 700 "$config_dir" "$data_dir"
  install -m 0755 "$TEMP_DIR/web-ssh" "$bin_dir/web-ssh"
  host_csv="$(IFS=,; printf '%s' "${HOSTS[*]}")"
  if [[ -n "$host_csv" ]]; then
    host_arg="--host $host_csv"
  fi
  printf '%s\n' "$host_csv" >"$config_dir/hosts"
  chmod 600 "$config_dir/hosts"

  # shellcheck disable=SC2086 # host_arg is intentionally an optional argument list.
  "$bin_dir/web-ssh" cert-renew ${host_arg}

  cat >"$unit_dir/web-ssh.service" <<EOF
[Unit]
Description=Web-SSH browser terminal
After=network-online.target

[Service]
Type=simple
ExecStart=%h/.local/bin/web-ssh --listen ${LISTEN_HOST}:${PORT} ${host_arg}
Restart=on-failure
RestartSec=3
Environment=PATH=%h/.local/bin:/usr/local/bin:/usr/bin:/bin
Environment=SHELL=${SHELL:-/bin/bash}

[Install]
WantedBy=default.target
EOF

  cat >"$unit_dir/web-ssh-cert-renew.service" <<EOF
[Unit]
Description=Renew the Web-SSH local certificate

[Service]
Type=oneshot
ExecStart=%h/.local/bin/web-ssh cert-renew ${host_arg}
EOF

  cat >"$unit_dir/web-ssh-cert-renew.timer" <<'EOF'
[Unit]
Description=Monthly Web-SSH certificate renewal check

[Timer]
OnCalendar=monthly
Persistent=true

[Install]
WantedBy=timers.target
EOF
  chmod 600 "$unit_dir/web-ssh.service"
}

start_service() {
  local systemctl_cmd=(systemctl --user)
  if [[ "${XDG_RUNTIME_DIR:-}" == "" ]]; then
    XDG_RUNTIME_DIR="/run/user/$(id -u)"
    export XDG_RUNTIME_DIR
  fi
  if ! "${systemctl_cmd[@]}" show-environment >/dev/null 2>&1; then
    die "user systemd is unavailable; rerun with --foreground and manage the process yourself"
  fi
  "${systemctl_cmd[@]}" daemon-reload
  "${systemctl_cmd[@]}" enable web-ssh.service
  "${systemctl_cmd[@]}" restart web-ssh.service
  "${systemctl_cmd[@]}" enable --now web-ssh-cert-renew.timer

  if command -v loginctl >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
    sudo -n loginctl enable-linger "$USER" 2>/dev/null ||
      printf 'Note: user lingering was not enabled automatically. Run: sudo loginctl enable-linger %s\n' "$USER" >&2
  fi
}

main() {
  parse_args "$@"
  require_command curl
  require_command sha256sum
  require_command tar
  require_command install

  local arch
  arch="$(detect_arch)"
  download_release "$arch" "$(resolved_version)"

  if ((FOREGROUND)); then
    local host_csv
    local -a host_args=()
    host_csv="$(IFS=,; printf '%s' "${HOSTS[*]}")"
    mkdir -p "$HOME/.local/bin" "$HOME/.config/web-ssh" "$HOME/.local/share/web-ssh"
    install -m 0755 "$TEMP_DIR/web-ssh" "$HOME/.local/bin/web-ssh"
    if [[ -n "$host_csv" ]]; then
      host_args=(--host "$host_csv")
    fi
    exec "$HOME/.local/bin/web-ssh" --listen "${LISTEN_HOST}:${PORT}" "${host_args[@]}"
  fi

  install_files
  if ((NO_START)); then
    printf 'Installed Web-SSH. Start it with: systemctl --user enable --now web-ssh.service\n'
    exit 0
  fi
  start_service
  printf 'Web-SSH is running at https://%s:%s\n' "${HOSTS[0]:-$HOSTNAME}" "$PORT"
  printf 'The certificate is self-signed; trust it explicitly in your browser.\n'
}

main "$@"
