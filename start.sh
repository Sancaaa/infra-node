#!/bin/sh
# Sets up (and updates) infra manager on a Linux machine from a git clone.
#
#   sudo sh start.sh                  build, install and (re)start the service
#   sudo sh start.sh admin [NAME]     create the first administrator (asks for a password)
#   sudo sh start.sh tools            install Ansible and Terraform (Debian/Ubuntu)
#   sudo sh start.sh caddy DOMAIN     HTTPS in front of it (installs Caddy on Debian/Ubuntu)
#   sh start.sh status                is it running?
#   sh start.sh logs                  follow the server's log
#
# To update later:  git pull && sudo sh start.sh
#
# What it puts where (the data folder is the only thing to keep):
#   /usr/local/bin/infra-manager          the server program (with the web UI inside)
#   /var/lib/infra-manager/               the database, SSH keys, secrets, Ansible & Terraform files
#   /etc/systemd/system/infra-manager.service
#
# It is safe to run again: it rebuilds, replaces the program and restarts. It never
# touches the database or keys.

BIN=/usr/local/bin/infra-manager
DATA_DIR=/var/lib/infra-manager
SERVICE_USER=infra-manager
LISTEN=127.0.0.1:8095
# Only needed to start building: Go downloads the exact version go.mod asks for.
GO_BOOTSTRAP=1.23.4

say() { printf '%s\n' "$*"; }
die() { printf 'start: %s\n' "$*" >&2; exit 1; }

need_root() {
    [ "$(id -u)" = "0" ] || die "run this as root: sudo sh start.sh $*"
}

# Go keeps its build cache under $HOME, and some ways of becoming root leave it unset.
[ -n "${HOME:-}" ] || HOME=/root
export HOME

# Everything is done from the folder this script is in, whatever folder the person
# was in when they ran it.
cd "$(dirname "$0")" || die "cannot enter the project folder"
ROOT=$(pwd)
[ -f go.mod ] && [ -d cmd/infra-manager ] || die "$ROOT is not the infra-manager project (no go.mod or cmd/infra-manager)"

# ---------------------------------------------------------------- go

# have_go says whether a usable go is on the PATH. Any go from 1.21 on can fetch
# the toolchain go.mod needs by itself; older ones cannot.
have_go() {
    command -v go >/dev/null 2>&1 || return 1
    version=$(go env GOVERSION 2>/dev/null) || return 1   # "go1.23.4"
    minor=${version#go1.}
    minor=${minor%%.*}
    case "$minor" in ''|*[!0-9]*) return 1 ;; esac
    [ "$minor" -ge 21 ]
}

install_go() {
    case "$(uname -m)" in
        x86_64|amd64) goarch=amd64 ;;
        aarch64|arm64) goarch=arm64 ;;
        *) die "unsupported processor $(uname -m): install Go from go.dev/dl yourself, then run this again" ;;
    esac
    command -v curl >/dev/null 2>&1 || die "curl is needed to download Go: apt-get install -y curl"
    say "Installing Go $GO_BOOTSTRAP into /usr/local/go (it then fetches the exact version this project needs)..."
    tmp=$(mktemp -d) || die "cannot make a temporary folder"
    curl -fsSL "https://go.dev/dl/go$GO_BOOTSTRAP.linux-$goarch.tar.gz" -o "$tmp/go.tgz" || { rm -rf "$tmp"; die "could not download Go"; }
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$tmp/go.tgz" || { rm -rf "$tmp"; die "could not unpack Go"; }
    rm -rf "$tmp"
}

ensure_go() {
    if ! have_go; then
        [ -x /usr/local/go/bin/go ] || install_go
        PATH="/usr/local/go/bin:$PATH"
        export PATH
        have_go || { install_go; have_go || die "Go is still not usable"; }
    fi
    say "Using $(go version)"
}

# ----------------------------------------------------------- install

install_all() {
    need_root
    command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || die "systemd was not found: this script installs a systemd service"
    ensure_go

    # No C compiler needed: the SQLite driver is pure Go.
    CGO_ENABLED=0
    export CGO_ENABLED

    tmp=$(mktemp -d) || die "cannot make a temporary folder"
    say "Building infra-manager..."
    if ! go build -trimpath -ldflags "-s -w" -o "$tmp/infra-manager" ./cmd/infra-manager; then
        rm -rf "$tmp"
        die "the build failed"
    fi

    # service install creates the system user, /var/lib/infra-manager (0700),
    # copies the binary atomically to /usr/local/bin/infra-manager, writes the
    # systemd unit, and restarts the service.
    if ! "$tmp/infra-manager" service install -listen "$LISTEN"; then
        rm -rf "$tmp"
        journalctl -u infra-manager -n 20 --no-pager
        die "service install failed (the log is above)"
    fi
    rm -rf "$tmp"

    say ""
    say "Next (the first time):"
    say "  1. sudo sh start.sh admin               create the first administrator"
    say "  2. sudo sh start.sh tools               install Ansible and Terraform"
    say "  3. sudo sh start.sh caddy YOUR.DOMAIN   HTTPS, so you can reach it from outside"
    say "  4. log in, add a host or configure Proxmox in Settings"
}

# ------------------------------------------------------------- admin

# run_as_service_user runs a command as the service's user, with the terminal
# still attached (the password is asked for there). runuser, unlike sudo, needs
# no configuration and is always there where systemd is.
run_as_service_user() {
    if command -v runuser >/dev/null 2>&1; then
        runuser -u "$SERVICE_USER" -- "$@"
    else
        sudo -u "$SERVICE_USER" "$@"
    fi
}

make_admin() {
    need_root admin
    [ -x "$BIN" ] || die "the server is not installed yet: run  sudo sh start.sh  first"
    name=${1:-admin}
    case "$name" in *[!A-Za-z0-9._-]*|'') die "use letters, digits, dot, dash or underscore in the user name" ;; esac
    say "Creating the administrator \"$name\"..."
    # From /: the service's user may not be allowed to enter the folder this script is in.
    (cd / && run_as_service_user "$BIN" user create --admin -data "$DATA_DIR" "$name")
}

# ------------------------------------------------------------- tools

install_tools() {
    need_root tools
    command -v apt-get >/dev/null 2>&1 || die "this is not Debian or Ubuntu: install ansible, openssh-client and terraform with your package manager"

    if ! command -v ansible-playbook >/dev/null 2>&1 || ! command -v ssh >/dev/null 2>&1; then
        say "Installing Ansible and OpenSSH client..."
        apt-get update -y >/dev/null
        apt-get install -y ansible openssh-client >/dev/null || die "could not install ansible and openssh-client"
    else
        say "Ansible is already installed: $(ansible --version | head -n 1)"
    fi

    if ! command -v terraform >/dev/null 2>&1; then
        say "Installing Terraform from HashiCorp's apt repository..."
        apt-get update -y >/dev/null
        apt-get install -y curl gnupg lsb-release >/dev/null || die "could not install Terraform's prerequisites"
        curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor --yes -o /usr/share/keyrings/hashicorp-archive-keyring.gpg || die "could not fetch HashiCorp's signing key"
        codename=$(lsb_release -cs) || die "could not detect OS codename"
        printf 'deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com %s main\n' "$codename" > /etc/apt/sources.list.d/hashicorp.list
        chmod o+r /usr/share/keyrings/hashicorp-archive-keyring.gpg /etc/apt/sources.list.d/hashicorp.list
        apt-get update -y >/dev/null
        apt-get install -y terraform >/dev/null || die "could not install terraform"
    else
        say "Terraform is already installed: $(terraform version | head -n 1)"
    fi

    if id "$SERVICE_USER" >/dev/null 2>&1; then
        say ""
        say "Checking that $SERVICE_USER can run both:"
        (cd / && run_as_service_user ansible --version | head -n 1) || die "$SERVICE_USER cannot run ansible"
        (cd / && run_as_service_user terraform version | head -n 1) || die "$SERVICE_USER cannot run terraform"
    fi
}

# ------------------------------------------------------------- caddy

install_caddy() {
    command -v caddy >/dev/null 2>&1 && return 0
    command -v apt-get >/dev/null 2>&1 || die "Caddy is not installed, and this is not Debian or Ubuntu: install it from caddyserver.com/docs/install, then run this again"
    say "Installing Caddy from its official package repository..."
    apt-get update -y >/dev/null
    apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gpg >/dev/null || die "could not install Caddy's prerequisites"
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg || die "could not fetch Caddy's signing key"
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' -o /etc/apt/sources.list.d/caddy-stable.list || die "could not add Caddy's repository"
    chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -y >/dev/null
    apt-get install -y caddy >/dev/null || die "could not install Caddy"
}

caddy_block() {
    cat <<EOF
$1 {
	reverse_proxy $LISTEN

	header Strict-Transport-Security "max-age=31536000"
}
EOF
}

setup_caddy() {
    need_root caddy
    domain=${1:-}
    [ -n "$domain" ] || die "give your domain name: sudo sh start.sh caddy infra.example.com"
    # A host name only. It goes into a config file, so nothing else may get in.
    case "$domain" in
        *[!A-Za-z0-9.-]*|.*|-*|*..*|*.) die "\"$domain\" is not a plain domain name" ;;
        *.*) ;;
        *) die "\"$domain\" is not a domain name with a dot in it" ;;
    esac

    install_caddy
    mkdir -p /etc/caddy

    if [ ! -f /etc/caddy/Caddyfile ] || grep -q '^:80 {' /etc/caddy/Caddyfile; then
        # Fresh Caddy install (default :80 example file): write a clean Caddyfile.
        [ -f /etc/caddy/Caddyfile ] && cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak.$(date +%Y%m%d%H%M%S)"
        caddy_block "$domain" > /etc/caddy/Caddyfile
    elif grep -q "reverse_proxy $LISTEN" /etc/caddy/Caddyfile; then
        say "/etc/caddy/Caddyfile already has a block for $LISTEN; keeping it as is."
    else
        # Another site (such as headnode) is already in Caddyfile: back up and append.
        cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak.$(date +%Y%m%d%H%M%S)"
        say "Keeping existing sites in /etc/caddy/Caddyfile (backup saved) and adding $domain..."
        printf '\n' >> /etc/caddy/Caddyfile
        caddy_block "$domain" >> /etc/caddy/Caddyfile
    fi

    caddy validate --config /etc/caddy/Caddyfile >/dev/null || die "/etc/caddy/Caddyfile is not valid (check it before reloading Caddy)"
    systemctl enable caddy >/dev/null 2>&1
    systemctl reload caddy 2>/dev/null || systemctl restart caddy || { journalctl -u caddy -n 20 --no-pager; die "Caddy did not start (the log is above)"; }
    say ""
    say "Caddy is serving https://$domain and getting its certificate."
    say "That needs the domain's DNS record to point at this machine, and ports 80 and 443 open."
    say "If you use ufw:  ufw allow 80,443/tcp"
}

# ------------------------------------------------------------- the rest

case "${1:-install}" in
    install|update) install_all ;;
    admin)          shift; make_admin "$@" ;;
    tools)          install_tools ;;
    caddy)          shift; setup_caddy "$@" ;;
    status)
        systemctl status infra-manager --no-pager || true
        say ""
        if command -v curl >/dev/null 2>&1; then
            curl -fsS -o /dev/null -w "http://$LISTEN answers with HTTP %{http_code}\n" "http://$LISTEN/" || say "nothing answers on $LISTEN"
        fi
        say ""
        if command -v ansible-playbook >/dev/null 2>&1; then
            say "ansible   : $(ansible --version | head -n 1)"
        else
            say "ansible   : not installed (run: sudo sh start.sh tools)"
        fi
        if command -v terraform >/dev/null 2>&1; then
            say "terraform : $(terraform version | head -n 1)"
        else
            say "terraform : not installed (run: sudo sh start.sh tools)"
        fi
        ;;
    logs)           exec journalctl -u infra-manager -f ;;
    -h|--help|help) sed -n '2,18p' "$0" ;;
    *)              die "unknown command \"$1\" (try: install, admin, tools, caddy, status, logs)" ;;
esac
