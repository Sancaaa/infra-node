# infra-node

Self-hosted infrastructure management dashboard in Go backed by **Terraform**, **Ansible**, and **Proxmox VE**. Instead of editing inventories or HCL folders by hand, you manage hosts, groups, role profiles, secrets, and Proxmox LXC containers through the UI—the server keeps canonical state in SQLite and generates `ansible/` and `terraform/` files atomically before every run.

```
Browser ──HTTPS + POST SSE──► Caddy ──HTTP──► infra-manager (SQLite) ──► terraform / ansible / Go SSH ──► Proxmox VE & Debian/Ubuntu Hosts
```

Ships as a single static `CGO_ENABLED=0` Go binary with an embedded zero-build web UI, running as a hardened non-root systemd service behind Caddy.

## Features

| Area | Capabilities |
|---|---|
| **Overview & scheduler** | Fleet health, config/Proxmox drift summaries with inline diffs and one-click fixes, pending updates and reboots, recent runs, and scheduled background jobs (1 min SSH health, 15 min Terraform drift, nightly Ansible compliance). |
| **Hosts & quick actions** | One-time password SSH enrollment (installs `id_ed25519` + optional `visudo`-checked sudoers), TOFU host-key management, live host details (facts, health, listening ports), systemd unit restart & `journalctl` logs, async reboot tracking, and audited admin command execution. |
| **Groups & variables** | Group membership, per-group and per-host variables (blocking reserved `ansible_*`, `im_*`, and `secret_*` names), ad-hoc Ansible ping and searchable facts. |
| **Profiles & configuration** | Seven embedded Debian/Ubuntu roles (`base`, `users`, `ssh_hardening`, `firewall`, `nginx`, `docker`, `node_exporter`), dry-run **Preview** (`--check --diff`), streaming **Apply**, and **Check again** idempotency verification. |
| **Patching & rolling runs** | Rolling runs (`serial`, `max_fail_percentage: 0`), rolling `apt` package updates, and sequential **Reboot one by one** that halts on the first failed host. |
| **Proxmox & Terraform** | Proxmox VE API discovery (nodes, storages, bridges, templates), LXC container create/resize/start/stop/remove/rebuild (`-replace`) via `bpg/proxmox`, single-use 15-minute reviewed plans, automatic post-create host enrollment, out-of-band drift detection (`-refresh-only`) with scoped accept/revert, zero-change **Adopt** via `import`, and 30-deep state backups with restore preview. |
| **Access, secrets & playbooks** | Managed SSH public key grants with exact **Revoke everywhere**, write-only `ansible-vault` secrets (`secret:<name>`), and syntax-checked custom playbooks. |
| **Code & show-command mode** | Read-only viewer for all generated Ansible and Terraform files, plus a sidebar **Show commands** toggle displaying the exact CLI commands behind actions. |
| **Users, roles & history** | Three-tier RBAC (`viewer < operator < admin`), self-service password/session management, and full SQLite action history. |

## Roles

| Role | Permissions |
|---|---|
| **viewer** | Read-only access to Overview, Hosts, Machines, Groups, History, and host Details. |
| **operator** | All `viewer` permissions plus host quick actions (check, restart service, logs, reboot), Ansible ping/facts/Code, Preview/Apply/Check again, rolling package updates & reboots, drift/compliance checks, and Proxmox container Start/Stop. |
| **admin** | All `operator` permissions plus host enrollment/edit/remove/arbitrary command, group & profile management, Access, Secrets, Custom Playbooks, Proxmox settings, machine create/resize/rebuild/adopt/remove/backup restore, and Users. |

Permissions are enforced centrally in `internal/web/permissions.go` (`can(user, action)`) and verified across the route table by automated tests. Self-demotion, self-disable, and removing the last active admin are blocked atomically in SQL.

## Security Model

- **Default-deny auth & sessions**: Every `/api/*` route except `POST /api/login` requires a valid session. Passwords use `bcrypt` (10–72 bytes); session cookies are `HttpOnly`, `Secure`, and `SameSite=Strict` storing 256-bit random tokens hashed with SHA-256 (7-day fixed lifetime). Login failures are rate-limited per IP with bounded memory tracking.
- **CSRF & CSP**: All mutations use `POST` and require same-origin `Sec-Fetch-Site` and matching `Origin` (host and scheme). Embedded assets use strict DOM construction (no `innerHTML`) and a strict `Content-Security-Policy`.
- **Write-only secrets & scrubbing**:
  - Host enrollment passwords are used once to install the SSH key and discarded immediately.
  - Vault secrets are piped to `ansible-vault` over stdin and stored only as ciphertext; vault password lives in `<data>/secrets/vault_password` (`0600`).
  - Proxmox API token secrets live only in `<data>/secrets/proxmox.tfvars.json` (`0600`), endpoints require `https://`, and changing the endpoint requires re-entering the token secret.
  - Streaming SSE output and logs pass through a line-buffered secret scrubber.
- **SSH & command safety**: Control-plane `id_ed25519` (`0600`) and shared OpenSSH `known_hosts` (`0600`) enforce strict host-key checking for both Go SSH and Ansible. Local CLIs (`terraform`, `ansible*`) always receive discrete argv slices (never `sh -c`), remote SSH arguments are validated and shell-quoted, and custom playbooks reject control-plane execution (`local_action`, `delegate_to: localhost`, `connection: local`, `lookup`/`query` file/env/pipe calls, `vars_files`, `add_host`).
- **Hardened service**: Runs as dedicated non-root user `infra-manager` (`StateDirectoryMode=0700`, `ProtectSystem=strict`, `NoNewPrivileges=true`, `PrivateTmp=true`).

## Quick Start

### Local development

Requirements: Go 1.27+ (`CGO_ENABLED=0` supported). For running Ansible/Terraform locally, install `ansible`, `terraform`, and `openssh-client` on Linux (the dashboard UI and API run on any OS).

```sh
go vet ./...
go test ./...
go run ./cmd/infra-manager user create --admin -data ./data admin
go run ./cmd/infra-manager serve -data ./data -listen 127.0.0.1:8095
```

Open `http://127.0.0.1:8095` and sign in (browsers accept `Secure` cookies on `127.0.0.1` and `localhost`).

### CLI commands

```sh
infra-manager serve [-data DIR] [-listen ADDR]         # defaults: /var/lib/infra-manager, 127.0.0.1:8095
infra-manager service install [-listen ADDR]           # install and start systemd unit (Linux, root)
infra-manager service uninstall                        # stop and remove systemd unit
infra-manager user create --admin [-data DIR] <name>   # create initial admin (run as service user on VPS)
infra-manager version
```

### VPS deployment

Deploy behind Caddy for automatic HTTPS using `start.sh` (`sudo sh start.sh`, `sudo sh start.sh admin`, `sudo sh start.sh caddy infra.example.com`). See [docs/deploy.md](docs/deploy.md) for prerequisites, firewall rules, and upgrades.

## Project Layout & Stack

```
cmd/infra-manager/   CLI entrypoint, systemd installer, listen validation, tty password reader
internal/store/      SQLite DB (16 tables, 27 migrations) for users, sessions, hosts, profiles, machines, history
internal/web/        HTTP handlers, RBAC permissions, auth, rate limiter, POST SSE streaming, background monitor
internal/remote/     Go SSH client, TOFU known_hosts, enrollment, health probes, quick actions, SSH test server
internal/ansible/    Atomic inventory/playbook/vars generator, 7 embedded roles, vault, output parser, playbook guardrails
internal/tf/         Proxmox VE HTTPS client, Terraform HCL/tfvars generator, plan/state JSON parser, runner
internal/run/        Subprocess runner with ANSI stripping and bounded stream timeouts
web/static/          Embedded vanilla JS/CSS SPA (no build step)
docs/                Deployment guide (docs/deploy.md) and roadmap (docs/roadmap.md)
```

**Tech stack**: Go standard library first, `golang.org/x/crypto` (SSH + bcrypt), `modernc.org/sqlite` (pure-Go SQLite, WAL mode), and zero-build vanilla JS/CSS embedded via `//go:embed`.
