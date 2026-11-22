# infra manager

A dashboard for the hosts of your lab. You add a **host** with a form (address, user, password), tick what it should have, and create Proxmox containers from a form too. **Ansible** and **Terraform** do the work underneath, on files the dashboard writes from its own data. You never pick a folder.

It runs on a VPS as a systemd service behind Caddy, with users, roles and a History of every change. The plan is in [docs/roadmap.md](docs/roadmap.md), the reason in OD-06 of `otherDashboard/decisions.md`.

**Status: IM9 (compliance and the full Overview — MVP complete).** New: **Compliance check** (`ansible-playbook site.yml --check --diff`, nightly at the time set in Settings or on demand) marking hosts whose files changed outside the dashboard as *drifted* with the diff and a **Fix** button, a **scheduler** tracking the last and next run of health check, Proxmox drift check and nightly compliance check, and the full **Overview** (hosts online, failing configuration, drifted from profile, drifted in Proxmox, pending updates and reboots, both kinds of drift with diffs/actions without scrolling, scheduled checks, last runs, and one **Next step** card).

Before it, **IM8 (drift, rebuild, adopt, state safety).** New: **Drift check** (`terraform plan -refresh-only`, on a button and every 15 minutes in the background) reporting plain-word out-of-band changes with **Put it back** or **Accept**, **Rebuild** (`-replace`, automatically trusting the fresh SSH host key with a History entry and re-applying the host's profile), **Adopt** (enter an existing container's node, VM ID and settings, write a temporary `import` block, and allow adoption only when the plan shows **no changes**), and **State backups** (taken before every apply, kept 30 deep, with **Preview restore** via `terraform plan -state=<backup>` before restoring). All Terraform operations share one mutex.

Before it, **IM7 (Proxmox: create machines with Terraform).** New: **Settings → Proxmox** (endpoint, API token ID, write-only token secret in `secrets/proxmox.tfvars.json` mode `0600`, and **Test connection** over stdlib HTTP that discovers nodes, storages, bridges and templates), generated `terraform/` (`versions.tf` pinned to `bpg/proxmox`, `provider.tf`, `main.tf` with `proxmox_virtual_environment_container` and `for_each = var.machines`, `machines.auto.tfvars.json`, visible read-only on **Code**), **Machines** page showing desired against real (*will be created*, *running*, *stopped*, *will change*, *will be removed*), **Create machine** (Small / Medium / Large presets or custom, static IP or DHCP, template, groups, "Configure it after creation"), **Review changes** and single-use 15-minute **Apply** (OD-04), automatic host enrollment and profile configuration after creation, **Start / Stop** (operator), **Resize** (plainly showing in-place vs recreate), **Remove** (destroys only that container and removes its host), and address lock on Terraform-generated hosts.

Before it, **IM6 (operations at scale).** New: **rolling** runs (N hosts at a time, stopping at the first failure and leaving the rest exactly as they were), **Update packages** for a group or a host (always rolling), then the list of hosts that need a reboot and **Reboot one by one** (each must come back before the next), an **Access** page (people's SSH public keys, given to groups or hosts with Ansible's `authorized_key`, and **Revoke everywhere**), **Secrets** (encrypted with `ansible-vault`, write-only, usable as a role's setting or a variable), and **Playbooks** (your own, checked with `--syntax-check` before they are saved, previewed and run like anything else).

Before it, **IM5 (profiles: configure hosts).** New: a **library of seven roles** that comes inside the program (base system, a user with SSH keys and sudo, SSH hardening, firewall, nginx, Docker, node exporter), a **profile** (roles with their settings, as a form) for a group or a host, **Preview** (a dry run, in plain words, with the file changes one click away), **Apply** (a live log and a recap), **Check again** (a second run: *Idempotent ✓*, or the tasks that changed again), and the **configuration state** of each host (never applied, applied, failed, changes waiting) on Hosts and Overview. Debian and Ubuntu hosts. Next: operations at scale (IM6).

Before it, **IM4 (groups and the Ansible engine).** New: **Groups** (create, rename, delete, put hosts in them several at once), **variables** for groups and for single hosts as a form, and the **Ansible files** the dashboard generates from its own data (`<data>/ansible/`: `ansible.cfg`, `inventory.ini`, `group_vars/`, `host_vars/`, written before every use, never edited by hand). **Ping with Ansible** for a host or a group, **Ansible facts** (searchable), **Code** (the generated files, read-only), and a **Show commands** switch in the sidebar (off by default). Without Ansible installed the pages say how to install it and everything else keeps working. Configuring hosts (IM5) is next.

Before it, **IM3 (status and quick actions).** What exists: the service, the login with three roles, the Users, Profile, History and Settings pages, **Hosts** (add a host with a password used once, edit, remove), a **check every minute** (online or offline, load, RAM, disk, failed services, reboot and updates waiting), **Details** read live from the host, the quick actions (**restart a service**, **service logs**, **reboot**, and for admins **run a command**), and the first **Overview**. Groups (IM4) and configuring hosts (IM5) are not there yet. The old Terraform-and-Ansible command runner (OD-04) is gone.

| Role | On the Hosts page |
|---|---|
| viewer | looks: the table and Details |
| operator | also Check now, Restart a service, Service logs, Reboot |
| admin | also Add, Edit, Remove, Trust the new key, Run a command |

## Run it

On your computer, to look at it:

```powershell
cd otherDashboard/infra-manager
go test ./...
go run ./cmd/infra-manager user create --admin -data ./data ada
go run ./cmd/infra-manager serve -data ./data -listen 127.0.0.1:8095
```

`user create` asks for a password (10 to 72 characters; nothing is shown while you type). Then open `http://127.0.0.1:8095` and log in. The session cookie is `Secure`, which Chrome and Firefox accept for `127.0.0.1` and `localhost` only; on a VPS the page is reached over HTTPS through Caddy.

On a VPS: [docs/deploy.md](docs/deploy.md), which installs the service, Caddy for HTTPS, `ansible` and `terraform`.

## Commands

```
infra-manager serve [-data DIR] [-listen ADDR]   run the dashboard
infra-manager service install [-listen ADDR]     install and start the systemd service (Linux, root)
infra-manager service uninstall                  stop and remove the service
infra-manager user create --admin [-data DIR] NAME   create the first admin (asks for the password)
infra-manager version
```

Defaults: `-data /var/lib/infra-manager`, `-listen 127.0.0.1:8095`. On a VPS, run `user create` as the service user: `sudo -u infra-manager infra-manager user create --admin NAME` (as root it refuses, so the database files stay owned by the service).

- **The data directory** holds everything the dashboard remembers: the database `infra-manager.db`, and later the SSH key it uses and its secrets. It is created `0700`; an existing one that other users can read gets a warning at start.
- **The database** is SQLite (pure Go, no cgo), changed by numbered migrations that run at start. See `internal/store/migrations.go`.
- **The service** runs as its own user `infra-manager`, not root.
- **Listening:** only an IP address and a port are accepted. Anything that is not `127.0.0.1`, `::1` or `localhost` prints a warning: Caddy, on the same machine, is meant to be the only door.

## Roles

| Role | Can |
|---|---|
| **viewer** | Look at things, and change nothing. |
| **operator** | Everything a viewer can, plus the everyday actions on hosts (from IM3), Preview and Apply, Update packages, Reboot one by one, and Start / Stop of Proxmox machines. |
| **admin** | Everything, including the Users page, profiles, Access, Secrets, Playbooks, Proxmox settings, and creating, resizing and removing machines. |

Everybody can change their own password and see or end their own sessions. One function, `can(user, action)` in `internal/web/permissions.go`, decides; the page only hides buttons. Rules on the Users page: nobody can disable or demote themselves, and the last enabled admin can never be disabled or demoted (checked inside the SQL statement, so two admins cannot undo each other at the same moment). Disabling a user, or resetting their password, ends all their sessions at once.

## Security

- **Every `/api` route needs a session.** Without one the answer is `401`, also for an address that is not a route. The table of routes in `internal/web/server.go` names the action each one needs, and a test walks that table, so a new route cannot skip the check.
- **Login:** passwords are bcrypt hashes (10 to 72 characters). The cookie is `HttpOnly`, `Secure` and `SameSite=Strict`, and holds a random token whose SHA-256 is all the database keeps. A session lasts 7 days, with no renewal. Wrong passwords are slowed down per address (3 free, then 1 s, 2 s, 4 s, up to 15 minutes). A wrong user name and a wrong password get the same answer and take the same time.
- **History** records every change from here on, refused ones included: who, what, which target, the result and the address. A refused login does not store the name that was typed (people type passwords there). Lines for requests nobody is logged in for are capped at 60 a minute so they cannot fill the database. No password, token or key is ever written to it.
- A request that changes something (anything but GET) is accepted only from this page: the browser must not mark it as cross-site, and its `Origin` must be the dashboard's own address (`internal/web/security.go`, the idea of headnode's D-22). Every answer carries a strict Content-Security-Policy: no inline script, no other sites.
- Local programs (`terraform`, `ansible`) are started with their arguments one by one, never through `sh -c` (`internal/run`). Commands that go to a host over SSH are checked and quoted first (roadmap, "Rules for every agent").
- **The password typed in Add host is used once and forgotten.** The dashboard logs in with it, puts its own key in `~/.ssh/authorized_keys` (once: adding the same host again changes nothing), checks that the key works, and drops the password. It is not stored, logged, written to History or sent back, and tests look for it in the database files, the keys folder, the log, History and every answer. Nothing else on the page ever holds a password for a host.
- **The dashboard's SSH key** is made on the first start in `<data>/keys/id_ed25519` (mode `0600`); only its public half is ever shown (Settings). Losing the data folder loses it: hosts would have to be given a new key.
- **Host keys: trust on first use**, saved in `<data>/keys/known_hosts` (OpenSSH's format, so Ansible can use the same file). After that a different key is refused, always. A reinstalled host shows as **Host key changed** until an admin looks at both fingerprints and chooses **Trust the new key**, which is written to History. Trusting only works for the fingerprint that was shown.
- **Remote commands go through the host's shell**, so every value in one is checked against a strict pattern and then quoted by `remote.ShellQuote`, which is tested against a real shell. The scripts that run on a host are constants of the program that read their values as `$1`, `$2`. The dashboard sends no free text to a host in IM2.
- **The check every minute** logs in to each host with the key, a few at a time, and reads its state; it changes nothing on the host. A host that refused the key or showed a different host key is tried only every ten minutes, so that a broken host does not fill its own log with failed logins (and get this machine banned). A host that is being rebooted is left alone until it answers.
- **Run a command is the one place free text goes to a host.** Only an admin may, the command is written to History word for word (with the exit code), it stops after a timeout (1 to 120 s), and it can run as root only on a host where the dashboard has sudo. Every other action sends a fixed command with, at most, a service name that was checked against a strict pattern and quoted.
- **Ansible runs as a separate program on generated files.** `ansible.cfg` points at the dashboard's key and its own `known_hosts` with strict host key checking, so Ansible trusts exactly the hosts that were added and no password is involved. The files are rendered from the database right before each run; a variable cannot override the connection settings the dashboard writes itself. Only one Ansible run goes at a time. Variables and the Code page are for operators and admins (a value may not be for every viewer); History records the names of changed variables, not their values.
- **Configuring is safe to repeat and safe to read first.** The roles are built from modules, so a second run changes nothing (Check again proves it); Preview shows what would change before anything does. Every value a person types into a profile is checked against a strict pattern, because it ends up in a file on a host. **SSH hardening can never lock the dashboard out:** it is refused on a host the dashboard logs in to as root, and a host that is to get it is logged in to with the dashboard's key first; the file it writes is checked with `sshd -t` before it is put in place. Preview, Apply and Check again are for operators and admins; changing a profile is for admins.
- **sudo:** `sudo -n true` tells whether commands can run as root. When sudo asks for a password and the person allowed it, the dashboard writes `/etc/sudoers.d/infra-manager-<user>` after `visudo -cf` accepted it, and Remove takes it out again.
- **Rolling runs stop at a failure.** `serial` and `max_fail_percentage: 0` are written into the generated playbooks from a number the dashboard checked; a host the run never reached is reported as *not reached* and nothing is recorded about it. Updating packages is always rolling, and **Reboot one by one** stops at the first host that does not come back.
- **Access is exact.** The dashboard writes down which keys it put on which host, so Revoke everywhere (and deleting a key) really takes the key off every one of them, and it never touches a key it did not put there. A key is public, so the Access page shows it; it is an admin's page all the same, because who may log in where is the most sensitive thing the dashboard does.
- **Secrets are write-only.** A value is typed once, goes to `ansible-vault` on its standard input (never in an argument, so not in the process list or in a command the page shows), and only the ciphertext is kept. The vault password is made once in `<data>/secrets/` (`0600`). The page lists names and where each is used; nothing can read a value back, and tests look for it in every answer, the log, History and every file of the data folder.
- **Custom playbooks run as root** on the hosts they are aimed at, so they are an admin's, to save and to run; a playbook is saved only if `--syntax-check` accepts it, is aimed with `--limit` (it can only narrow its own `hosts:`), and is in History.
- **Proxmox API token secret is write-only.** Only the endpoint, token ID and TLS flag are in the database; the token secret lives exclusively in `<data>/secrets/proxmox.tfvars.json` (`0600`), never in `terraform/`, History, logs, or API answers (tested). **Only the reviewed saved plan is applied**, by its random ID, once, within 15 minutes, and only if the desired machines did not change since the plan was made. One Terraform job runs at a time. A Terraform-generated host's address cannot be edited on the Hosts page (the machine owns it).
- A secret is never written to the database, a log or History.

## How it is built

```
cmd/infra-manager/   main.go (serve), service.go (systemd install), listen.go (the -listen check),
                     user.go + password*.go (`user create`, hidden password input)
internal/store/      the data directory, the database, the migrations; users.go (accounts and the
                     last-admin rule), sessions.go, history.go, hosts.go, groups.go, profiles.go,
                     access.go, settings.go, machines.go
internal/web/        server.go (the route table, the session check), permissions.go (can), auth.go (login),
                     users.go, profile.go, history.go, hosts.go, ops.go (quick actions), groups.go, ansible.go,
                     config.go (profiles, plans, state), configure.go (preview, apply; every kind of run goes
                     through execute), patch.go (update packages, reboot one by one), access.go, secrets.go,
                     playbooks.go, proxmox.go (Proxmox settings and discovery), machines.go (create, resize,
                     remove, start/stop, Terraform plan/apply and auto-enrollment), overview.go (the API),
                     monitor.go (the check every minute, the reboot watcher), ratelimit.go, security.go (cross-site
                     check, CSP), sse.go (streams a job's log, used from IM4), answers.go
internal/remote/     everything over SSH: key.go (the dashboard's key), knownhosts.go (trust on first use), shell.go
                     (ShellQuote and the checks of what a person types), client.go, enroll.go (add, check, trust, remove),
                     facts.go, health.go (the check every minute), ops.go (restart, logs, reboot, run, details),
                     explain.go (errors as sentences); remotetest/ is an SSH server for tests, with stubs for
                     sudo, reboot and the like so that a test can never touch the machine it runs on
internal/run/        starts a local program, strips colour codes, keeps the command in the form a person types it
internal/tf/         proxmox.go (Proxmox VE API client, validation, 0600 secret file), generate.go (versions.tf,
                     provider.tf, main.tf, machines.auto.tfvars.json), runner.go (terraform commands),
                     plan.go (reads `terraform show -json` for plans and state, plain summaries), explain.go (errors as sentences)
internal/ansible/    generate.go (the files Ansible reads: render, write, read back for View code, the checks of
                     group names and variables), library.go (the roles, their settings and the checks of them,
                     profiles merged into a plan per host, fingerprints), roles/ (the roles themselves, embedded),
                     runner.go (the commands), vault.go (secrets: names, the vault password, ansible-vault),
                     parse.go (reads the PLAY RECAP, diffs, failures, the one-line output
                     and facts), explain.go (errors as sentences)
web/static/          index.html, style.css, app.js, headnode-mark.svg, compiled into the program
docs/                roadmap.md, deploy.md
```

The tests of `internal/remote` and `internal/web` that add hosts talk to a real SSH server inside the test and run the real scripts with `sh`; they are skipped where there is no `sh` (plain Windows without Git's tools). The tests that run Ansible use stand-ins for `ansible`, `ansible-playbook` and `ansible-vault`: shell scripts that read the generated files, put on `PATH` for the test. They are skipped on Windows, which does not run a script by its first line.
