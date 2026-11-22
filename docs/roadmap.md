# infra manager — Roadmap (v2: hosts first)

This replaces the first two versions (plan `plans/03-infra-manager.md`, OD-04). Those were a Terraform/Ansible **command runner**: you gave it folders, wrote the `.tf` files, inventory and playbooks yourself, and it ran them. The owner's verdict: "a tutorial page, but fancy". The decision behind this roadmap is **OD-06** in `otherDashboard/decisions.md`.

Each milestone is a **vertical slice**: it ends with a demo that runs end to end. Work through them in order. Don't start the next milestone until the owner has checked every done criterion of the current one.

**Status: IM0 to IM7 are done. IM8 is written and waiting for the owner's check (`go test ./...`, then the three demos in its "Done when"). IM9 is not started.**

---

## The idea

You manage **hosts**, not folders and files. Adding a host is a form: address, user, password. Configuring it is ticking what it should have. Creating a container on Proxmox is a form too. Terraform and Ansible do the work underneath. The dashboard writes their files from its own data, runs them, and shows the result in plain words. You never pick a folder or pass a path.

For learning, nothing is hidden. **View code** shows the files the dashboard generated. The **Show commands** switch (off by default) shows the command behind an action, in its confirm dialog and on the first line of its log.

## Where it runs

On a **VPS** (Linux), as a systemd service, behind Caddy for HTTPS. `terraform` and `ansible` are installed on the same VPS. The VPS can reach the Proxmox API and the hosts over SSH.

Because it holds an SSH key that opens every managed host, and the Proxmox API token, **login comes before anything else** (IM1). It listens on `127.0.0.1` and Caddy is the only door.

## How it works inside

```
                 browser
                    │  HTTPS (Caddy) + login
┌───────────────────▼──────────────────────────────────┐
│ infra-manager  (one Go binary, systemd)              │
│                                                      │
│  Data: the truth          /var/lib/infra-manager 0700│
│    database      users, sessions, hosts, groups,     │
│                  profiles, machines, history         │
│    keys/         the dashboard's SSH key, known_hosts│
│    secrets/      vault password, Proxmox token  0600 │
│                                                      │
│  Generated workspaces (rebuilt from the data)        │
│    ansible/      inventory, ansible.cfg, group_vars, │
│                  roles, site.yml                     │
│    terraform/    main.tf, machines.auto.tfvars.json  │
│                                                      │
│  Engines                                             │
│    Go SSH     → hosts: add, status, quick actions    │
│    ansible    → hosts: configure (profiles)          │
│    terraform  → Proxmox: create / change / destroy   │
└──────────────────────────────────────────────────────┘
```

Every change follows the same loop:

1. A click changes the data.
2. The files are generated again.
3. The tool runs in preview mode (`--check --diff`, `terraform plan`).
4. You read the result in plain words and confirm.
5. It applies the change.
6. The change goes to History.

**Terraform without an HCL parser.** The dashboard writes `main.tf` once, with `for_each = var.machines`. After that it only edits `machines.auto.tfvars.json`, which Terraform reads on its own, using Go's `encoding/json`. Ansible is generated from the database, so no INI or YAML ever has to be read back.

## Roles

| Role | Can |
|---|---|
| **viewer** | See hosts, status, details, machines and History. Change nothing. |
| **operator** | Everything a viewer can, plus the fixed quick actions (restart a service, read logs, update packages, reboot), Preview and Apply of profiles, and Start/Stop of machines. |
| **admin** | Everything, plus: add and remove hosts, run any command, edit profiles and groups, manage secrets and people's SSH keys, create, resize and remove machines, manage Proxmox settings and users. |

One `can(user, action)` function on the server decides. The browser only hides buttons.

## Rules for every agent (on top of `plans/README.md`)

- Work only in `otherDashboard/infra-manager/`, and on the active milestone only. Decisions go to `otherDashboard/decisions.md` (the next free `OD-xx`, or an update of OD-06). Never edit headnode files.
- Read headnode's `CLAUDE.md`, `docs/principles.md` and `docs/design.md` as the style guide only.
- Do not run `go`, `git` or other terminal commands. End each milestone with the exact commands for the owner, and what they should print.
- **Exception to `plans/README.md`:** this app is **not** a no-login lab tool. Every `/api/*` route except login checks the session and the role. Every change checks `Origin` and `Sec-Fetch-Site` (`security.go`).
- **Remote commands go through a shell.** SSH `exec` hands one string to the remote shell, so "arguments separate" cannot be enforced there. Every value that goes into a remote command is first checked against a strict pattern (service names, package names, paths), then quoted with one tested `shellQuote` function. Only **Run a command** (admin) sends free text, and it is audited word for word.
- Locally, never `sh -c` with input. `terraform` and `ansible` get separate arguments.
- A secret (a password typed in Add host, the Proxmox token, vault values) is never written to the database, a log, History or an API answer. Tests check this.
- Commands are off by default (OD-04's redesign stays): no "Ran" blocks under every table.

## Dependencies (approved by the owner, 2026-11-22)

1. **`golang.org/x/crypto`** for SSH (`ssh`) and password hashing (`bcrypt`). k3s manager (OD-01) and headnode already use it.
2. **`modernc.org/sqlite`** for storage. It is pure Go, so no cgo is needed, and headnode uses the same one. Users, sessions, hosts, groups, History and writes from several requests at once are what a database is for. JSON files with one mutex were the rejected alternative.

Nothing else without a new approval.

---

## IM0 — Foundation reset
- [x] The two dependencies approved (`x/crypto`, `modernc.org/sqlite`) and recorded in OD-06
- [x] `go.mod` with those two, the database opened at `<data>/infra-manager.db`, and the tables created by simple numbered migrations (`internal/store`; one table, `settings`, see OD-07)
- [x] Keep only what still fits:
  - `internal/run`: ANSI strip, and the command in typed form for Show commands
  - `internal/web/sse.go` and `security.go`
  - `tf/plan.go`: reading `show -json`
  - `tf/explain.go` and `ansible/explain.go`
  - `ansible/parse.go`: the recap
- [x] Delete the rest: the folder flags, the Lab, Make inventory from outputs, the `.tf` lint, the old pages and `NextStep`
- [x] `infra-manager serve -data /var/lib/infra-manager -listen 127.0.0.1:8095`. The data directory is created `0700`, and an existing one with looser permissions gets a warning
- [x] `infra-manager service install|uninstall`: a systemd unit running as its own user `infra-manager`, not root
- [x] An empty page in headnode's style: sidebar, logo, "No hosts yet"
- [x] `docs/deploy.md`: VPS, Caddy with HTTPS, installing `ansible` and `terraform`

**Done when:** on a fresh VPS, `infra-manager service install` starts the service, `https://infra.<your domain>` shows the empty page through Caddy, `/var/lib/infra-manager` is `drwx------`, and `go test ./...` passes.

## IM1 — Login, users, roles, History
- [x] `infra-manager user create --admin <name>`: the first user, created from the CLI, with the password asked on the terminal
- [x] Login and logout. Cookie session: `HttpOnly`, `Secure`, `SameSite=Strict`. Passwords hashed with bcrypt. A login rate limit
- [x] Every `/api/*` checks the session. Every change checks the role with `can()` and the Origin
- [x] **Users** page (admin):
  - create a user with a role
  - change a user's role
  - reset a password (ends that user's sessions)
  - disable or enable a user
- [x] Guards: nobody can disable or demote themselves, and the last enabled admin cannot be disabled or demoted
- [x] **Profile**: change your own password (ends your other sessions), see your sessions, sign out everywhere else
- [x] **History** page: who, what, which host or machine, the result, and when. Every change from here on lands there, refused ones included

**Done when:**
- Without login, every `/api/*` answers 401.
- A viewer gets 403 on every change.
- Disabling a user logs them out at once.
- The last admin cannot remove their own admin role.
- Each of these appears in History.

## IM2 — Add a host
- [x] On first start the dashboard generates its own SSH key (ed25519), `keys/id_ed25519`, mode `0600`. Settings shows the public key with a Copy button
- [x] **Add host** dialog: name, address, port (22), user, and one of:
  - **Password (used once):** the dashboard logs in with it, adds its public key to `~/.ssh/authorized_keys` (once, never twice), checks that key login works, then forgets the password.
  - **I added the key myself:** the dialog shows the one-line command to paste on the host, then tests the key login.
- [x] **sudo:** checked with `sudo -n true`. If it needs a password and Add host had one, an option "Let the dashboard use sudo without a password" writes `/etc/sudoers.d/infra-manager-<user>`, checked by `visudo -cf` before it is moved in place. Without sudo, the host is added and marked "no sudo": configuring it will not work, and the UI says so
- [x] **Host keys:** trust on first use. The host key is saved in `keys/known_hosts`. A changed key refuses every connection with a clear warning, and only an admin can choose **Trust the new key** (audited)
- [x] First facts over SSH: OS, kernel, CPU count, RAM, disks, IP addresses, uptime
- [x] **Hosts** page: a table with name, address, status, OS, CPU / RAM / disk and groups. Row ⋯: Details, Edit, Remove (the groups column comes in IM4, when groups exist; the row menu also has Check now and Trust the new key)
- [x] **Remove** asks whether to also take the dashboard's key out of the host's `authorized_keys`
- [x] Tests: the password does not appear in the database, the data directory, the logs or History; `authorized_keys` keeps one copy after adding twice; a changed host key is refused

**Done when:**
- On a fresh Debian VM, Add host with user and password shows the host *online* with its OS and sizes within seconds.
- `grep -r <that password> /var/lib/infra-manager` finds nothing.
- Adding it again does not duplicate the key.
- Reinstalling the VM (new host key) makes the dashboard refuse it with the warning until an admin trusts the new key.

## IM3 — Status and quick actions
- [x] A health check every 60 s over Go SSH, a few hosts at a time: online or offline, load, RAM, disk, uptime, last seen
- [x] **Host details**:
  - system information
  - disks and their usage
  - IP addresses
  - listening ports (`ss -tlnp`)
  - failed services (`systemctl --failed`)
  - number of pending updates
  - whether a reboot is required
- [x] Quick actions, from the row ⋯ menu and the details page:
  - **Restart a service** (operator; picked from the host's own list)
  - **Service logs** (operator; `journalctl -u <unit> -n 200`)
  - **Reboot** (operator; confirm, then wait until the host is back)
  - **Run a command** (admin; output, exit code, a timeout)
- [x] **Overview** page, first version: hosts online / total, hosts with failed services, hosts with pending updates, hosts that need a reboot
- [x] Every action in History, the command text of Run a command included

**Done when:**
- Shutting a VM down turns it *offline* within two minutes.
- Restarting nginx from the row works, and its logs show.
- Reboot waits and shows the host *online* again.
- A viewer sees no action buttons and gets 403 from the API.

## IM4 — Groups and the Ansible engine
- [x] **Groups**: create, rename and delete a group, add or remove hosts (several at once), and group variables as a key/value form; host variables too
- [x] Generated `ansible/`:
  - `inventory.ini` built from the database
  - `ansible.cfg` with `private_key_file` set to the dashboard's key, the dashboard's own `known_hosts`, `host_key_checking = True` and `remote_user` per host
  - `group_vars/` and `host_vars/`

  Files are written atomically (temp file, then rename).
- [x] **Ping with Ansible** for a host or group (proves the Ansible path, not only Go SSH), and **Facts** (searchable)
- [x] **View code**: the generated files, read-only. The Show commands switch, off by default
- [x] Without `ansible` on the VPS: one sentence with the install command, and the rest of the app keeps working

**Done when:**
- Two hosts in group `web` answer the Ansible ping, green.
- View code shows the inventory with both hosts.
- Changing a group variable in the form changes `group_vars/web.yml`.

## IM5 — Profiles: configure hosts
- [x] A library of built-in roles, embedded in the binary. Each role has a small parameter schema (shown as a form), uses modules rather than `shell`, and restarts services only through handlers, so a second run reports `changed=0`:
  - **base**: updates, a package list, timezone, NTP
  - **users**: a deploy user with SSH keys and sudo
  - **ssh hardening**: no root login, no password login. It is applied only after the dashboard's key login has been checked on that host, so it can never lock the dashboard out
  - **firewall**: ufw, with port 22 always kept open
  - **nginx**: a site with a domain, and a static root or a reverse proxy to an upstream
  - **docker**: the engine and the compose plugin
  - **node_exporter**
- [x] A **profile** = roles plus their parameters, given to a group or to one host. A host's profile is its groups' profiles plus its own
- [x] **Preview**: `--check --diff`, per host, with file diffs, in plain words ("nginx will be installed; /etc/nginx/sites-enabled/app will be created")
- [x] **Apply**: a live log, then the recap as a table. For one host, a group, or one role (`--tags`)
- [x] Configuration state per host: *applied*, *failed*, *never applied*, *changes waiting*. Shown on Hosts and Overview
- [x] **Check again** after an Apply: a second run with a verdict, *Idempotent ✓* or the tasks that changed again

**Done when:**
- Group `web` gets base, nginx and firewall.
- Preview lists what will change.
- Apply succeeds, and `curl http://web-1` answers.
- Check again says *Idempotent ✓*.
- ssh hardening on a host still leaves the dashboard able to log in.

## IM6 — Operations at scale
- [x] **Rolling apply**: N hosts at a time (`serial`), stop when one fails (`max_fail_percentage`)
- [x] **Patching**: "Update packages" for a group, rolling. Afterwards, a list of the hosts that need a reboot and **Reboot one by one** (each waits for the previous one to come back)
- [x] **Access**: people's SSH public keys, each with a name. Give a person access to groups or hosts, or **Revoke everywhere**. Done with Ansible `authorized_key`, so revoking really removes the key
- [x] **Secrets**: values encrypted with `ansible-vault`. The vault password is generated by the dashboard into `secrets/` (`0600`). Secret values are write-only in the UI and can be used as role parameters (a database password, for example)
- [x] **Custom playbooks**: upload or edit a playbook in a plain editor, `--syntax-check` on save, Preview / Apply against a group

**Done when:**
- Updating group `web` one at a time stops at a host that fails, and leaves the rest untouched.
- Giving a teammate access lets their key log into every `web` host, and Revoke removes it from all of them.
- A secret's value never appears in an API answer, a log or History (tested).

## IM7 — Proxmox: create machines (Terraform)
- [x] **Settings → Proxmox**:
  - endpoint and API token id; the token secret is write-only and stored in `secrets/`
  - **Test connection**: stdlib HTTP to the Proxmox API, which also fills the lists of nodes, storages, bridges and templates
- [x] Generated `terraform/`:
  - `versions.tf` (`bpg/proxmox`, a pinned version)
  - the provider settings, read from variables
  - `main.tf` with `proxmox_virtual_environment_container` and `for_each = var.machines`
  - `machines.auto.tfvars.json`
  - the secrets in a `0600` tfvars file

  The dashboard's SSH public key is put into every container at creation.
- [x] **Create machine**: name, size (Small / Medium / Large presets, or custom), disk, IP (static or DHCP), template, groups. Then **Review changes** ("1 container will be created") and **Apply** of that saved plan (OD-04's rule stays: only the plan on screen is applied, once, within 15 minutes)
- [x] After creation, the container **becomes a host by itself**: added with its IP and groups. With "Configure it after creation" ticked, its groups' profile is applied
- [x] **Machines** page: desired against real (*will be created*, *running*, *stopped*, *will change*, *will be removed*). Row ⋯:
  - **Start / Stop**
  - **Resize**: the review says plainly whether it is changed in place or **destroyed and created again**
  - **Remove**: destroys only that container, and its host is removed too
- [x] A Terraform-generated host cannot have its address edited on the Hosts page (the machine owns it)

**Done when:**
- From nothing, Create machine twice (web-1 and web-2, group `web`) gives two containers that appear as hosts, *online*, configured, with nginx answering.
- Giving web-1 more RAM is reviewed as "changed in place".
- Remove web-2 destroys only web-2, and its host leaves the list.

## IM8 — Drift, rebuild, adopt, state safety
- [x] **Drift check** (`plan -refresh-only`) on a button and on a schedule: "web-1 was changed outside the dashboard (memory 1024 → 2048)", with **Put it back** (a normal plan and apply) or **Accept** (writes the new value into the machine's data)
- [x] **Rebuild** (`-replace`): a fresh container with the same name and IP. The host's new SSH host key is trusted automatically, because the dashboard made the machine itself (audited), and the profile is applied again
- [x] **Adopt**: a container made by hand in Proxmox (for example the praktikum one). The dashboard writes an `import` block and the machine's data. The review must show **no changes** before Adopt is allowed; otherwise it lists what does not match
- [x] **State backups** before every apply, kept 30 deep. **Restore** (admin) shows the plan that the restored state would lead to first
- [x] One Terraform job at a time (the mutex from OD-04 stays)

**Done when:**
- Changing a container's memory in the Proxmox GUI shows up as drift on the next check, and Put it back restores it.
- Adopting the praktikum container shows "no changes", and the container then appears as a machine and a host.
- Restoring a backup works.

## IM9 — Compliance and the full Overview
- [x] **Compliance check**: every night (the time is set in Settings), check mode of every host's profile. A host whose files were changed by hand becomes *drifted from its profile*, with the diff and a **Fix** button
- [x] A scheduler for the health check, drift check and compliance check, with the next and last run shown
- [x] **Overview**, full version:
  - hosts online
  - hosts failing their configuration
  - hosts drifted from their profile
  - machines drifted in Proxmox
  - pending updates and reboots
  - the last runs
  - **one "Next step" card** (as in OD-04's redesign)

**Done when:**
- Editing `/etc/nginx/sites-enabled/app` by hand on web-1 marks it *drifted* after the next check, with the diff.
- Fix makes it compliant again.
- The Overview shows both kinds of drift without scrolling.

---

## After the MVP (not scheduled)
To be chosen later by the owner:
- **Proxmox itself as a configuration target**: the Proxmox node added as a host, with Proxmox roles (storage, bridges, downloading templates with `pveam`, `vzdump` backup schedules, API users and tokens).
- Roles scoped to groups: a viewer or operator for group `web` only, as in headnode.
- 2FA.
- Notifications (Telegram or email) for offline hosts, failed applies and drift.
- Proxmox VMs, not only containers.
- Proxmox snapshots before risky changes.
- Other Terraform providers (Cloudflare DNS, a cloud VPS).
- Community roles from Ansible Galaxy.
- A web terminal (headnode already does this).
