# Deploying infra manager on a VPS

infra manager runs on a small Linux VPS (Debian or Ubuntu, with systemd) as a service, behind Caddy for HTTPS. It listens on `127.0.0.1` only, so Caddy is the one door in from the internet.

You need: a VPS you can log into as root (or with `sudo`), a domain name whose DNS record points at it (`infra.example.com` below), and ports 80 and 443 open. If headnode already runs on that VPS, its Caddy is the one to use: see the note in step 4.

Everything behind the page needs a login (step 3). The session cookie is marked `Secure`, so the dashboard only works over HTTPS, which Caddy provides (step 4).

## 1. Get the program onto the VPS

On your computer, in `otherDashboard/infra-manager`, build it for Linux. It is one file with the web page inside:

```powershell
$env:CGO_ENABLED = "0"; $env:GOOS = "linux"; $env:GOARCH = "amd64"
go build -o bin/infra-manager-linux-amd64 ./cmd/infra-manager
```

(`./scripts/build.sh` does the same for amd64 and arm64 where bash is available.) Then copy it over:

```powershell
scp bin/infra-manager-linux-amd64 you@<vps>:/tmp/infra-manager
```

## 2. Install the service

On the VPS:

```sh
chmod +x /tmp/infra-manager
sudo /tmp/infra-manager service install
```

It says what it does, in this order:

1. creates the system user `infra-manager` (no login shell, no password),
2. creates `/var/lib/infra-manager`, mode `0700`, owned by that user,
3. copies the program to `/usr/local/bin/infra-manager`,
4. writes `/etc/systemd/system/infra-manager.service` (it runs as `infra-manager`, **not root**) and starts it.

When it ends it says "infra manager is running as a service". The service listens on `127.0.0.1:8095`. Another port: `sudo /tmp/infra-manager service install -listen 127.0.0.1:9000` (and change the Caddy line below to match).

Check it:

```sh
systemctl status infra-manager
ls -ld /var/lib/infra-manager          # drwx------ ... infra-manager infra-manager
ss -ltn | grep 8095                    # 127.0.0.1:8095, not 0.0.0.0
curl -s http://127.0.0.1:8095/ | head -3
```

### Updating

Build and copy the new program as in step 1, then run `sudo /tmp/infra-manager service install` again. It replaces the program and restarts the service. The data is not touched, and database changes are applied when the service starts.

### Removing

```sh
sudo infra-manager service uninstall
```

It stops and removes the service, and leaves the program, the user and `/var/lib/infra-manager` where they are (that folder will hold the keys and secrets, so deleting it is your decision). It prints the one command that removes them too.

## 3. Create the first admin

Nobody can log in until there is a user. Create the first admin with the service's own user (not root: the database files would end up owned by root, and the service could not write them). It asks for the password, and shows nothing while you type:

```sh
sudo -u infra-manager infra-manager user create --admin ada
```

A password is 10 to 72 characters. Everyone after the first admin is created on the **Users** page.

If you forget it, there is no reset by e-mail: another admin resets it on the Users page. If the only admin is locked out, create a second admin with the same command and a new name (the service can keep running), log in with it, and reset the first.

## 4. HTTPS with Caddy

Point your domain's DNS record at the VPS. Install Caddy (the official Debian and Ubuntu package, from [caddyserver.com/docs/install](https://caddyserver.com/docs/install)):

```sh
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy
```

Put this in `/etc/caddy/Caddyfile`, with your own name:

```
infra.example.com {
	reverse_proxy 127.0.0.1:8095

	header Strict-Transport-Security "max-age=31536000"
}
```

```sh
sudo systemctl reload caddy
```

Caddy gets and renews the certificate by itself. If you use a firewall, allow the ports: `sudo ufw allow 80,443/tcp` (and keep 22 for ssh).

Caddy passes the `Host` header on unchanged, which the dashboard's cross-site check relies on: it compares a request's `Origin` with the `Host` it was sent to. Do not change `Host` in the proxy.

**If headnode already runs on this VPS**, do not install a second Caddy. Add the `infra.example.com { ... }` block above to the Caddyfile that is there (`deploy/Caddyfile` in headnode shows its block) and reload Caddy.

Open `https://infra.example.com`: the login page. Log in as the admin from step 3 and you see the sidebar and **No hosts yet**.

Caddy sets `X-Forwarded-For` to the visitor's address, and the dashboard believes it only from this same machine. It uses it for the login limit (3 free wrong passwords per address, then a growing wait) and for History. So Caddy has to run on the VPS itself, not on another machine.

## 5. Install Ansible and Terraform

They run on the same VPS, as the service user, and are found through the normal system `PATH`. IM0 does not call them yet: Ansible is first used in IM4 and Terraform in IM7. Installing them now means the VPS is ready. Install them with the system's package manager (`apt`), not into your own home folder (`pipx`, `~/bin`): the service cannot see your home.

**Ansible**, plus the `ssh` program that it runs:

```sh
sudo apt install -y ansible openssh-client
ansible --version
```

The `ansible` package of a Debian or Ubuntu release is the version that release froze, so it can be a few releases behind. It is fine to start with; on Ubuntu the Ansible project's PPA has a newer one if a later milestone needs it.

**Terraform**, from HashiCorp's own apt repository (Terraform is not in Debian's or Ubuntu's):

```sh
sudo apt install -y gnupg lsb-release wget
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install -y terraform
terraform version
```

Check that the service user can run both (they are on its `PATH`):

```sh
sudo -u infra-manager ansible --version
sudo -u infra-manager terraform version
```

The VPS must also be able to reach the Proxmox API (port 8006) and your hosts over SSH (port 22). That is for IM2 and IM7: a firewall or a VPN between the VPS and your lab is something to sort out before them.

## 6. Add a host

The VPS must be able to reach the host's SSH port (22 by default). On the host you need a user that can log in with a password (or one you can paste a key for) and, to configure the host later, that can use `sudo`.

1. **Hosts → Add host.** Give it a name, its address and SSH user, and its password. Leave **Let the dashboard use sudo without a password** ticked unless the user already has passwordless sudo or you do not want the dashboard to configure this host.
2. The dashboard logs in with the password, puts its own key in `~/.ssh/authorized_keys`, checks that logging in with the key works, and forgets the password. A few seconds later the host is in the table, *Online*, with its OS and sizes.

If you would rather not give the dashboard a password at all, choose **I added the key myself**: the dialog shows one line to run on the host (the same line is on **Settings**), then press Add host.

The first time a host is added, the dashboard saves its SSH host key (trust on first use), in `/var/lib/infra-manager/keys/known_hosts`. If the host is reinstalled, its key changes, and the dashboard refuses to connect until an admin has looked at the new key and chosen **Trust the new key** (row menu ⋯). A reinstalled host has also lost the dashboard's login key: after trusting, **Edit** the host and give its password to install the key again.

**Remove** forgets the host, and (ticked by default) takes the dashboard's key, and the sudo rule it wrote if any, off the host.

## 7. Status and quick actions

Each minute the dashboard logs in to every host and reads its load, memory, disk, uptime, failed services and whether a reboot or updates are waiting. A host that stops answering is *Offline* within about a minute, with "last seen" under it. The first check runs a few seconds after the service starts.

From a host's row (⋯): **Details** (read from the host right then, including its listening ports), **Restart a service** and **Service logs** (picked from the host's own list of services), **Reboot** (the page shows *Rebooting* and waits until the host answers again, up to ten minutes), and for admins **Run a command**. Restart, logs and reboot need `sudo` for the dashboard on that host (the **no sudo** tag says when it has none).

The **Overview** page counts hosts online, with failed services, with updates waiting and needing a reboot. "Updates waiting" is what `apt-get -s upgrade` says from the host's own package list: the dashboard does not run `apt update`, so keep the hosts' lists fresh (the `unattended-upgrades` or `apt-daily` timers do it on Debian and Ubuntu).

## 8. Groups and Ansible

**Groups → Create group** (`web`, say), then **Hosts in it…** and tick the hosts. **Variables…** on a group or a host is a form of names and values; they become Ansible variables. **Code** shows the files Ansible reads (`ansible.cfg`, `inventory.ini`, `group_vars/web.yml`, …): they are generated from what you click, every time Ansible runs, and are read-only.

**Ping with Ansible** (row ⋯ of a host, or of a group) runs `ansible <name> -m ping` on those files. It needs, on the VPS, `ansible` and the `ssh` program (step 5), and on each host, Python 3 (`sudo apt install -y python3` on a minimal Debian). Green means Ansible can reach the host: that is what configuring it needs, and the check every minute (which does not use Ansible) does not prove it. Turn on **Show commands** in the sidebar to see the command behind a button.

As the service user, you can run the same thing by hand, which is how to learn Ansible:

```sh
sudo -u infra-manager env ANSIBLE_CONFIG=/var/lib/infra-manager/ansible/ansible.cfg ansible web -m ping
```

## 9. Configure hosts with profiles

A **profile** is a list of roles with their settings. Give one to a **group** (**Groups → ⋯ → Profile…**) or to a single **host** (**Hosts → ⋯ → Profile…**); a host gets its groups' roles plus its own. The roles: base system (packages, time zone, chrony), a user with SSH keys and sudo, SSH hardening, firewall (ufw), nginx, Docker, and the Prometheus node exporter. They are for **Debian and Ubuntu** hosts, and the host needs `sudo` for the dashboard (the **no sudo** tag says when it has none).

Then, from the same menu:

1. **Preview…** runs a dry run and lists, for each host, what would change, in plain words. **Show the file changes** opens the diff.
2. **Apply…** asks for confirmation, then shows the live log and a recap. Every task is safe to run again.
3. **Check again** (offered after an apply that worked) runs it a second time: it should say **Idempotent ✓**. If not, it names the tasks that changed again.

The Hosts page shows each host's state: *never applied*, *applied*, *failed*, or *changes waiting* (its profile changed since it was applied). The Overview counts the failing and the waiting.

The roles need the Ansible collection `community.general` (for ufw). The Debian and Ubuntu package `ansible` includes it; with only `ansible-core`, run `sudo -u infra-manager ansible-galaxy collection install community.general`. To check the generated playbook by hand:

```sh
cd /var/lib/infra-manager/ansible
sudo -u infra-manager env ANSIBLE_CONFIG=$PWD/ansible.cfg ansible-playbook site.yml --syntax-check
```

**SSH hardening** turns off root login and password login. It is applied only to a host the dashboard has just logged in to with its key, and never turns off root login on a host the dashboard logs in to as root: to harden such a host, first apply the **users** role (a user with your key and sudo), then **Edit** the host to log in as that user. Keep a second way in (a console) the first time you try it on a machine you care about.

On a **Proxmox LXC container**, ufw may not start (it needs iptables), and Docker needs *nesting* switched on for the container.

## 10. Operations at scale

- **Rolling:** the Apply dialog has **Rolling** (all at once, one at a time, 2, 3, 5, 10). A rolling run stops after the batch in which a host fails; the hosts after it show *Not reached* and are left exactly as they were.
- **Update packages…** (row ⋯ of a group or a host): `apt update`, then a safe upgrade, one host at a time by default. **Preview first…** is a dry run. Afterwards the recap lists the hosts that need a reboot, with **Reboot one by one…**: each host must answer again before the next is touched, and it stops at the first one that does not come back.
- **Access** (admin): **Add a key** (name + the public key line), **Where it may log in…** (groups and single hosts), then **Preview…** and **Apply…**. Granting changes no host until Apply. **Revoke everywhere…** takes one key off every host it was put on. The playbook uses `ansible.posix.authorized_key` (in the Debian and Ubuntu `ansible` package; with only `ansible-core`: `sudo -u infra-manager ansible-galaxy collection install ansible.posix`).
- **Secrets** (admin) need `ansible-vault` (part of the `ansible` package). A value is typed once and can never be shown again. Use one in a role's setting (the nginx proxy token) or write `secret:name` as a variable's value. The vault password is made in `/var/lib/infra-manager/secrets/vault_password` (`0600`): back it up with the data folder, because without it the stored secrets cannot be read.
- **Playbooks** (admin): write one in the editor; it is saved only if `ansible-playbook --syntax-check` accepts it. **Run on…** gives a Preview first. It runs as root on the chosen hosts. Use `no_log: true` on a task that handles a secret.

## 11. Proxmox and Terraform (Machines)

1. In Proxmox VE, create an API token (Datacenter → Permissions → API Tokens) with permissions to create, resize, start/stop and destroy LXC containers and allocate disk space (for example a dedicated user with `PVEAdmin` or a custom role, and **Privilege Separation** unchecked if the token should inherit the user's roles). Note the token ID (`user@realm!tokenname`) and the secret UUID.
2. In **Settings → Proxmox** (admin): enter the Proxmox endpoint (`https://<pve-ip>:8006`), the API token ID, and the token secret. Tick **Allow self-signed TLS certificate** if your Proxmox node uses its default self-signed certificate. Press **Save settings**, then **Test connection**: it checks the Proxmox API and fills the lists of nodes, rootdir storages, network bridges and LXC templates.
3. On **Machines → Create machine** (admin): pick a name, size preset (Small / Medium / Large, or custom), disk, node, storage, bridge, template, static IP or DHCP, and groups. Leave **Configure it after creation** ticked to apply the groups' profile once the container is up.
4. **Review changes** runs `terraform init` (on first use) and `terraform plan -out=...` and shows the changes in plain words ("1 container will be created", "will be changed in place", or "will be destroyed and created again"). Press **Apply** within 15 minutes to apply that exact saved plan once.
5. After creation, the container has the dashboard's SSH key already installed, becomes an *Online* host on **Hosts** automatically (with its address locked because the machine owns it), joins its groups, and runs its groups' profile if ticked.
6. Operators can **Start** and **Stop** containers from the row ⋯ menu on **Machines**, and run **Check drift** (which also runs every 15 minutes automatically). When a container was changed in the Proxmox GUI, **Machines** shows what changed with **Put it back…** (normal plan/apply) or **Accept** (updates the dashboard's data and refreshes state).
7. Admins can **Resize**, **Rebuild** (`-replace`: recreates the container, automatically trusts its fresh SSH host key with a History entry, and re-applies its profile), **Remove** (destroys only that container and removes its host), **Adopt container…** (from the header ⋯ menu; writes an `import` block and requires "no changes" before adopting), and **State backups…** (automatic backups before every apply, kept 30 deep; **Preview restore** runs `terraform plan -state=<backup>` before touching live state).

To inspect the generated Terraform files by hand (never edit them, the dashboard overwrites them on the next plan):

```sh
ls -la /var/lib/infra-manager/terraform
ls -l /var/lib/infra-manager/secrets/proxmox.tfvars.json   # -rw------- infra-manager
```

## Checklist

- [ ] `systemctl status infra-manager` says `active (running)`, and the process runs as `infra-manager`: `ps -o user= -p $(systemctl show -p MainPID --value infra-manager)`.
- [ ] `ls -ld /var/lib/infra-manager` shows `drwx------ ... infra-manager infra-manager`.
- [ ] `ss -ltn` shows port 8095 on `127.0.0.1` only. The firewall allows only 22, 80 and 443.
- [ ] `https://infra.example.com` shows the login page, and `http://` redirects to it.
- [ ] Without logging in, `curl -s -o /dev/null -w '%{http_code}\n' https://infra.example.com/api/users` prints `401`.
- [ ] You can log in as the admin, and **History** shows the login.
- [ ] `ansible --version` and `terraform version` work for the service user.
- [ ] `ls -l /var/lib/infra-manager/keys` shows `id_ed25519` as `-rw-------`, owned by `infra-manager`, and **Settings** shows the public key.
- [ ] After adding a host with a password: `sudo grep -r 'THE PASSWORD' /var/lib/infra-manager` finds nothing (use a space before the command, or `HISTCONTROL=ignorespace`, so the password does not land in your shell history).
- [ ] On the host, `grep -c infra-manager ~/.ssh/authorized_keys` prints `1`, also after adding it a second time.
- [ ] Two hosts in the group `web` both answer **Ping with Ansible**, green. **Code** shows the inventory with both under `[web]`, and changing a group variable changes `group_vars/web.yml`.
- [ ] Group `web` with the profile base + nginx + firewall: **Preview** lists the changes, **Apply** succeeds, `curl http://web-1` answers, **Check again** says *Idempotent ✓*.
- [ ] SSH hardening on a host: afterwards the dashboard still shows it *Online* and **Ping with Ansible** is green.
- [ ] Update packages on group `web` with one host made to fail (for example `sudo chmod 000 /var/lib/dpkg/lock-frontend` on the second): the first host is updated, the failing one is *Failed*, the rest say *Not reached* and were not touched.
- [ ] Access: add your own second key, give it group `web`, Apply: `grep -c 'that key' ~/.ssh/authorized_keys` prints `1` on every `web` host and you can log in with it. **Revoke everywhere**: it prints `0` on all of them, and the dashboard still logs in.
- [ ] Secrets: add one, use it in nginx's proxy token, Apply; then `sudo grep -r 'THE VALUE' /var/lib/infra-manager` finds nothing, and the History page does not show it.
- [ ] Proxmox: after saving the API token secret, `sudo grep -r 'THE TOKEN SECRET' /var/lib/infra-manager/infra-manager.db /var/lib/infra-manager/terraform /var/lib/infra-manager/ansible` finds nothing; only `/var/lib/infra-manager/secrets/proxmox.tfvars.json` (`-rw-------`) holds it.
- [ ] Machines: create `web-1` and `web-2` in group `web` (with `base` + `nginx`), Review and Apply -> both become *Online* hosts, configured, with nginx answering. Resize `web-1`'s RAM -> Review says "will be changed in place". Remove `web-2` -> destroys only `web-2` and removes its host.
- [ ] Shut a host down: its row says *Offline* within two minutes. Start it: *Online* again.
- [ ] A viewer sees no action buttons on Hosts, and `fetch('/api/hosts/1/restart', {method: 'POST'})` in their browser console answers 403.
- [ ] Backups: the whole `/var/lib/infra-manager` folder is the data. The database is in WAL mode, so stop the service for a moment before copying it (`systemctl stop infra-manager`).

## If something does not work

- **"this needs root"**: put `sudo` in front.
- **"the service did not stay up"**: `journalctl -u infra-manager -n 30` says why. A common cause is another program already using the port: change it with `-listen`.
- **`status=217/USER`** in the log: the user `infra-manager` does not exist. Run `service install` again.
- **"unable to open database file"**: the data folder belongs to someone else (a test run of `serve` as root, say). `service install` fixes the owner; so does `sudo chown -R infra-manager:infra-manager /var/lib/infra-manager`.
- **Logging in works but you are logged out at once, or the page never leaves the login**: the browser dropped the session cookie because it is `Secure` and the page was opened over plain `http://`. Use the `https://` address. Only `http://127.0.0.1` and `http://localhost` are exempt (Chrome and Firefox).
- **"Too many failed attempts"**: the limit is per address. The wait grows with each wrong password and is forgotten after an hour without any, or after a right one. A restart of the service also clears it.
- **Add host says "Nothing answers" or "did not answer in time"**: the VPS cannot reach that address and port. Try `ssh user@address` from the VPS (as yourself).
- **"did not accept that user name and password"**: the user, or its password, is wrong, or sshd has `PasswordAuthentication no`. Use **I added the key myself** then.
- **"did not accept the dashboard's key"** after the key was installed: sshd may refuse keys for that user (`PubkeyAuthentication no`, or `AllowUsers`), or the user's home or `.ssh` is writable by others, which sshd's `StrictModes` refuses. `journalctl -u ssh` on the host says which.
- **A host is added but marked "no sudo"**: sudo asks for a password and the dashboard could not set up a rule. Give the user passwordless sudo yourself (`/etc/sudoers.d/`), then **Check now**.
- **A host stays *Rebooting*, then goes Offline**: it did not answer for ten minutes. Look at its console. If it answers but was never down (the reboot did nothing), History says "the host kept running".
- **A host shows "Key refused" or "Host key changed" and is not checked every minute**: broken hosts are looked at every ten minutes on purpose. **Check now** looks at once.
- **Updates show "Not known"**: the host has no `apt-get` (not Debian or Ubuntu), or has not been counted yet (the first count comes with the first check).
- **Ansible ping says "Python is missing"**: install `python3` on the host. **"Host key verification failed"**: the host's key is not in the dashboard's known_hosts (it was removed by hand, or the host was added another way): remove the host and add it again.
- **Ansible ping says "Permission denied (publickey)"** for a host that shows *Online*: the dashboard's own check logs in, and Ansible does not. Look at `ansible.cfg` in **Code**: `private_key_file` must be the dashboard's key, readable by the service user (`ls -l /var/lib/infra-manager/keys`).
- **"Ansible is not installed"**: the sentence shows the install command; the rest of the dashboard works without it.
- **Preview or Apply says "A role needs an Ansible collection"**: install `community.general` (section 9).
- **A host is "left out" of an Apply**: the answer lists why (no profile, no sudo, SSH hardening refused). Fix that and apply again.
- **Apply says a package does not exist**: the host's distribution or release does not have it. Check the package names in the base role's list.
- **ufw fails on a Proxmox container**: the container is not allowed to change firewall rules. Leave the firewall role off for it, or use Proxmox's own firewall.
- **Access says "couldn't resolve module/action 'ansible.posix.authorized_key'"**: install the `ansible.posix` collection (section 10).
- **Setting a secret says Ansible is not installed**: `ansible-vault` is missing; `sudo apt install -y ansible`.
- **A secret cannot be deleted**: the message names what still uses it. Change those first.
- **A playbook is refused on save**: the answer shows what `--syntax-check` printed. Nothing was saved.
- **Test connection says the TLS certificate is not trusted**: Proxmox ships with a self-signed certificate. Tick **Allow self-signed TLS certificate** in **Settings → Proxmox** and save.
- **Review changes says Terraform is not installed**: install Terraform from HashiCorp's apt repository (section 5); the rest of the dashboard keeps working without it.
- **A created container shows *Offline* or "SSH did not answer yet"**: check that the LXC template includes `openssh-server` (Proxmox's standard Debian and Ubuntu templates do), that the VPS can route to the container's IP on port 22, and that the container is running.
- **Caddy cannot get a certificate**: the DNS record does not point at this VPS yet, or ports 80 and 443 are closed.
- **The page loads without styling**: a proxy that rewrites or caches `/style.css`. Caddy as above does not.
