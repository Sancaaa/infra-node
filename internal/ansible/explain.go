package ansible

import "strings"

// Explain turns the SSH and sudo errors of an unreachable or failed host into
// a sentence that says what to do (day 27, case 8 of the study roadmap). An
// unknown error gets "": Ansible's own message is then shown as it is.
func Explain(raw string) string {
	t := strings.ToLower(raw)
	has := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(t, w) {
				return true
			}
		}
		return false
	}
	switch {
	case has("permission denied (publickey"):
		return "The host refused the SSH key. Copy your public key to it (ssh-copy-id), or point Ansible at the right key (private_key_file in ansible.cfg)."
	case has("identity file") && has("not accessible", "no such file"):
		return "The SSH key that ansible.cfg or the inventory names does not exist on this machine."
	case has("missing sudo password", "sudo: a password is required", "incorrect sudo password"):
		return "sudo asks for a sudo password on the host, so Ansible cannot become root. Give the user NOPASSWD in sudoers, or edit the host to configure passwordless sudo."
	case has("host key verification failed"):
		return "SSH does not trust this host's key yet. Check the host on the Hosts page, or trust the new key if the host was rebuilt."
	case has("could not resolve hostname", "name or service not known"):
		return "The host name cannot be resolved. Use its IP address in the inventory, or fix DNS or /etc/hosts."
	case has("connection timed out", "no route to host", "network is unreachable"):
		return "The host cannot be reached over the network. Is it on, and is the address in the inventory right?"
	case has("connection refused"):
		return "Nothing answers on the SSH port. Is sshd running on the host, and is the port right?"
	case has("/usr/bin/python", "python") && has("not found", "no such file"):
		return "Python is missing on the host, and Ansible's modules need it. Install python3 there, or set ansible_python_interpreter."
	case has("couldn't resolve module/action", "couldn't resolve module", "community.general"):
		return "A role needs an Ansible collection that is not installed here (community.general). The Debian and Ubuntu package \"ansible\" has it; with ansible-core run: ansible-galaxy collection install community.general"
	case has("could not get lock", "dpkg frontend lock", "unable to acquire the dpkg"):
		return "Another package manager is running on the host (an automatic update, most likely). Try again in a minute."
	case has("no package matching"):
		return "A package in the list does not exist on this host's distribution or release. Check the package names."
	}
	return ""
}
