package tf

import "strings"

// Explain turns the errors that come up again and again into a sentence that
// says what to do. The page shows the sentence and keeps Terraform's own text
// under it, folded. An unknown error gets "": the raw text is then the message.
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
	case has("error acquiring the state lock", "locked a portion of the file", "state lock", "lock info:"):
		return "Another terraform is using this folder's state. Is terraform running in a terminal? Wait for it to finish, then try again."
	case has("terraform init") && has("required", "not installed", "inconsistent dependency lock", "module not installed", "could not load plugin", "please run"):
		return "Terraform is not initialized for its providers. Run a plan again (the dashboard initializes automatically) or check provider connectivity."
	case has("401", "authentication failure", "permission check failed", "unauthorized", "invalid token", "no such token", "invalid credentials"):
		return "The API refused the login. Check the token the provider reads (for Proxmox: user@realm!tokenid=uuid) and that it has the permissions it needs."
	case has("no such host", "connection refused", "i/o timeout", "no route to host", "context deadline exceeded"):
		return "Terraform could not reach the API at the provider's endpoint. Is the server on, and is the address in the provider block right?"
	case has("x509:", "certificate signed by unknown authority", "tls: failed to verify"):
		return "The Proxmox server's TLS certificate is not trusted. If it uses a self-signed certificate, turn on \"Allow self-signed TLS certificate\" in Settings → Proxmox."
	case has("no configuration files"):
		return "This folder has no .tf files."
	}
	return ""
}
