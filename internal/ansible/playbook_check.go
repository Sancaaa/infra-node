package ansible

import (
	"regexp"
	"strings"
)

// Static guardrails for custom playbooks. Custom playbooks may manage remote
// hosts over SSH, never execute commands or read files/secrets on the
// dashboard host (the Ansible control plane).

var (
	playbookRules = []struct {
		re  *regexp.Regexp
		msg string
	}{
		{regexp.MustCompile(`(?im)(?:^|[\s,{}\-])['"]?local_action['"]?\s*:`), "Custom playbooks cannot use local_action because it runs on the dashboard host instead of the managed hosts."},
		{regexp.MustCompile(`(?im)(?:^|[\s,{}\-])['"]?ansible_(?:connection|ssh_\w+|scp_\w+|sftp_\w+|private_key_file)['"]?\s*[:=]`), "Custom playbooks cannot override Ansible connection or SSH transport variables."},
		{regexp.MustCompile(`(?im)(?:^|[\s,{}\-])['"]?connection['"]?\s*:\s*['"]?(?:(?:[\w.]+\.)?local\b|\{\{|\{%)`), "Custom playbooks cannot use a local or dynamic connection (connection: local runs on the dashboard host)."},
		{regexp.MustCompile(`(?i)\b(?:lookup|query)\s*\(`), "Custom playbooks cannot use Ansible lookup or query plugins because they run on the dashboard host."},
		{regexp.MustCompile(`(?im)(?:^|[\s,{}\-])['"]?with_(?:file|pipe|env|password|ini|csvfile|lines|first_found|fileglob|vars|varnames|filetree|template|config|unvault|url|dig|dnstxt|unix_chkpwd)['"]?\s*:`), "Custom playbooks cannot use Ansible lookup or query plugins because they run on the dashboard host."},
		{regexp.MustCompile(`(?im)(?:^|[\s,{}\-])(?:when|failed_when|changed_when|until|that)\s*:[^\n]*\bq\s*\(`), "Custom playbooks cannot use Ansible lookup or query plugins because they run on the dashboard host."},
		{regexp.MustCompile(`(?im)(?:^|[\s,{}\-])['"]?(?:vars_files|(?:ansible\.(?:builtin|legacy)\.)?include_vars)['"]?\s*:`), "Custom playbooks cannot read files from the dashboard host with vars_files or include_vars."},
		{regexp.MustCompile(`(?im)(?:^|[\s,{}\-])['"]?(?:ansible\.(?:builtin|legacy)\.)?add_host['"]?\s*:`), "Custom playbooks cannot add dynamic hosts with add_host."},
	}
	jinjaBlockRe  = regexp.MustCompile(`(?s)\{\{.*?\}\}|\{%.*?%\}`)
	shortQueryRe  = regexp.MustCompile(`(?i)\bq\s*\(`)
	delegateKeyRe = regexp.MustCompile(`(?i)(?:^|[\s,{}\-])['"]?delegate_to['"]?\s*:`)
	hostsKeyRe    = regexp.MustCompile(`(?i)(?:^|[\s,{}\-])['"]?hosts['"]?\s*:`)
	localTargetRe = regexp.MustCompile(`(?i)\{\{|\{%|\b(?:localhost|ip6-localhost|ip6-loopback|127\.\d+\.\d+\.\d+|0\.0\.0\.0)\b|(?:^|[^0-9a-f:])(?:::1?|0:0:0:0:0:0:0:1)(?:$|[^0-9a-f:])`)
)

// CheckPlaybookContent refuses custom playbook constructs that execute on or
// read files/environment variables from the dashboard host (control plane).
func CheckPlaybookContent(content string) error {
	clean := stripYAMLComments(content)
	for _, rule := range playbookRules {
		if rule.re.MatchString(clean) {
			return CheckError(rule.msg)
		}
	}
	for _, block := range jinjaBlockRe.FindAllString(clean, -1) {
		if shortQueryRe.MatchString(block) {
			return CheckError("Custom playbooks cannot use Ansible lookup or query plugins because they run on the dashboard host.")
		}
	}
	if keyHasLocalTarget(clean, delegateKeyRe) {
		return CheckError("Custom playbooks cannot delegate tasks to localhost or the dashboard host.")
	}
	if keyHasLocalTarget(clean, hostsKeyRe) {
		return CheckError("Custom playbooks cannot target localhost in hosts.")
	}
	return nil
}

// stripYAMLComments strips # comments outside single/double quotes, line by line.
func stripYAMLComments(content string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		var quote byte
		for j := 0; j < len(line); j++ {
			c := line[j]
			if quote != 0 {
				if c == '\\' && quote == '"' {
					j++
				} else if c == quote {
					quote = 0
				}
			} else if c == '\'' || c == '"' {
				quote = c
			} else if c == '#' && (j == 0 || line[j-1] == ' ' || line[j-1] == '\t') {
				line = line[:j]
				break
			}
		}
		lines[i] = strings.TrimRight(line, "\r")
	}
	return strings.Join(lines, "\n")
}

// keyHasLocalTarget reports whether any value for keyRe (inline, flow, or
// indented/list continuation) targets localhost, loopback, or a Jinja template.
func keyHasLocalTarget(clean string, keyRe *regexp.Regexp) bool {
	lines := strings.Split(clean, "\n")
	for i, line := range lines {
		loc := keyRe.FindStringIndex(line)
		if loc == nil {
			continue
		}
		if val := strings.TrimSpace(line[loc[1]:]); val != "" {
			if strings.Contains(line[:loc[0]], "{") {
				if cut := strings.IndexByte(val, '}'); cut >= 0 {
					val = val[:cut]
				}
			}
			if localTargetRe.MatchString(val) {
				return true
			}
			continue
		}
		for j := i + 1; j < len(lines); j++ {
			trimmed := strings.TrimSpace(lines[j])
			if trimmed == "" {
				continue
			}
			if localTargetRe.MatchString(trimmed) {
				return true
			}
			if !strings.HasPrefix(trimmed, "-") {
				break
			}
		}
	}
	return false
}
