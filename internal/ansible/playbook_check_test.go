package ansible

import (
	"strings"
	"testing"
)

func TestCheckPlaybookContentAllowsSafePlaybooks(t *testing.T) {
	safe := []string{
		"- name: Tune\n  hosts: all\n  become: true\n  tasks:\n    - ansible.builtin.debug:\n        msg: hello\n",
		"# Never use local_action, delegate_to: localhost, connection: local, or lookup('file', '/etc/passwd')\n- hosts: web:db # not localhost\n  connection: ssh\n  tasks:\n    - ansible.builtin.apt:\n        name: curl\n      delegate_to: db-1\n",
		"- hosts: web\n  tasks:\n    - ansible.builtin.command:\n        cmd: systemctl status nginx\n      when: app_env == \"prod\"\n",
	}
	for i, content := range safe {
		if err := CheckPlaybookContent(content); err != nil {
			t.Errorf("safe[%d]: unexpectedly rejected: %v", i, err)
		}
	}
}

func TestCheckPlaybookContentRejectsControlPlaneEscape(t *testing.T) {
	cases := []struct {
		name, content, wantErr string
	}{
		{"local_action block", "- hosts: all\n  tasks:\n    - local_action: command id\n", "local_action"},
		{"local_action flow", "- hosts: all\n  tasks:\n    - { name: x, local_action: 'command id' }\n", "local_action"},
		{"delegate_to localhost", "- hosts: all\n  tasks:\n    - command: id\n      delegate_to: localhost\n", "delegate"},
		{"delegate_to 127.0.0.1", "- hosts: all\n  tasks:\n    - command: id\n      delegate_to: 127.0.0.1\n", "delegate"},
		{"delegate_to ::1", "- hosts: all\n  tasks:\n    - command: id\n      delegate_to: \"::1\"\n", "delegate"},
		{"delegate_to 0.0.0.0", "- hosts: all\n  tasks:\n    - command: id\n      delegate_to: 0.0.0.0\n", "delegate"},
		{"delegate_to multiline", "- hosts: all\n  tasks:\n    - command: id\n      delegate_to:\n        127.0.1.1\n", "delegate"},
		{"delegate_to jinja", "- hosts: all\n  tasks:\n    - command: id\n      delegate_to: \"{{ 'local' + 'host' }}\"\n", "delegate"},
		{"connection local", "- hosts: all\n  connection: local\n  tasks: []\n", "connection"},
		{"connection fqcn local", "- hosts: all\n  connection: ansible.builtin.local\n  tasks: []\n", "connection"},
		{"connection flow", "- { hosts: all, connection: local, tasks: [] }\n", "connection"},
		{"connection jinja", "- hosts: all\n  connection: \"{{ conn }}\"\n  tasks: []\n", "connection"},
		{"hosts localhost", "- hosts: localhost\n  tasks: []\n", "localhost"},
		{"hosts union localhost", "- hosts: web:localhost\n  tasks: []\n", "localhost"},
		{"hosts multiline list", "- hosts:\n  - web\n  - 127.0.0.1\n  tasks: []\n", "localhost"},
		{"hosts ipv6 loopback", "- hosts: \"::1\"\n  tasks: []\n", "localhost"},
		{"hosts jinja", "- hosts: \"{{ target }}\"\n  tasks: []\n", "localhost"},
		{"lookup file", "- hosts: all\n  tasks:\n    - debug:\n        msg: \"{{ lookup('file', '/etc/passwd') }}\"\n", "lookup"},
		{"query env", "- hosts: all\n  tasks:\n    - debug:\n        msg: \"{{ query('env', 'PATH') }}\"\n", "lookup"},
		{"q shorthand jinja", "- hosts: all\n  tasks:\n    - debug:\n        msg: \"{{ q('pipe', 'id') }}\"\n", "lookup"},
		{"q shorthand when", "- hosts: all\n  tasks:\n    - debug:\n        msg: hi\n      when: q('env', 'USER') != ''\n", "lookup"},
		{"with_file", "- hosts: all\n  tasks:\n    - debug:\n        msg: \"{{ item }}\"\n      with_file:\n        - /etc/passwd\n", "lookup"},
		{"vars_files", "- hosts: all\n  vars_files:\n    - /etc/passwd\n  tasks: []\n", "vars_files"},
		{"include_vars", "- hosts: all\n  tasks:\n    - ansible.builtin.include_vars:\n        file: /etc/passwd\n", "include_vars"},
		{"add_host", "- hosts: all\n  tasks:\n    - ansible.builtin.add_host:\n        name: localbox\n", "add_host"},
		{"ansible_connection", "- hosts: all\n  vars:\n    ansible_connection: local\n  tasks: []\n", "connection"},
		{"ansible_ssh_common_args", "- hosts: all\n  vars:\n    ansible_ssh_common_args: '-o ProxyCommand=id'\n  tasks: []\n", "SSH transport"},
	}
	for _, tc := range cases {
		err := CheckPlaybookContent(tc.content)
		if err == nil {
			t.Errorf("%s: accepted, want error containing %q", tc.name, tc.wantErr)
			continue
		}
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.wantErr)) {
			t.Errorf("%s: got %q, want %q", tc.name, err.Error(), tc.wantErr)
		}
	}
}
