package web

import "infra-manager/internal/store"

// Action is something a person can try to do. Every route names the action it
// needs, and can() is the ONE place that says who may do it: the rules of the
// roadmap's "Roles" table can be audited by reading this file. The browser
// only hides buttons; it decides nothing.
type Action string

const (
	// Any logged-in person, whatever their role: their own profile and password.
	ActionSelf Action = "self"
	// Look at things: hosts, status, machines, History.
	ActionView Action = "view"
	// The everyday actions on hosts (operator): check a host now. IM3 adds the
	// quick actions to it.
	ActionOperate Action = "operate"
	// Users page: create, change a role, reset a password, disable.
	ActionManageUsers Action = "users.manage"
	// Add, edit and remove hosts, and trust a host's new key.
	ActionManageHosts Action = "hosts.manage"
	// Run any command on a host. Free text, as root if asked: only an admin.
	ActionRun Action = "hosts.run"
	// Create, rename and delete groups, change who is in them, and edit the
	// variables of groups and hosts.
	ActionManageGroups Action = "groups.manage"
	// Settings: the dashboard's SSH key (and, later, Proxmox).
	ActionSettings Action = "settings.manage"
	// SSH keys of people on the hosts (IM6): who may log in where. Giving access
	// is the most sensitive thing the dashboard does, so it is an admin's.
	ActionAccess Action = "access.manage"
	// Secrets (IM6): setting and deleting them. Nobody can read one back.
	ActionSecrets Action = "secrets.manage"
	// Custom playbooks (IM6): free-form Ansible, run as root on the hosts. It is
	// as powerful as "run a command", so it is an admin's, to save and to run.
	ActionPlaybooks Action = "playbooks.manage"
	// Proxmox machines (IM7): create, resize, remove containers and run Terraform
	// plan/apply. Viewing machines is ActionView; Start/Stop is ActionOperate.
	ActionManageMachines Action = "machines.manage"
)

// roleRank orders the roles: a higher role can do everything a lower one can.
var roleRank = map[string]int{
	store.RoleViewer:   1,
	store.RoleOperator: 2,
	store.RoleAdmin:    3,
}

// minRole is the lowest role that may do each action. Later milestones add
// their actions here (quick actions are operator, adding a host is admin).
var minRole = map[Action]string{
	ActionSelf:        store.RoleViewer,
	ActionView:        store.RoleViewer,
	ActionOperate:     store.RoleOperator,
	ActionManageUsers: store.RoleAdmin,
	ActionManageHosts: store.RoleAdmin,
	ActionRun:          store.RoleAdmin,
	ActionManageGroups: store.RoleAdmin,
	ActionSettings:     store.RoleAdmin,
	ActionAccess:       store.RoleAdmin,
	ActionSecrets:        store.RoleAdmin,
	ActionPlaybooks:      store.RoleAdmin,
	ActionManageMachines: store.RoleAdmin,
}

// can reports whether a user may do an action. Anything not listed is refused,
// and so is a disabled user or a role nobody has heard of: a missing key in a
// Go map gives 0, which never reaches the lowest rank.
func can(u store.User, a Action) bool {
	need, ok := minRole[a]
	if !ok || u.Disabled {
		return false
	}
	have := roleRank[u.Role]
	return have > 0 && have >= roleRank[need]
}
