package tf

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Plan is a saved plan, read from `terraform show -json <planfile>`. Only the
// fields the page shows are read; the format is documented by HashiCorp as
// "JSON Output Format" and has been stable since Terraform 0.12.
type Plan struct {
	ID      string    `json:"id"` // random, so Apply can say which plan it means
	Mode    string    `json:"mode"`
	Created time.Time `json:"created"`
	Summary Summary   `json:"summary"`
	Changes []Change  `json:"changes"` // what apply will do
	Drift   []Change  `json:"drift"`   // what changed outside Terraform since the last apply
}

type Summary struct {
	Add     int `json:"add"`
	Change  int `json:"change"`
	Replace int `json:"replace"`
	Destroy int `json:"destroy"`
	Read    int `json:"read"`
}

// Change is one resource in the plan.
type Change struct {
	Address    string       `json:"address"`
	Action     string       `json:"action"` // create, update, replace, destroy, read
	Reason     string       `json:"reason,omitempty"`
	Attributes []AttrChange `json:"attributes"`
}

// AttrChange is one attribute that differs. Before and After are JSON text
// ("\"dhcp\"", "1024", "true"), "" when the attribute is not there, or the
// words "(sensitive)" / "(known after apply)".
type AttrChange struct {
	Path      string `json:"path"`
	Before    string `json:"before"`
	After     string `json:"after"`
	Sensitive bool   `json:"sensitive,omitempty"`
	Unknown   bool   `json:"unknown,omitempty"`
}

type resourceChange struct {
	Address      string `json:"address"`
	ActionReason string `json:"action_reason"`
	Change       struct {
		Actions         []string `json:"actions"`
		Before          any      `json:"before"`
		After           any      `json:"after"`
		AfterUnknown    any      `json:"after_unknown"`
		BeforeSensitive any      `json:"before_sensitive"`
		AfterSensitive  any      `json:"after_sensitive"`
	} `json:"change"`
}

// ParsePlan reads the JSON of `terraform show -json`. The ID, mode and time
// are set by the caller.
func ParsePlan(data []byte) (*Plan, error) {
	var doc struct {
		ResourceChanges []resourceChange `json:"resource_changes"`
		ResourceDrift   []resourceChange `json:"resource_drift"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("cannot read the plan's JSON: %w", err)
	}

	p := &Plan{Changes: []Change{}, Drift: []Change{}}
	for _, rc := range doc.ResourceChanges {
		action := actionOf(rc.Change.Actions)
		if action == "" {
			continue // no-op: the resource stays as it is
		}
		p.Changes = append(p.Changes, toChange(rc, action))
		switch action {
		case "create":
			p.Summary.Add++
		case "update":
			p.Summary.Change++
		case "replace":
			p.Summary.Replace++
		case "destroy":
			p.Summary.Destroy++
		case "read":
			p.Summary.Read++
		}
	}
	for _, rc := range doc.ResourceDrift {
		if action := actionOf(rc.Change.Actions); action != "" {
			p.Drift = append(p.Drift, toChange(rc, action))
		}
	}
	return p, nil
}

// actionOf names Terraform's list of actions. A replacement is a delete and a
// create, in either order (create first when create_before_destroy is set).
func actionOf(actions []string) string {
	switch strings.Join(actions, ",") {
	case "create":
		return "create"
	case "update":
		return "update"
	case "delete":
		return "destroy"
	case "delete,create", "create,delete":
		return "replace"
	case "read":
		return "read"
	}
	return "" // "no-op", or nothing
}

func toChange(rc resourceChange, action string) Change {
	c := rc.Change
	return Change{
		Address:    rc.Address,
		Action:     action,
		Reason:     reasonText(rc.ActionReason),
		Attributes: attributes(c.Before, c.After, c.AfterUnknown, c.BeforeSensitive, c.AfterSensitive),
	}
}

// reasonText turns Terraform's reason codes into words, for the ones that
// explain a replacement or a destroy.
func reasonText(code string) string {
	switch code {
	case "replace_because_cannot_update":
		return "an attribute that cannot be changed in place was changed"
	case "replace_because_tainted":
		return "the resource is tainted"
	case "replace_by_request":
		return "replacement was asked for (-replace)"
	case "delete_because_no_resource_config":
		return "it is no longer in the configuration"
	case "delete_because_count_index", "delete_because_each_key":
		return "count or for_each no longer includes it"
	}
	return code
}

// attributes compares the two sides attribute by attribute and returns the ones
// that differ, sorted by path. Values marked sensitive are never put in the
// result, only the word "(sensitive)".
func attributes(before, after, unknown, beforeSensitive, afterSensitive any) []AttrChange {
	b := map[string]string{}
	flatten("", before, b)
	a := map[string]string{}
	flatten("", after, a)
	u := map[string]bool{}
	flattenMask("", unknown, u)
	bs := map[string]bool{}
	flattenMask("", beforeSensitive, bs)
	as := map[string]bool{}
	flattenMask("", afterSensitive, as)

	paths := map[string]bool{}
	for k := range b {
		paths[k] = true
	}
	for k := range a {
		paths[k] = true
	}
	for k := range u {
		paths[k] = true
	}
	sorted := make([]string, 0, len(paths))
	for k := range paths {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	out := []AttrChange{}
	for _, path := range sorted {
		bv, inBefore := b[path]
		av, inAfter := a[path]
		unk := masked(u, path)
		if !unk && inBefore == inAfter && bv == av {
			continue
		}
		ac := AttrChange{Path: path}
		if inBefore {
			ac.Before = bv
			if masked(bs, path) {
				ac.Before, ac.Sensitive = "(sensitive)", true
			}
		}
		switch {
		case unk:
			ac.After, ac.Unknown = "(known after apply)", true
		case inAfter:
			ac.After = av
			if masked(as, path) {
				ac.After, ac.Sensitive = "(sensitive)", true
			}
		}
		out = append(out, ac)
	}
	return out
}

func join(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// flatten turns nested JSON into path → JSON text: {"a":{"b":[1]}} becomes
// "a.b[0]" → "1". Null and empty values are left out, so a create does not list
// every optional attribute that is not set.
func flatten(prefix string, v any, out map[string]string) {
	switch t := v.(type) {
	case nil:
	case map[string]any:
		for k, x := range t {
			flatten(join(prefix, k), x, out)
		}
	case []any:
		for i, x := range t {
			flatten(fmt.Sprintf("%s[%d]", prefix, i), x, out)
		}
	default:
		text, _ := json.Marshal(t)
		out[prefix] = string(text)
	}
}

// flattenMask reads the shape Terraform uses for "sensitive" and "unknown":
// the same nesting as the value, with true where it applies. A true at some
// level covers everything below it.
func flattenMask(prefix string, v any, out map[string]bool) {
	switch t := v.(type) {
	case bool:
		if t {
			out[prefix] = true
		}
	case map[string]any:
		for k, x := range t {
			flattenMask(join(prefix, k), x, out)
		}
	case []any:
		for i, x := range t {
			flattenMask(fmt.Sprintf("%s[%d]", prefix, i), x, out)
		}
	}
}

func masked(mask map[string]bool, path string) bool {
	if mask[path] {
		return true
	}
	for p := range mask {
		if p == "" || strings.HasPrefix(path, p+".") || strings.HasPrefix(path, p+"[") {
			return true
		}
	}
	return false
}

// MachineName extracts the machine's key from a for_each resource address like
// proxmox_virtual_environment_container.machine["web-1"].
func MachineName(address string) string {
	if start := strings.Index(address, `["`); start >= 0 {
		rest := address[start+2:]
		if end := strings.LastIndex(rest, `"]`); end >= 0 {
			return rest[:end]
		}
	}
	return address
}

// PlainAction describes a Terraform action in plain words for the review dialog.
func PlainAction(action string) string {
	switch action {
	case "create":
		return "will be created"
	case "update":
		return "will be changed in place"
	case "replace":
		return "will be destroyed and created again"
	case "destroy":
		return "will be destroyed"
	case "read":
		return "will be read"
	default:
		return action
	}
}

// PlainSummary turns a plan's summary counts into a plain sentence such as
// "1 container will be created." or "No changes: everything matches."
func PlainSummary(p *Plan) string {
	if p == nil {
		return "No changes: everything matches."
	}
	s := p.Summary
	var parts []string
	unit := func(n int) string {
		if n == 1 {
			return "1 container"
		}
		return fmt.Sprintf("%d containers", n)
	}
	if s.Add > 0 {
		parts = append(parts, unit(s.Add)+" will be created")
	}
	if s.Change > 0 {
		parts = append(parts, unit(s.Change)+" will be changed in place")
	}
	if s.Replace > 0 {
		parts = append(parts, unit(s.Replace)+" will be destroyed and created again")
	}
	if s.Destroy > 0 {
		parts = append(parts, unit(s.Destroy)+" will be destroyed")
	}
	if len(parts) == 0 {
		return "No changes: everything matches."
	}
	return strings.Join(parts, ", ") + "."
}

// StateMachine is what Terraform's current state knows about one container.
type StateMachine struct {
	Name string
	VMID int
	Node string
	IPv4 string
}

// ParseState reads `terraform show -json` (state) and returns the containers
// from output "machines", keyed by machine name.
func ParseState(data []byte) (map[string]StateMachine, error) {
	out := map[string]StateMachine{}
	if len(strings.TrimSpace(string(data))) == 0 {
		return out, nil
	}
	var doc struct {
		Values *struct {
			Outputs map[string]struct {
				Value map[string]struct {
					VMID     int    `json:"vm_id"`
					NodeName string `json:"node_name"`
					IPv4     string `json:"ipv4"`
				} `json:"value"`
			} `json:"outputs"`
		} `json:"values"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("cannot read terraform state JSON: %w", err)
	}
	if doc.Values == nil {
		return out, nil
	}
	for name, v := range doc.Values.Outputs["machines"].Value {
		ip, _, _ := strings.Cut(v.IPv4, "/")
		out[name] = StateMachine{Name: name, VMID: v.VMID, Node: v.NodeName, IPv4: ip}
	}
	return out, nil
}

// DriftDetail summarizes one drifted container in plain words and pulls out any
// drifted size values (CPU, memory, disk) so Accept can update SQLite.
type DriftDetail struct {
	Machine    string       `json:"machine"`
	Action     string       `json:"action"`
	Sentence   string       `json:"sentence"`
	Attributes []AttrChange `json:"attributes"`
	Cores      int          `json:"cores,omitempty"`
	MemoryMB   int          `json:"memory_mb,omitempty"`
	DiskGB     int          `json:"disk_gb,omitempty"`
}

func driftAttrLabel(path string) string {
	switch path {
	case "memory[0].dedicated":
		return "memory"
	case "cpu[0].cores":
		return "CPU"
	case "disk[0].size":
		return "disk"
	case "disk[0].datastore_id":
		return "storage"
	case "network_interface[0].bridge":
		return "bridge"
	}
	return path
}

// ExplainDrift turns a resource_drift entry into a sentence such as
// "web-1 was changed outside the dashboard (memory 1024 → 2048)".
func ExplainDrift(c Change) DriftDetail {
	name := MachineName(c.Address)
	d := DriftDetail{Machine: name, Action: c.Action, Attributes: c.Attributes}
	if c.Action == "destroy" {
		d.Sentence = name + " was deleted outside the dashboard"
		return d
	}
	var parts []string
	for _, a := range c.Attributes {
		parts = append(parts, fmt.Sprintf("%s %s → %s", driftAttrLabel(a.Path), a.Before, a.After))
		if n, err := strconv.Atoi(a.After); err == nil && n > 0 {
			switch a.Path {
			case "cpu[0].cores":
				d.Cores = n
			case "memory[0].dedicated":
				d.MemoryMB = n
			case "disk[0].size":
				d.DiskGB = n
			}
		}
	}
	if len(parts) == 0 {
		d.Sentence = name + " was changed outside the dashboard"
	} else {
		d.Sentence = fmt.Sprintf("%s was changed outside the dashboard (%s)", name, strings.Join(parts, ", "))
	}
	return d
}
