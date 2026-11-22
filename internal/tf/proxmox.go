package tf

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Proxmox VE API client, validation, and 0600 secret storage (IM7). Everything
// uses stdlib net/http. The API token secret lives only in
// <data>/secrets/proxmox.tfvars.json and is scrubbed from errors.

type CheckError string

func (e CheckError) Error() string { return string(e) }

var (
	tokenIDRe     = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+![A-Za-z0-9._-]+$`)
	machineNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	pveIdentRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	templateRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}:vztmpl/[A-Za-z0-9._+-]{1,200}$`)
)

func CheckEndpoint(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.ContainsAny(s, " \t\r\n\x00'\"") {
		return "", CheckError("Enter a Proxmox endpoint such as https://192.168.1.10:8006.")
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", CheckError("The Proxmox endpoint must be an https:// address with no credentials or query, such as https://192.168.1.10:8006.")
	}
	u.Path = strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api2/json")
	return u.String(), nil
}

func CheckTokenID(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if !tokenIDRe.MatchString(s) {
		return "", CheckError("The API token ID must look like user@realm!tokenname (for example terraform@pve!infra).")
	}
	return s, nil
}

func CheckTokenSecret(secret string) error {
	if secret == "" || len(secret) > 500 || strings.ContainsAny(secret, " \t\r\n\x00") {
		return CheckError("The API token secret must be one line with no spaces.")
	}
	return nil
}

func CheckMachineName(name string) error {
	if !machineNameRe.MatchString(name) {
		return CheckError("A machine name is 1 to 63 characters: lowercase letters, digits and hyphens, starting and ending with a letter or digit.")
	}
	return nil
}

func CheckIdent(value, what string) error {
	if !pveIdentRe.MatchString(value) {
		return CheckError("Pick a valid " + what + ".")
	}
	return nil
}

func CheckTemplateID(tmpl string) error {
	if !templateRe.MatchString(tmpl) || strings.Contains(tmpl, "..") {
		return CheckError("Pick a valid container template (such as local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst).")
	}
	return nil
}

func CheckMachineSize(cores, memoryMB, diskGB int) error {
	switch {
	case cores < 1 || cores > 64:
		return CheckError("CPU cores must be between 1 and 64.")
	case memoryMB < 128 || memoryMB > 262144:
		return CheckError("Memory must be between 128 MB and 262144 MB.")
	case diskGB < 2 || diskGB > 4096:
		return CheckError("Disk size must be between 2 GB and 4096 GB.")
	}
	return nil
}

func CheckIPConfig(mode, cidr, gateway string) (cleanCIDR, cleanIP, cleanGW string, err error) {
	if mode == "dhcp" {
		return "", "", "", nil
	}
	if mode != "static" {
		return "", "", "", CheckError("Choose either static IP or DHCP.")
	}
	ip, ipNet, perr := net.ParseCIDR(strings.TrimSpace(cidr))
	if perr != nil || ip.To4() == nil {
		return "", "", "", CheckError("Enter a static IPv4 address with its prefix, such as 192.168.1.50/24.")
	}
	ones, _ := ipNet.Mask.Size()
	cleanIP = ip.To4().String()
	cleanCIDR = fmt.Sprintf("%s/%d", cleanIP, ones)
	if gw := strings.TrimSpace(gateway); gw != "" {
		parsed := net.ParseIP(gw)
		if parsed == nil || parsed.To4() == nil {
			return "", "", "", CheckError("The gateway must be an IPv4 address such as 192.168.1.1, or left empty.")
		}
		cleanGW = parsed.To4().String()
	}
	return cleanCIDR, cleanIP, cleanGW, nil
}

// ---------------------------------------------------------------- secret file

// SecretPath is where the Proxmox token secret lives (mode 0600), outside
// terraform/ so View code never sees it.
func SecretPath(dataDir string) string {
	return filepath.Join(dataDir, "secrets", "proxmox.tfvars.json")
}

// writePrivate writes data atomically with mode 0600 inside a 0700 folder,
// skipping unchanged files. Shared by SaveTokenSecret and Write.
func writePrivate(path string, data []byte) error {
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, data) {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func SaveTokenSecret(path, secret string) error {
	if err := CheckTokenSecret(secret); err != nil {
		return err
	}
	data, err := json.MarshalIndent(map[string]string{"proxmox_token_secret": secret}, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(path, append(data, '\n'))
}

func LoadTokenSecret(path string) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read proxmox secret: %w", err)
	}
	var sf struct {
		Secret string `json:"proxmox_token_secret"`
	}
	if err := json.Unmarshal(data, &sf); err != nil {
		return "", fmt.Errorf("parse proxmox secret: %w", err)
	}
	return sf.Secret, nil
}

func HasTokenSecret(path string) bool {
	s, err := LoadTokenSecret(path)
	return err == nil && s != ""
}

// ------------------------------------------------------------ Proxmox client

type ProxmoxConfig struct {
	Endpoint    string
	TokenID     string
	TokenSecret string
	Insecure    bool
}

type ProxmoxClient struct {
	endpoint string
	tokenID  string
	secret   string
	http     *http.Client
	TaskPoll time.Duration
}

func NewProxmoxClient(cfg ProxmoxConfig) *ProxmoxClient {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &ProxmoxClient{
		endpoint: strings.TrimRight(cfg.Endpoint, "/"),
		tokenID:  cfg.TokenID,
		secret:   cfg.TokenSecret,
		http:     &http.Client{Timeout: 20 * time.Second, Transport: tr},
		TaskPoll: 500 * time.Millisecond,
	}
}

func (c *ProxmoxClient) scrub(msg string) string {
	if c.secret != "" {
		return strings.ReplaceAll(msg, c.secret, "…")
	}
	return msg
}

func (c *ProxmoxClient) doJSON(ctx context.Context, method, apiPath string, form url.Values, out any) error {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+"/api2/json"+apiPath, body)
	if err != nil {
		return fmt.Errorf("build Proxmox request: %s", c.scrub(err.Error()))
	}
	req.Header.Set("Authorization", "PVEAPIToken="+c.tokenID+"="+c.secret)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New(explainProxmoxNetErr(c.scrub(err.Error())))
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("read Proxmox response: %s", c.scrub(err.Error()))
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("Proxmox refused the API token (HTTP %d). Check the token ID, secret, and permissions.", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		text := strings.TrimSpace(c.scrub(string(raw)))
		if len(text) > 300 {
			text = text[:300]
		}
		return fmt.Errorf("Proxmox answered HTTP %d: %s", resp.StatusCode, text)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("Proxmox did not return JSON: %s", c.scrub(err.Error()))
	}
	return json.Unmarshal(env.Data, out)
}

func explainProxmoxNetErr(raw string) string {
	low := strings.ToLower(raw)
	switch {
	case strings.Contains(low, "x509:"), strings.Contains(low, "certificate"), strings.Contains(low, "tls:"):
		return "The Proxmox server's TLS certificate is not trusted. If it uses a self-signed certificate, tick \"Allow self-signed TLS certificate\"."
	case strings.Contains(low, "connection refused"):
		return "Could not connect to the Proxmox API (connection refused). Check the endpoint address and port (usually 8006)."
	case strings.Contains(low, "no such host"):
		return "Could not resolve the Proxmox host name. Check the endpoint address."
	case strings.Contains(low, "deadline exceeded"), strings.Contains(low, "timeout"):
		return "Proxmox did not answer in time. Check that the VPS can reach port 8006."
	}
	return "Could not reach Proxmox: " + raw
}

// Discovery is cached from Test connection so Create machine can offer dropdowns.
type Discovery struct {
	Version   string            `json:"version"`
	Nodes     []ProxmoxNode     `json:"nodes"`
	Storages  []ProxmoxStorage  `json:"storages"`
	Bridges   []ProxmoxBridge   `json:"bridges"`
	Templates []ProxmoxTemplate `json:"templates"`
	CheckedAt int64             `json:"checked_at"`
}

type ProxmoxNode struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type ProxmoxStorage struct {
	Node string `json:"node"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type ProxmoxBridge struct {
	Node string `json:"node"`
	Name string `json:"name"`
	CIDR string `json:"cidr,omitempty"`
}

type ProxmoxTemplate struct {
	Node  string `json:"node"`
	VolID string `json:"volid"`
}

func (c *ProxmoxClient) Discover(ctx context.Context) (Discovery, error) {
	var ver struct {
		Version string `json:"version"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/version", nil, &ver); err != nil {
		return Discovery{}, err
	}
	var rawNodes []struct {
		Node   string `json:"node"`
		Status string `json:"status"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/nodes", nil, &rawNodes); err != nil {
		return Discovery{}, err
	}

	d := Discovery{
		Version: ver.Version, Nodes: []ProxmoxNode{}, Storages: []ProxmoxStorage{},
		Bridges: []ProxmoxBridge{}, Templates: []ProxmoxTemplate{}, CheckedAt: time.Now().Unix(),
	}
	sort.Slice(rawNodes, func(i, j int) bool { return rawNodes[i].Node < rawNodes[j].Node })
	for _, rn := range rawNodes {
		if rn.Node == "" {
			continue
		}
		d.Nodes = append(d.Nodes, ProxmoxNode{Name: rn.Node, Status: rn.Status})
		if rn.Status != "" && rn.Status != "online" {
			continue
		}
		nodeEsc := url.PathEscape(rn.Node)

		var rawStorages []struct {
			Storage string `json:"storage"`
			Type    string `json:"type"`
			Content string `json:"content"`
			Active  *int   `json:"active"`
			Enabled *int   `json:"enabled"`
		}
		if c.doJSON(ctx, http.MethodGet, "/nodes/"+nodeEsc+"/storage", nil, &rawStorages) == nil {
			sort.Slice(rawStorages, func(i, j int) bool { return rawStorages[i].Storage < rawStorages[j].Storage })
			for _, st := range rawStorages {
				if (st.Active != nil && *st.Active == 0) || (st.Enabled != nil && *st.Enabled == 0) {
					continue
				}
				if hasContent(st.Content, "rootdir") {
					d.Storages = append(d.Storages, ProxmoxStorage{Node: rn.Node, Name: st.Storage, Type: st.Type})
				}
				if hasContent(st.Content, "vztmpl") {
					var items []struct {
						VolID string `json:"volid"`
					}
					if c.doJSON(ctx, http.MethodGet, "/nodes/"+nodeEsc+"/storage/"+url.PathEscape(st.Storage)+"/content?content=vztmpl", nil, &items) == nil {
						for _, item := range items {
							if item.VolID != "" {
								d.Templates = append(d.Templates, ProxmoxTemplate{Node: rn.Node, VolID: item.VolID})
							}
						}
					}
				}
			}
		}

		var rawNet []struct {
			Iface string `json:"iface"`
			Type  string `json:"type"`
			CIDR  string `json:"cidr"`
		}
		if c.doJSON(ctx, http.MethodGet, "/nodes/"+nodeEsc+"/network?type=bridge", nil, &rawNet) == nil {
			sort.Slice(rawNet, func(i, j int) bool { return rawNet[i].Iface < rawNet[j].Iface })
			for _, iface := range rawNet {
				if iface.Type == "bridge" && iface.Iface != "" {
					d.Bridges = append(d.Bridges, ProxmoxBridge{Node: rn.Node, Name: iface.Iface, CIDR: iface.CIDR})
				}
			}
		}
	}
	sort.Slice(d.Templates, func(i, j int) bool { return d.Templates[i].Node+d.Templates[i].VolID < d.Templates[j].Node+d.Templates[j].VolID })
	return d, nil
}

func hasContent(csv, want string) bool {
	for _, p := range strings.Split(csv, ",") {
		if strings.TrimSpace(p) == want {
			return true
		}
	}
	return false
}

type ContainerStatus struct {
	VMID   int
	Name   string
	Status string // "running" or "stopped"
}

func (c *ProxmoxClient) ListContainers(ctx context.Context, node string) ([]ContainerStatus, error) {
	var raw []struct {
		VMID   any    `json:"vmid"` // Proxmox returns int or string depending on version
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/nodes/"+url.PathEscape(node)+"/lxc", nil, &raw); err != nil {
		return nil, err
	}
	out := make([]ContainerStatus, len(raw))
	for i, r := range raw {
		vmid := 0
		switch v := r.VMID.(type) {
		case float64:
			vmid = int(v)
		case string:
			vmid, _ = strconv.Atoi(v)
		}
		out[i] = ContainerStatus{VMID: vmid, Name: r.Name, Status: r.Status}
	}
	return out, nil
}

func (c *ProxmoxClient) ContainerInterfaces(ctx context.Context, node string, vmid int) ([]string, error) {
	var raw []struct {
		Name string `json:"name"`
		Inet string `json:"inet"`
	}
	if err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/nodes/%s/lxc/%d/interfaces", url.PathEscape(node), vmid), nil, &raw); err != nil {
		return nil, err
	}
	var ips []string
	for _, iface := range raw {
		if iface.Name == "lo" || iface.Inet == "" {
			continue
		}
		addr, _, _ := strings.Cut(iface.Inet, "/")
		if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			ips = append(ips, ip.To4().String())
		}
	}
	return ips, nil
}

func (c *ProxmoxClient) StartContainer(ctx context.Context, node string, vmid int) error {
	var upid string
	if err := c.doJSON(ctx, http.MethodPost, fmt.Sprintf("/nodes/%s/lxc/%d/status/start", url.PathEscape(node), vmid), nil, &upid); err != nil {
		return err
	}
	return c.waitTask(ctx, node, upid)
}

func (c *ProxmoxClient) StopContainer(ctx context.Context, node string, vmid int) error {
	var upid string
	form := url.Values{"forceStop": {"1"}, "timeout": {"30"}}
	if err := c.doJSON(ctx, http.MethodPost, fmt.Sprintf("/nodes/%s/lxc/%d/status/shutdown", url.PathEscape(node), vmid), form, &upid); err != nil {
		return err
	}
	return c.waitTask(ctx, node, upid)
}

func (c *ProxmoxClient) waitTask(ctx context.Context, node, upid string) error {
	if upid == "" {
		return nil
	}
	poll := c.TaskPoll
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	path := fmt.Sprintf("/nodes/%s/tasks/%s/status", url.PathEscape(node), url.PathEscape(upid))
	for {
		var st struct {
			Status     string `json:"status"`
			ExitStatus string `json:"exitstatus"`
		}
		if err := c.doJSON(ctx, http.MethodGet, path, nil, &st); err != nil {
			return err
		}
		if st.Status == "stopped" {
			if st.ExitStatus != "" && st.ExitStatus != "OK" {
				return fmt.Errorf("Proxmox task failed: %s", st.ExitStatus)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("Proxmox task did not finish in time")
		case <-time.After(poll):
		}
	}
}
