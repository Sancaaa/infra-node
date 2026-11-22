package web

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"infra-manager/internal/store"
	"infra-manager/internal/tf"
)

// Proxmox settings and discovery (IM7). Endpoint, token ID, TLS flag and cached
// discovery live in settings. The token secret lives only in
// <data>/secrets/proxmox.tfvars.json (0600) and is never returned.

const (
	settingProxmoxEndpoint  = "proxmox.endpoint"
	settingProxmoxTokenID   = "proxmox.token_id"
	settingProxmoxInsecure  = "proxmox.insecure"
	settingProxmoxDiscovery = "proxmox.discovery"
)

type proxmoxSettings struct {
	Endpoint   string        `json:"endpoint"`
	TokenID    string        `json:"token_id"`
	Insecure   bool          `json:"insecure"`
	HasSecret  bool          `json:"has_secret"`
	Configured bool          `json:"configured"`
	Discovery  *tf.Discovery `json:"discovery,omitempty"`
}

func (s *Server) loadProxmoxSettings() (proxmoxSettings, error) {
	all, err := store.GetSettings(s.db, "proxmox.")
	if err != nil {
		return proxmoxSettings{}, err
	}
	st := proxmoxSettings{
		Endpoint:  all[settingProxmoxEndpoint],
		TokenID:   all[settingProxmoxTokenID],
		Insecure:  all[settingProxmoxInsecure] == "true",
		HasSecret: tf.HasTokenSecret(s.tf.SecretFile),
	}
	st.Configured = st.Endpoint != "" && st.TokenID != "" && st.HasSecret
	if raw := all[settingProxmoxDiscovery]; raw != "" {
		var d tf.Discovery
		if json.Unmarshal([]byte(raw), &d) == nil {
			st.Discovery = &d
		}
	}
	return st, nil
}

func (s *Server) proxmoxClient() (*tf.ProxmoxClient, proxmoxSettings, error) {
	st, err := s.loadProxmoxSettings()
	if err != nil || !st.Configured {
		return nil, st, err
	}
	secret, err := tf.LoadTokenSecret(s.tf.SecretFile)
	if err != nil || secret == "" {
		st.HasSecret, st.Configured = false, false
		return nil, st, err
	}
	return tf.NewProxmoxClient(tf.ProxmoxConfig{
		Endpoint: st.Endpoint, TokenID: st.TokenID, TokenSecret: secret, Insecure: st.Insecure,
	}), st, nil
}

func (s *Server) terraformVersion() string {
	if _, err := exec.LookPath(s.tf.Bin); err != nil {
		return ""
	}
	s.tfVersion.mu.Lock()
	defer s.tfVersion.mu.Unlock()
	if s.tfVersion.version == "" || time.Since(s.tfVersion.at) > 5*time.Minute {
		s.tfVersion.version, s.tfVersion.at = s.tf.Version(), time.Now()
	}
	return s.tfVersion.version
}

func (s *Server) terraformStatusMap() map[string]any {
	version := s.terraformVersion()
	return map[string]any{"installed": version != "", "version": version, "hint": tf.InstallHint}
}

func (s *Server) getProxmox(w http.ResponseWriter, r *http.Request, me store.User) {
	st, err := s.loadProxmoxSettings()
	if err != nil {
		serverError(w, "read Proxmox settings", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"endpoint": st.Endpoint, "token_id": st.TokenID, "insecure": st.Insecure,
		"has_secret": st.HasSecret, "configured": st.Configured,
		"discovery": st.Discovery, "terraform": s.terraformStatusMap(),
	})
}

func (s *Server) saveProxmox(w http.ResponseWriter, r *http.Request, me store.User) {
	var req struct {
		Endpoint    string `json:"endpoint"`
		TokenID     string `json:"token_id"`
		TokenSecret string `json:"token_secret"`
		Insecure    bool   `json:"insecure"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	prev, err := s.loadProxmoxSettings()
	if err != nil {
		serverError(w, "read Proxmox settings", err)
		return
	}
	endpoint, err := tf.CheckEndpoint(req.Endpoint)
	if err != nil {
		s.failHost(w, r, me, "proxmox.settings", "proxmox", http.StatusBadRequest, err.Error())
		return
	}
	tokenID, err := tf.CheckTokenID(req.TokenID)
	if err != nil {
		s.failHost(w, r, me, "proxmox.settings", "proxmox", http.StatusBadRequest, err.Error())
		return
	}
	prevEndpoint, _ := tf.CheckEndpoint(prev.Endpoint)
	secret := strings.TrimSpace(req.TokenSecret)
	if secret != "" {
		if err := tf.CheckTokenSecret(secret); err != nil {
			s.failHost(w, r, me, "proxmox.settings", "proxmox", http.StatusBadRequest, err.Error())
			return
		}
		if err := tf.SaveTokenSecret(s.tf.SecretFile, secret); err != nil {
			serverError(w, "save Proxmox token secret", err)
			return
		}
	} else if !prev.HasSecret {
		s.failHost(w, r, me, "proxmox.settings", "proxmox", http.StatusBadRequest, "Enter the API token secret.")
		return
	} else if prevEndpoint == "" || endpoint != prevEndpoint {
		s.failHost(w, r, me, "proxmox.settings", "proxmox", http.StatusBadRequest, "Changing the Proxmox endpoint requires re-entering the API token secret.")
		return
	}

	insecureVal := "false"
	if req.Insecure {
		insecureVal = "true"
	}
	for k, v := range map[string]string{settingProxmoxEndpoint: endpoint, settingProxmoxTokenID: tokenID, settingProxmoxInsecure: insecureVal} {
		if err := store.SetSetting(s.db, k, v); err != nil {
			serverError(w, "save Proxmox settings", err)
			return
		}
	}
	if prev.Endpoint != "" && prev.Endpoint != endpoint {
		_ = store.SetSetting(s.db, settingProxmoxDiscovery, "")
	}
	s.clearPendingPlan()

	detail := endpoint + " (" + tokenID + ")"
	if secret != "" {
		detail += "; token secret updated"
	}
	s.record(r, me, "proxmox.settings", "proxmox", store.ResultOK, detail)
	s.getProxmox(w, r, me)
}

func (s *Server) testProxmox(w http.ResponseWriter, r *http.Request, me store.User) {
	var req struct {
		Endpoint    string `json:"endpoint"`
		TokenID     string `json:"token_id"`
		TokenSecret string `json:"token_secret"`
		Insecure    *bool  `json:"insecure"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	saved, err := s.loadProxmoxSettings()
	if err != nil {
		serverError(w, "read Proxmox settings", err)
		return
	}
	endpoint, err := tf.CheckEndpoint(firstNonEmpty(strings.TrimSpace(req.Endpoint), saved.Endpoint))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	tokenID, err := tf.CheckTokenID(firstNonEmpty(strings.TrimSpace(req.TokenID), saved.TokenID))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	savedEndpoint, _ := tf.CheckEndpoint(saved.Endpoint)
	secret := strings.TrimSpace(req.TokenSecret)
	if secret == "" {
		if savedEndpoint == "" {
			writeError(w, http.StatusBadRequest, "Save or enter the Proxmox API token secret first.")
			return
		}
		if endpoint != savedEndpoint {
			writeError(w, http.StatusBadRequest, "Changing the Proxmox endpoint requires re-entering the API token secret.")
			return
		}
		secret, err = tf.LoadTokenSecret(s.tf.SecretFile)
		if err != nil {
			serverError(w, "read Proxmox token secret", err)
			return
		}
	}
	if tf.CheckTokenSecret(secret) != nil {
		writeError(w, http.StatusBadRequest, "Save or enter the Proxmox API token secret first.")
		return
	}
	insecure := saved.Insecure
	if req.Insecure != nil {
		insecure = *req.Insecure
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	disc, err := tf.NewProxmoxClient(tf.ProxmoxConfig{
		Endpoint: endpoint, TokenID: tokenID, TokenSecret: secret, Insecure: insecure,
	}).Discover(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if savedEndpoint == "" || savedEndpoint == endpoint {
		if raw, err := json.Marshal(disc); err == nil {
			_ = store.SetSetting(s.db, settingProxmoxDiscovery, string(raw))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "discovery": disc})
}

func scrubSecret(text, secret string) string {
	if secret != "" {
		return strings.ReplaceAll(text, secret, "…")
	}
	return text
}

func scrubSecrets(text string, secrets []string) string {
	for _, secret := range secrets {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, "…")
		}
	}
	return text
}

// streamSecrets returns control-plane secrets (Proxmox API token secret and
// Ansible vault password) that must be scrubbed from live streams, error
// responses, and History.
func (s *Server) streamSecrets() []string {
	var out []string
	if secret, err := tf.LoadTokenSecret(s.tf.SecretFile); err == nil && secret != "" {
		out = append(out, secret)
	}
	if raw, err := os.ReadFile(s.vaultPasswordPath()); err == nil {
		if pw := strings.TrimSpace(string(raw)); pw != "" {
			out = append(out, pw)
		}
	}
	return out
}
