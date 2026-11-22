package store

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAccessKeysAndGrants(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	h1, _ := CreateHost(db, sampleHost("web-1", "10.0.0.1"), now)
	h2, _ := CreateHost(db, sampleHost("db-1", "10.0.0.2"), now)
	web, _ := CreateGroup(db, "web", now)

	k, err := CreateAccessKey(db, "Dewi", "ssh-ed25519 AAAAkey1", "", now)
	if err != nil || k.ID == 0 {
		t.Fatalf("create: %+v %v", k, err)
	}
	if _, err := CreateAccessKey(db, "Dewi", "ssh-ed25519 AAAAother", "", now); !errors.Is(err, ErrAccessNameTaken) {
		t.Errorf("same name: %v", err)
	}
	if _, err := CreateAccessKey(db, "Budi", "ssh-ed25519 AAAAkey1", "", now); !errors.Is(err, ErrAccessKeyTaken) {
		t.Errorf("same key: %v", err)
	}

	if err := SetAccessGrants(db, k.ID, []int64{web.ID}, []int64{h2.ID}); err != nil {
		t.Fatal(err)
	}
	got, err := GetAccessKey(db, k.ID)
	if err != nil || !reflect.DeepEqual(got.GroupIDs, []int64{web.ID}) || !reflect.DeepEqual(got.HostIDs, []int64{h2.ID}) {
		t.Fatalf("grants: %+v %v", got, err)
	}

	// Setting again replaces; an unknown group or host changes nothing.
	if err := SetAccessGrants(db, k.ID, []int64{web.ID, 999}, nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown group: %v", err)
	}
	if err := SetAccessGrants(db, k.ID, nil, []int64{999}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown host: %v", err)
	}
	if got, _ = GetAccessKey(db, k.ID); len(got.GroupIDs) != 1 || len(got.HostIDs) != 1 {
		t.Errorf("a failed change was half applied: %+v", got)
	}
	if err := SetAccessGrants(db, 999, nil, nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown key: %v", err)
	}
	if err := SetAccessGrants(db, k.ID, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ = GetAccessKey(db, k.ID); len(got.GroupIDs)+len(got.HostIDs) != 0 {
		t.Errorf("grants were not cleared: %+v", got)
	}

	// A deleted group takes its grants with it.
	SetAccessGrants(db, k.ID, []int64{web.ID}, []int64{h1.ID})
	DeleteGroup(db, web.ID)
	if got, _ = GetAccessKey(db, k.ID); len(got.GroupIDs) != 0 || len(got.HostIDs) != 1 {
		t.Errorf("grants after the group was deleted: %+v", got)
	}

	if err := DeleteAccessKey(db, k.ID); err != nil {
		t.Fatal(err)
	}
	if err := DeleteAccessKey(db, k.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete twice: %v", err)
	}
	if keys, _ := ListAccessKeys(db); len(keys) != 0 {
		t.Errorf("keys left: %+v", keys)
	}
}

func TestInstalledKeysSurviveTheKeyRow(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	h, _ := CreateHost(db, sampleHost("web-1", "10.0.0.1"), now)
	k, _ := CreateAccessKey(db, "Dewi", "ssh-ed25519 AAAAkey1", "", now)

	if err := SaveInstalled(db, h.ID, []InstalledKey{{Name: k.Name, PublicKey: k.PublicKey, User: "deploy"}}); err != nil {
		t.Fatal(err)
	}
	// Deleting the key must not forget it is on the host: that is how it gets taken off.
	DeleteAccessKey(db, k.ID)
	all, err := AllInstalled(db)
	if err != nil || len(all[h.ID]) != 1 || all[h.ID][0].PublicKey != "ssh-ed25519 AAAAkey1" {
		t.Fatalf("installed: %+v %v", all, err)
	}
	// Saving the host's new state replaces the old one.
	if err := SaveInstalled(db, h.ID, nil); err != nil {
		t.Fatal(err)
	}
	if all, _ = AllInstalled(db); len(all[h.ID]) != 0 {
		t.Errorf("not cleared: %+v", all)
	}
	// A host that is deleted takes its records.
	SaveInstalled(db, h.ID, []InstalledKey{{Name: "x", PublicKey: "ssh-ed25519 AAAAx", User: "u"}})
	DeleteHost(db, h.ID)
	if all, _ = AllInstalled(db); len(all) != 0 {
		t.Errorf("records of a deleted host: %+v", all)
	}
}

func TestSecretsHaveNoReadBack(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	if err := SetSecret(db, "db_pass", "$ANSIBLE_VAULT;1.1;AES256\nabc", now); err != nil {
		t.Fatal(err)
	}
	before, _ := SecretVersions(db)
	if err := SetSecret(db, "db_pass", "$ANSIBLE_VAULT;1.1;AES256\ndef", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	after, _ := SecretVersions(db)
	if before["db_pass"] == "" || before["db_pass"] == after["db_pass"] {
		t.Errorf("a rotated secret must get a new version: %v → %v", before, after)
	}
	list, err := ListSecrets(db)
	if err != nil || len(list) != 1 || list[0].Name != "db_pass" {
		t.Fatalf("list: %+v %v", list, err)
	}
	if ok, _ := SecretExists(db, "db_pass"); !ok {
		t.Error("exists")
	}
	if ok, _ := SecretExists(db, "nope"); ok {
		t.Error("exists for an unknown name")
	}
	ciphers, _ := SecretCiphertexts(db)
	if !strings.Contains(ciphers["db_pass"], "def") {
		t.Errorf("ciphertext: %v", ciphers)
	}
	if err := DeleteSecret(db, "db_pass"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteSecret(db, "db_pass"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete twice: %v", err)
	}
}

func TestPlaybooks(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	if err := SavePlaybook(db, "tune", "- hosts: all\n", now); err != nil {
		t.Fatal(err)
	}
	if err := SavePlaybook(db, "tune", "- hosts: web\n", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	p, err := GetPlaybook(db, "tune")
	if err != nil || p.Content != "- hosts: web\n" || p.UpdatedAt != now.Add(time.Minute).Unix() {
		t.Fatalf("get: %+v %v", p, err)
	}
	if _, err := GetPlaybook(db, "none"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}
	list, _ := ListPlaybooks(db)
	if len(list) != 1 || list[0].Content != "" {
		t.Errorf("the list holds names only: %+v", list)
	}
	all, _ := AllPlaybooks(db)
	if all["tune"] != "- hosts: web\n" {
		t.Errorf("all: %v", all)
	}
	if err := DeletePlaybook(db, "tune"); err != nil {
		t.Fatal(err)
	}
	if err := DeletePlaybook(db, "tune"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete twice: %v", err)
	}
}
