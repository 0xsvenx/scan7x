package main

import (
	"os"
	"reflect"
	"testing"
	"time"
)

func TestStoreProjectAndDiff(t *testing.T) {
	os.Setenv("SCAN7X_HOME", t.TempDir())
	defer os.Unsetenv("SCAN7X_HOME")

	store, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	prog := Program{
		Platform: "hackerone", Name: "Demo", Handle: "demo", URL: "https://h1/demo",
		InScope: []ScopeAsset{{Identifier: "*.demo.com", Category: CatWildcard, Host: "demo.com", Wildcard: true}},
	}
	id, err := store.CreateProject("demo", prog, "all", "full")
	if err != nil {
		t.Fatal(err)
	}

	// First run: everything is new.
	res1 := &ReconResult{
		Mode: "full", Started: time.Now(), Finished: time.Now(),
		Subdomains: []string{"a.demo.com", "b.demo.com"},
		LiveHosts:  []LiveHost{{URL: "https://a.demo.com", Status: 200}},
		Endpoints:  []string{"/api/x"},
		Secrets:    []Secret{{Type: "jwt", Match: "eyJexample"}},
	}
	d1, err := store.SaveResult(id, res1)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d1.NewSubdomains, []string{"a.demo.com", "b.demo.com"}) {
		t.Errorf("first NewSubdomains = %v", d1.NewSubdomains)
	}
	if d1.NewSecrets != 1 || d1.NewEndpoints != 1 || len(d1.NewLive) != 1 {
		t.Errorf("first diff counts wrong: %+v", d1)
	}

	// Second run: only c.demo.com is new; endpoint/secret already seen.
	res2 := &ReconResult{
		Mode: "full", Started: time.Now(), Finished: time.Now(),
		Subdomains: []string{"a.demo.com", "b.demo.com", "c.demo.com"},
		Endpoints:  []string{"/api/x"},
		Secrets:    []Secret{{Type: "jwt", Match: "eyJexample"}},
	}
	d2, err := store.SaveResult(id, res2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(d2.NewSubdomains, []string{"c.demo.com"}) {
		t.Errorf("second NewSubdomains = %v, want [c.demo.com]", d2.NewSubdomains)
	}
	if d2.NewSecrets != 0 || d2.NewEndpoints != 0 {
		t.Errorf("second diff should be empty for endpoints/secrets: %+v", d2)
	}

	// A newly-added scope asset is detected.
	prog.InScope = append(prog.InScope, ScopeAsset{Identifier: "api.demo.com", Category: CatDomain, Host: "api.demo.com"})
	added, err := store.syncAssets(id, prog)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(added, []string{"api.demo.com"}) {
		t.Errorf("syncAssets added = %v, want [api.demo.com]", added)
	}

	// list + load round-trip.
	list, err := store.ListProjects()
	if err != nil || len(list) != 1 || list[0].Subdomains != 3 {
		t.Fatalf("list wrong: %+v (err %v)", list, err)
	}
	p, err := store.GetProject("demo")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadResult(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Subdomains) != 3 || len(loaded.Endpoints) != 1 || len(loaded.Secrets) != 1 {
		t.Errorf("LoadResult wrong: subs=%d eps=%d secrets=%d", len(loaded.Subdomains), len(loaded.Endpoints), len(loaded.Secrets))
	}
}
