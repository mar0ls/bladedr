package store

import (
	"context"
	"testing"
)

func TestCollectionStaticAndDynamic(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	prod1 := &Host{Hostname: "prod1", Tags: map[string]string{"env": "prod"}}
	prod2 := &Host{Hostname: "prod2", Tags: map[string]string{"env": "prod"}}
	dev1 := &Host{Hostname: "dev1", Tags: map[string]string{"env": "dev"}}
	for _, h := range []*Host{prod1, prod2, dev1} {
		if err := m.CreateHost(ctx, h); err != nil {
			t.Fatal(err)
		}
	}

	// Static collection: explicit members.
	static := &Collection{Name: "critical"}
	if err := m.CreateCollection(ctx, static); err != nil {
		t.Fatal(err)
	}
	_ = m.AddCollectionMember(ctx, static.ID, prod1.ID)
	_ = m.AddCollectionMember(ctx, static.ID, dev1.ID)
	hosts, err := m.CollectionHosts(ctx, static.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Fatalf("static collection should resolve 2 members, got %d", len(hosts))
	}
	// Removing a member updates resolution.
	_ = m.RemoveCollectionMember(ctx, static.ID, dev1.ID)
	if hosts, _ = m.CollectionHosts(ctx, static.ID); len(hosts) != 1 || hosts[0].ID != prod1.ID {
		t.Fatalf("after removal static should resolve only prod1, got %v", hosts)
	}

	// Dynamic collection: tag rule env=prod matches prod1 and prod2, not dev1.
	dyn := &Collection{Name: "all-prod", Dynamic: true, MatchTags: map[string]string{"env": "prod"}}
	if err := m.CreateCollection(ctx, dyn); err != nil {
		t.Fatal(err)
	}
	hosts, err = m.CollectionHosts(ctx, dyn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Fatalf("dynamic env=prod should match 2 hosts, got %d", len(hosts))
	}
	for _, h := range hosts {
		if h.Tags["env"] != "prod" {
			t.Errorf("dynamic collection matched a non-prod host: %s", h.Hostname)
		}
	}

	// A newly-tagged host joins the dynamic collection automatically.
	dev1.Tags["env"] = "prod"
	_ = m.UpdateHost(ctx, dev1)
	if hosts, _ = m.CollectionHosts(ctx, dyn.ID); len(hosts) != 3 {
		t.Fatalf("dynamic collection should pick up the re-tagged host, got %d", len(hosts))
	}
}
