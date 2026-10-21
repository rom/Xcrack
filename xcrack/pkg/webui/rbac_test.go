package webui

import "testing"

// TestRBACAccessDecisions checks the read (canAccess) vs mutate (canMutate) split
// across owner, other user, shared-with reader, viewer, and admin.
func TestRBACAccessDecisions(t *testing.T) {
	s := &Server{auth: &authenticator{
		enabled: true,
		admins:  map[string]bool{"adm": true},
		viewers: map[string]bool{"view": true},
	}}

	owner := user{Subject: "alice"}
	bob := user{Subject: "bob"}
	viewer := user{Subject: "view"}
	admin := user{Subject: "adm", Admin: true}

	// Owner: read + mutate own job.
	if !s.canAccess(owner, "alice", nil) || !s.canMutate(owner, "alice") {
		t.Fatal("owner must read and mutate their own job")
	}
	// Unrelated user: neither.
	if s.canAccess(bob, "alice", nil) {
		t.Fatal("an unrelated user must not read another's job")
	}
	// Shared-with reader: read yes, mutate no.
	if !s.canAccess(bob, "alice", []string{"bob"}) {
		t.Fatal("a shared-with user must read")
	}
	if s.canMutate(bob, "alice") {
		t.Fatal("a shared-with user must not mutate")
	}
	// Viewer: read all, mutate none.
	if !s.canAccess(viewer, "alice", nil) {
		t.Fatal("a viewer must read every job")
	}
	if s.canMutate(viewer, "alice") {
		t.Fatal("a viewer must not mutate")
	}
	// Admin: both.
	if !s.canAccess(admin, "alice", nil) || !s.canMutate(admin, "alice") {
		t.Fatal("an admin must read and mutate")
	}

	// Auth off: everything is the implicit owner.
	off := &Server{auth: &authenticator{enabled: false}}
	if !off.canAccess(user{}, "whoever", nil) || !off.canMutate(user{}, "whoever") {
		t.Fatal("single-user mode must allow all access")
	}
}
