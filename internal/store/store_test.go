package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/juju/juju/permissions-demo/api"
)

func TestSeededHierarchyAndCustomRoleRevision(t *testing.T) {
	ctx := context.Background()
	data, err := Open(ctx, filepath.Join(t.TempDir(), "demo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()

	resources, err := data.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 6 {
		t.Fatalf("got %d resources, want 6", len(resources))
	}

	role, err := data.CreateRole(ctx, api.CreateRole{
		Name: "unit operator", Description: "Operate units", Permissions: []string{"unit.read", "unit.ssh"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if role.Revision != 1 || role.ID != "unit-operator" {
		t.Fatalf("unexpected role: %#v", role)
	}

	updated, err := data.UpdateRole(ctx, "admin", role.ID, 1, api.UpdateRole{
		Description: "Read units", Permissions: []string{"unit.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 || len(updated.Permissions) != 1 {
		t.Fatalf("unexpected updated role: %#v", updated)
	}
	_, err = data.UpdateRole(ctx, "admin", role.ID, 1, api.UpdateRole{
		Description: "stale", Permissions: []string{"unit.read"},
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v, want ErrConflict", err)
	}
}

func TestMachineMayHaveModelOrApplicationParent(t *testing.T) {
	ctx := context.Background()
	data, err := Open(ctx, filepath.Join(t.TempDir(), "demo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()

	for _, input := range []api.CreateResource{
		{Type: api.Machine, Name: "model machine", Parent: &api.ResourceRef{Type: api.Model, ID: "production"}},
		{Type: api.Machine, Name: "app machine", Parent: &api.ResourceRef{Type: api.Application, ID: "payments"}},
	} {
		resource, err := data.CreateResource(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		if resource.Parent == nil || resource.Parent.Type != input.Parent.Type {
			t.Fatalf("unexpected parent: %#v", resource.Parent)
		}
	}
}

func TestListGroupsWithSingleConnection(t *testing.T) {
	ctx := context.Background()
	data, err := Open(ctx, filepath.Join(t.TempDir(), "demo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()

	user, err := data.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	group, err := data.CreateGroup(ctx, "operators")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.AddGroupMember(ctx, group.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	groups, err := data.ListGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0].Members) != 1 || groups[0].Members[0] != user.ID {
		t.Fatalf("unexpected groups: %#v", groups)
	}
}
