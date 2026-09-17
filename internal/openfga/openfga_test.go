package openfga

import (
	"testing"

	"github.com/juju/juju/permissions-demo/api"
	"github.com/juju/juju/permissions-demo/internal/catalog"
)

func TestPermissionTuplesScopePreservesExplicitHierarchy(t *testing.T) {
	binding := api.Binding{
		ID: "binding-1", SubjectType: api.SubjectTypeUser, SubjectID: "alice",
		Scope:    api.ResourceRef{Type: api.Model, ID: "production"},
		Selector: api.Selector{Match: api.Scope},
	}
	tuples, err := PermissionTuples(binding, []string{catalog.ApplicationConfigWrite, catalog.UnitSSH})
	if err != nil {
		t.Fatal(err)
	}
	want := []Tuple{
		{User: "grant:binding-1#subject", Relation: "application_config_write", Object: "model:production"},
		{User: "grant:binding-1#subject", Relation: "unit_ssh", Object: "model:production"},
	}
	if len(tuples) != len(want) {
		t.Fatalf("got %d tuples, want %d", len(tuples), len(want))
	}
	for i := range want {
		if tuples[i] != want[i] {
			t.Fatalf("tuple %d: got %#v, want %#v", i, tuples[i], want[i])
		}
	}
}

func TestPermissionTuplesExactMatchesResourceTypes(t *testing.T) {
	resources := []api.ResourceRef{{Type: api.Unit, ID: "app-0"}, {Type: api.Machine, ID: "0"}}
	binding := api.Binding{
		ID: "binding-1", Scope: api.ResourceRef{Type: api.Model, ID: "production"},
		Selector: api.Selector{Match: api.Exact, Resources: &resources},
	}
	tuples, err := PermissionTuples(binding, []string{catalog.UnitSSH, catalog.MachineSSH})
	if err != nil {
		t.Fatal(err)
	}
	want := []Tuple{
		{User: "grant:binding-1#subject", Relation: "ssh", Object: "unit:app-0"},
		{User: "grant:binding-1#subject", Relation: "ssh", Object: "machine:0"},
	}
	if len(tuples) != len(want) {
		t.Fatalf("got %d tuples, want %d", len(tuples), len(want))
	}
	for i := range want {
		if tuples[i] != want[i] {
			t.Fatalf("tuple %d: got %#v, want %#v", i, tuples[i], want[i])
		}
	}
}

func TestPermissionTuplesRejectsUnmatchedExactPermission(t *testing.T) {
	resources := []api.ResourceRef{{Type: api.Unit, ID: "app-0"}}
	binding := api.Binding{
		ID: "binding-1", Scope: api.ResourceRef{Type: api.Model, ID: "production"},
		Selector: api.Selector{Match: api.Exact, Resources: &resources},
	}
	_, err := PermissionTuples(binding, []string{catalog.MachineSSH})
	if err == nil {
		t.Fatal("expected an error")
	}
}
