package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/juju/juju/permissions-demo/api"
	"github.com/juju/juju/permissions-demo/internal/store"
)

func TestExactTargetMustBeWithinScope(t *testing.T) {
	ctx := context.Background()
	data, err := store.Open(ctx, filepath.Join(t.TempDir(), "demo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()

	other, err := data.CreateResource(ctx, api.CreateResource{
		Type: api.Model, Name: "staging", Parent: &api.ResourceRef{Type: api.Controller, ID: "juju"},
	})
	if err != nil {
		t.Fatal(err)
	}
	application, err := data.CreateResource(ctx, api.CreateResource{
		Type: api.Application, Name: "other-app", Parent: &api.ResourceRef{Type: api.Model, ID: other.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	resources := []api.ResourceRef{{Type: api.Application, ID: application.ID}}
	svc := &Service{store: data}
	err = svc.validateBinding(ctx, api.CreateBinding{
		SubjectType: api.SubjectTypeUser, SubjectID: "admin", RoleID: "application-observer",
		Scope:    api.ResourceRef{Type: api.Model, ID: "production"},
		Selector: api.Selector{Match: api.Exact, Resources: &resources},
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestCompatibilityRole(t *testing.T) {
	for _, test := range []struct {
		access api.LegacyAccessLevel
		want   string
	}{
		{api.LegacyAccessLevelRead, "model-reader"},
		{api.LegacyAccessLevelWrite, "model-writer"},
		{api.LegacyAccessLevelAdmin, "model-admin"},
	} {
		if got := compatibilityRole(test.access); got != test.want {
			t.Fatalf("compatibilityRole(%q) = %q, want %q", test.access, got, test.want)
		}
	}
}
