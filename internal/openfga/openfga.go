package openfga

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	openfgamodel "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
	"github.com/openfga/language/pkg/go/transformer"

	"github.com/juju/juju/permissions-demo/api"
	"github.com/juju/juju/permissions-demo/internal/catalog"
)

//go:embed model.fga
var modelDSL string

const (
	storeIDKey = "openfga-store-id"
	modelIDKey = "openfga-model-id"
)

type Settings interface {
	Setting(context.Context, string) (string, bool, error)
	SetSetting(context.Context, string, string) error
}

type Engine struct {
	client *fgaclient.OpenFgaClient
}

type Tuple struct {
	User     string
	Relation string
	Object   string
}

func Bootstrap(ctx context.Context, apiURL string, settings Settings) (*Engine, error) {
	client, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{ApiUrl: apiURL})
	if err != nil {
		return nil, fmt.Errorf("create OpenFGA client: %w", err)
	}
	storeID, ok, err := settings.Setting(ctx, storeIDKey)
	if err != nil {
		return nil, err
	}
	if !ok {
		created, err := client.CreateStore(ctx).Body(fgaclient.ClientCreateStoreRequest{Name: "juju-permissions-demo"}).Execute()
		if err != nil {
			return nil, fmt.Errorf("create OpenFGA store: %w", err)
		}
		storeID = created.Id
		if err := settings.SetSetting(ctx, storeIDKey, storeID); err != nil {
			return nil, err
		}
	}
	if err := client.SetStoreId(storeID); err != nil {
		return nil, fmt.Errorf("select OpenFGA store: %w", err)
	}

	modelID, ok, err := settings.Setting(ctx, modelIDKey)
	if err != nil {
		return nil, err
	}
	if !ok {
		modelJSON, err := transformer.TransformDSLToJSON(modelDSL)
		if err != nil {
			return nil, fmt.Errorf("compile OpenFGA model: %w", err)
		}
		var model openfgamodel.WriteAuthorizationModelRequest
		if err := json.Unmarshal([]byte(modelJSON), &model); err != nil {
			return nil, fmt.Errorf("decode OpenFGA model: %w", err)
		}
		created, err := client.WriteAuthorizationModel(ctx).Body(model).Execute()
		if err != nil {
			return nil, fmt.Errorf("write OpenFGA model: %w", err)
		}
		modelID = created.AuthorizationModelId
		if err := settings.SetSetting(ctx, modelIDKey, modelID); err != nil {
			return nil, err
		}
	}
	if err := client.SetAuthorizationModelId(modelID); err != nil {
		return nil, fmt.Errorf("select OpenFGA model: %w", err)
	}
	return &Engine{client: client}, nil
}

func (e *Engine) Health(ctx context.Context) error {
	_, err := e.client.GetStore(ctx).Execute()
	return err
}

func (e *Engine) Check(ctx context.Context, principal, permission string, resource api.ResourceRef) (bool, error) {
	relation, err := catalog.Relation(permission)
	if err != nil {
		return false, err
	}
	if !catalog.Supports(permission, resource.Type) {
		return false, fmt.Errorf("permission %q does not apply to %q", permission, resource.Type)
	}
	response, err := e.client.Check(ctx).Body(fgaclient.ClientCheckRequest{
		User: "user:" + principal, Relation: relation, Object: catalog.ResourceObject(resource),
	}).Options(fgaclient.ClientCheckOptions{
		Consistency: openfgamodel.CONSISTENCYPREFERENCE_HIGHER_CONSISTENCY.Ptr(),
	}).Execute()
	if err != nil {
		return false, fmt.Errorf("OpenFGA check: %w", err)
	}
	return response.GetAllowed(), nil
}

func (e *Engine) Write(ctx context.Context, writes, deletes []Tuple) error {
	body := fgaclient.ClientWriteRequest{}
	if len(writes) > 0 {
		items := make([]fgaclient.ClientTupleKey, len(writes))
		for i, tuple := range writes {
			items[i] = fgaclient.ClientTupleKey{User: tuple.User, Relation: tuple.Relation, Object: tuple.Object}
		}
		body.Writes = items
	}
	if len(deletes) > 0 {
		items := make([]fgaclient.ClientTupleKeyWithoutCondition, len(deletes))
		for i, tuple := range deletes {
			items[i] = fgaclient.ClientTupleKeyWithoutCondition{User: tuple.User, Relation: tuple.Relation, Object: tuple.Object}
		}
		body.Deletes = items
	}
	if len(writes) == 0 && len(deletes) == 0 {
		return nil
	}
	_, err := e.client.Write(ctx).Body(body).Options(fgaclient.ClientWriteOptions{
		Conflict: fgaclient.ClientWriteConflictOptions{
			OnDuplicateWrites: fgaclient.CLIENT_WRITE_REQUEST_ON_DUPLICATE_WRITES_IGNORE,
			OnMissingDeletes:  fgaclient.CLIENT_WRITE_REQUEST_ON_MISSING_DELETES_IGNORE,
		},
	}).Execute()
	if err != nil {
		return fmt.Errorf("write OpenFGA tuples: %w", err)
	}
	return nil
}

func SubjectTuple(binding api.Binding) Tuple {
	user := string(binding.SubjectType) + ":" + binding.SubjectID
	if binding.SubjectType == api.SubjectTypeGroup {
		user += "#member"
	}
	return Tuple{User: user, Relation: "subject", Object: "grant:" + binding.ID}
}

func MembershipTuple(groupID, userID string) Tuple {
	return Tuple{User: "user:" + userID, Relation: "member", Object: "group:" + groupID}
}

func ParentTuple(resource api.Resource) (Tuple, bool) {
	if resource.Parent == nil {
		return Tuple{}, false
	}
	return Tuple{
		User: catalog.ResourceObject(*resource.Parent), Relation: "parent",
		Object: catalog.ResourceObject(api.ResourceRef{Type: resource.Type, ID: resource.ID}),
	}, true
}

func PermissionTuples(binding api.Binding, permissions []string) ([]Tuple, error) {
	principal := "grant:" + binding.ID + "#subject"
	var targets []api.ResourceRef
	switch binding.Selector.Match {
	case api.Scope:
		targets = []api.ResourceRef{binding.Scope}
	case api.Exact:
		if binding.Selector.Resources == nil || len(*binding.Selector.Resources) == 0 {
			return nil, fmt.Errorf("exact selector requires resources")
		}
		targets = *binding.Selector.Resources
	default:
		return nil, fmt.Errorf("unknown selector %q", binding.Selector.Match)
	}

	var result []Tuple
	for _, permission := range permissions {
		matched := false
		for _, target := range targets {
			if binding.Selector.Match == api.Exact && !catalog.Supports(permission, target.Type) {
				continue
			}
			relation, err := relationAtScope(permission, target.Type, binding.Selector.Match)
			if err != nil {
				return nil, err
			}
			result = append(result, Tuple{User: principal, Relation: relation, Object: catalog.ResourceObject(target)})
			matched = true
		}
		if !matched {
			return nil, fmt.Errorf("permission %q has no matching exact resource", permission)
		}
	}
	return result, nil
}

func relationAtScope(permission string, target api.ResourceType, match api.SelectorMatch) (string, error) {
	if catalog.Supports(permission, target) {
		return catalog.Relation(permission)
	}
	if match == api.Exact {
		return "", fmt.Errorf("permission %q does not apply to exact %q resource", permission, target)
	}
	prefix := strings.SplitN(permission, ".", 2)[0]
	relation := strings.NewReplacer(".", "_", "-", "_").Replace(permission)
	switch target {
	case api.Controller:
		return relation, nil
	case api.Model:
		if prefix == "application" || prefix == "unit" || prefix == "machine" || prefix == "policy" {
			return relation, nil
		}
	case api.Application:
		if prefix == "unit" || prefix == "machine" {
			return relation, nil
		}
	}
	return "", fmt.Errorf("permission %q cannot be inherited from %q", permission, target)
}
