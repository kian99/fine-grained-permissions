package service

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/juju/juju/permissions-demo/api"
	"github.com/juju/juju/permissions-demo/internal/catalog"
	fga "github.com/juju/juju/permissions-demo/internal/openfga"
	"github.com/juju/juju/permissions-demo/internal/store"
)

var (
	ErrForbidden = errors.New("forbidden")
	ErrInvalid   = errors.New("invalid request")
)

type Service struct {
	store  *store.Store
	engine *fga.Engine
}

func New(store *store.Store, engine *fga.Engine) *Service {
	return &Service{store: store, engine: engine}
}

func (s *Service) Sync(ctx context.Context) error {
	var desired []fga.Tuple
	resources, err := s.store.ListResources(ctx, nil)
	if err != nil {
		return err
	}
	for _, resource := range resources {
		if tuple, ok := fga.ParentTuple(resource); ok {
			desired = append(desired, tuple)
		}
	}
	memberships, err := s.store.ListMemberships(ctx)
	if err != nil {
		return err
	}
	for _, membership := range memberships {
		desired = append(desired, fga.MembershipTuple(membership[0], membership[1]))
	}
	bindings, err := s.store.ListBindings(ctx)
	if err != nil {
		return err
	}
	for _, binding := range bindings {
		permissions, err := s.store.BindingPermissions(ctx, binding)
		if err != nil {
			return err
		}
		tuples, err := fga.PermissionTuples(binding, permissions)
		if err != nil {
			return err
		}
		desired = append(desired, append(tuples, fga.SubjectTuple(binding))...)
	}
	return s.replaceTuples(ctx, "all|", desired)
}

func (s *Service) Health(ctx context.Context) error { return s.engine.Health(ctx) }

func (s *Service) Check(ctx context.Context, principal, permission string, resource api.ResourceRef) (api.AuthorizationDecision, error) {
	if principal == "" {
		return api.AuthorizationDecision{}, fmt.Errorf("%w: principal is required", ErrInvalid)
	}
	if !resource.Type.Valid() || resource.ID == "" {
		return api.AuthorizationDecision{}, fmt.Errorf("%w: valid resource type and ID are required", ErrInvalid)
	}
	if _, ok := catalog.Permission(permission); !ok {
		return api.AuthorizationDecision{}, fmt.Errorf("%w: unknown permission %q", ErrInvalid, permission)
	}
	if resource.Type != api.Controller {
		if _, err := s.store.GetResource(ctx, resource.Type, resource.ID); err != nil {
			return api.AuthorizationDecision{}, err
		}
	} else if resource.ID != catalog.ControllerID {
		return api.AuthorizationDecision{}, store.ErrNotFound
	}
	allowed, err := s.engine.Check(ctx, principal, permission, resource)
	if err != nil {
		return api.AuthorizationDecision{}, err
	}
	reason := "no matching binding"
	if allowed {
		reason = "allowed by an applicable direct or group role binding"
	}
	return api.AuthorizationDecision{Allowed: allowed, Reason: reason, Permission: permission, Resource: resource}, nil
}

func (s *Service) CheckBatch(ctx context.Context, checks []api.AuthorizationCheck) ([]api.AuthorizationDecision, error) {
	result := make([]api.AuthorizationDecision, len(checks))
	for i, check := range checks {
		decision, err := s.Check(ctx, check.Principal, check.Permission, check.Resource)
		if err != nil {
			return nil, err
		}
		result[i] = decision
	}
	return result, nil
}

func (s *Service) require(ctx context.Context, actor, permission string, resource api.ResourceRef) error {
	decision, err := s.Check(ctx, actor, permission, resource)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return ErrForbidden
	}
	return nil
}
func controllerRef() api.ResourceRef {
	return api.ResourceRef{Type: api.Controller, ID: catalog.ControllerID}
}

func (s *Service) ListUsers(ctx context.Context, actor string) ([]api.User, error) {
	if err := s.require(ctx, actor, catalog.PolicyRead, controllerRef()); err != nil {
		return nil, err
	}
	return s.store.ListUsers(ctx)
}
func (s *Service) CreateUser(ctx context.Context, actor string, input api.CreateUser) (api.User, error) {
	if err := s.require(ctx, actor, catalog.PolicyManage, controllerRef()); err != nil {
		return api.User{}, err
	}
	return s.store.CreateUser(ctx, input.Name)
}
func (s *Service) ListGroups(ctx context.Context, actor string) ([]api.Group, error) {
	if err := s.require(ctx, actor, catalog.PolicyRead, controllerRef()); err != nil {
		return nil, err
	}
	return s.store.ListGroups(ctx)
}
func (s *Service) CreateGroup(ctx context.Context, actor string, input api.CreateGroup) (api.Group, error) {
	if err := s.require(ctx, actor, catalog.PolicyManage, controllerRef()); err != nil {
		return api.Group{}, err
	}
	return s.store.CreateGroup(ctx, input.Name)
}
func (s *Service) AddGroupMember(ctx context.Context, actor, groupID, userID string) error {
	if err := s.require(ctx, actor, catalog.PolicyManage, controllerRef()); err != nil {
		return err
	}
	if err := s.store.AddGroupMember(ctx, groupID, userID); err != nil {
		return err
	}
	return s.Sync(ctx)
}
func (s *Service) RemoveGroupMember(ctx context.Context, actor, groupID, userID string) error {
	if err := s.require(ctx, actor, catalog.PolicyManage, controllerRef()); err != nil {
		return err
	}
	if err := s.store.RemoveGroupMember(ctx, groupID, userID); err != nil {
		return err
	}
	return s.Sync(ctx)
}

func (s *Service) ListRoles(ctx context.Context, actor string) ([]api.Role, error) {
	if err := s.require(ctx, actor, catalog.PolicyRead, controllerRef()); err != nil {
		return nil, err
	}
	return s.store.ListRoles(ctx)
}
func (s *Service) GetRole(ctx context.Context, actor, id string) (api.Role, error) {
	if err := s.require(ctx, actor, catalog.PolicyRead, controllerRef()); err != nil {
		return api.Role{}, err
	}
	return s.store.GetRole(ctx, id)
}
func (s *Service) CreateRole(ctx context.Context, actor string, input api.CreateRole) (api.Role, error) {
	if err := s.require(ctx, actor, catalog.PolicyManage, controllerRef()); err != nil {
		return api.Role{}, err
	}
	if err := validatePermissions(input.Permissions); err != nil {
		return api.Role{}, err
	}
	return s.store.CreateRole(ctx, input)
}
func (s *Service) PreviewRoleUpdate(ctx context.Context, actor, id string, expected int, input api.UpdateRole) (api.RoleUpdatePreview, error) {
	if err := s.require(ctx, actor, catalog.PolicyManage, controllerRef()); err != nil {
		return api.RoleUpdatePreview{}, err
	}
	if err := validatePermissions(input.Permissions); err != nil {
		return api.RoleUpdatePreview{}, err
	}
	role, err := s.store.GetRole(ctx, id)
	if err != nil {
		return api.RoleUpdatePreview{}, err
	}
	if role.BuiltIn {
		return api.RoleUpdatePreview{}, fmt.Errorf("%w: built-in roles cannot be changed", ErrInvalid)
	}
	if role.Revision != expected {
		return api.RoleUpdatePreview{}, store.ErrConflict
	}
	count, err := s.store.CountBindings(ctx, id)
	if err != nil {
		return api.RoleUpdatePreview{}, err
	}
	added, removed := diff(role.Permissions, input.Permissions)
	bindings, err := s.store.ListBindings(ctx)
	if err != nil {
		return api.RoleUpdatePreview{}, err
	}
	for _, binding := range bindings {
		if binding.RoleID != id {
			continue
		}
		if _, err := fga.PermissionTuples(binding, input.Permissions); err != nil {
			return api.RoleUpdatePreview{}, fmt.Errorf("%w: binding %s: %v", ErrInvalid, binding.ID, err)
		}
	}
	return api.RoleUpdatePreview{RoleID: id, CurrentRevision: role.Revision, AddedPermissions: added, RemovedPermissions: removed, AffectedBindings: count}, nil
}
func (s *Service) UpdateRole(ctx context.Context, actor, id string, expected int, input api.UpdateRole) (api.Role, error) {
	if _, err := s.PreviewRoleUpdate(ctx, actor, id, expected, input); err != nil {
		return api.Role{}, err
	}
	updated, err := s.store.UpdateRole(ctx, actor, id, expected, input)
	if err != nil {
		return api.Role{}, err
	}
	if err := s.Sync(ctx); err != nil {
		return api.Role{}, err
	}
	return updated, nil
}

func (s *Service) ListBindings(ctx context.Context, actor string) ([]api.Binding, error) {
	if err := s.require(ctx, actor, catalog.PolicyRead, controllerRef()); err != nil {
		return nil, err
	}
	return s.store.ListBindings(ctx)
}
func (s *Service) CreateBinding(ctx context.Context, actor string, input api.CreateBinding) (api.Binding, error) {
	if err := s.validateBinding(ctx, input); err != nil {
		return api.Binding{}, err
	}
	managementScope, err := s.managementScope(ctx, input.Scope)
	if err != nil {
		return api.Binding{}, err
	}
	if err := s.require(ctx, actor, catalog.PolicyManage, managementScope); err != nil {
		return api.Binding{}, err
	}
	binding, err := s.store.CreateBinding(ctx, input, false)
	if err != nil {
		return api.Binding{}, err
	}
	if err := s.Sync(ctx); err != nil {
		return api.Binding{}, err
	}
	return binding, nil
}
func (s *Service) DeleteBinding(ctx context.Context, actor, id string) error {
	binding, err := s.store.GetBinding(ctx, id)
	if err != nil {
		return err
	}
	managementScope, err := s.managementScope(ctx, binding.Scope)
	if err != nil {
		return err
	}
	if err := s.require(ctx, actor, catalog.PolicyManage, managementScope); err != nil {
		return err
	}
	if err := s.store.DeleteBinding(ctx, id); err != nil {
		return err
	}
	return s.Sync(ctx)
}

func (s *Service) managementScope(ctx context.Context, ref api.ResourceRef) (api.ResourceRef, error) {
	for ref.Type != api.Controller && ref.Type != api.Model {
		resource, err := s.store.GetResource(ctx, ref.Type, ref.ID)
		if err != nil {
			return api.ResourceRef{}, err
		}
		if resource.Parent == nil {
			return api.ResourceRef{}, fmt.Errorf("%w: resource has no policy scope", ErrInvalid)
		}
		ref = *resource.Parent
	}
	return ref, nil
}
func (s *Service) replaceTuples(ctx context.Context, prefix string, desired []fga.Tuple) error {
	stored, err := s.store.ListSyncedTuples(ctx, prefix)
	if err != nil {
		return err
	}
	current := make([]fga.Tuple, len(stored))
	for i, tuple := range stored {
		current[i] = fga.Tuple{User: tuple[0], Relation: tuple[1], Object: tuple[2]}
	}
	writes, deletes := tupleDiff(current, desired)
	if err := s.engine.Write(ctx, writes, deletes); err != nil {
		return err
	}
	records := make([][3]string, len(desired))
	for i, tuple := range desired {
		records[i] = [3]string{tuple.User, tuple.Relation, tuple.Object}
	}
	return s.store.ReplaceSyncedTuples(ctx, prefix, records)
}
func (s *Service) validateBinding(ctx context.Context, input api.CreateBinding) error {
	if _, err := s.store.GetRole(ctx, input.RoleID); err != nil {
		return err
	}
	switch input.SubjectType {
	case api.SubjectTypeUser:
		ok, err := s.store.UserExists(ctx, input.SubjectID)
		if err != nil {
			return err
		}
		if !ok {
			return store.ErrNotFound
		}
	case api.SubjectTypeGroup:
		ok, err := s.store.GroupExists(ctx, input.SubjectID)
		if err != nil {
			return err
		}
		if !ok {
			return store.ErrNotFound
		}
	default:
		return fmt.Errorf("%w: invalid subject type", ErrInvalid)
	}
	if input.Scope.Type != api.Controller {
		if _, err := s.store.GetResource(ctx, input.Scope.Type, input.Scope.ID); err != nil {
			return err
		}
	}
	if input.Selector.Match == api.Exact {
		if input.Selector.Resources == nil || len(*input.Selector.Resources) == 0 {
			return fmt.Errorf("%w: exact selector requires resources", ErrInvalid)
		}
		for _, ref := range *input.Selector.Resources {
			if _, err := s.store.GetResource(ctx, ref.Type, ref.ID); err != nil {
				return err
			}
			within, err := s.isWithinScope(ctx, ref, input.Scope)
			if err != nil {
				return err
			}
			if !within {
				return fmt.Errorf("%w: resource %s:%s is outside scope %s:%s",
					ErrInvalid, ref.Type, ref.ID, input.Scope.Type, input.Scope.ID)
			}
		}
	} else if input.Selector.Match != api.Scope {
		return fmt.Errorf("%w: invalid selector", ErrInvalid)
	} else if input.Selector.Resources != nil {
		return fmt.Errorf("%w: scope selector cannot include exact resources", ErrInvalid)
	}
	return nil
}

func (s *Service) isWithinScope(ctx context.Context, ref, scope api.ResourceRef) (bool, error) {
	for {
		if ref == scope {
			return true, nil
		}
		if ref.Type == api.Controller {
			return false, nil
		}
		resource, err := s.store.GetResource(ctx, ref.Type, ref.ID)
		if err != nil {
			return false, err
		}
		if resource.Parent == nil {
			return false, nil
		}
		ref = *resource.Parent
	}
}

func (s *Service) GrantLegacy(ctx context.Context, actor string, input api.LegacyAccessChange) (api.Binding, error) {
	if !input.Access.Valid() {
		return api.Binding{}, fmt.Errorf("%w: invalid legacy access level", ErrInvalid)
	}
	scope := api.ResourceRef{Type: api.Model, ID: input.ModelID}
	if err := s.require(ctx, actor, catalog.PolicyManage, scope); err != nil {
		return api.Binding{}, err
	}
	if ok, err := s.store.UserExists(ctx, input.UserID); err != nil {
		return api.Binding{}, err
	} else if !ok {
		return api.Binding{}, store.ErrNotFound
	}
	if _, err := s.store.GetResource(ctx, api.Model, input.ModelID); err != nil {
		return api.Binding{}, err
	}
	roleID := compatibilityRole(input.Access)
	_, err := s.store.GetCompatibilityBinding(ctx, input.UserID, input.ModelID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return api.Binding{}, err
	}
	binding, err := s.store.UpsertCompatibilityBinding(ctx, input.UserID, roleID, input.ModelID)
	if err != nil {
		return api.Binding{}, err
	}
	if err := s.Sync(ctx); err != nil {
		return api.Binding{}, err
	}
	return binding, nil
}
func (s *Service) RevokeLegacy(ctx context.Context, actor string, input api.LegacyAccessChange) (api.LegacyRevokeResult, error) {
	scope := api.ResourceRef{Type: api.Model, ID: input.ModelID}
	if err := s.require(ctx, actor, catalog.PolicyManage, scope); err != nil {
		return api.LegacyRevokeResult{}, err
	}
	binding, err := s.store.GetCompatibilityBinding(ctx, input.UserID, input.ModelID)
	if err != nil {
		return api.LegacyRevokeResult{}, err
	}
	if !input.Access.Valid() || binding.RoleID != compatibilityRole(input.Access) {
		return api.LegacyRevokeResult{}, fmt.Errorf("%w: revoke level must match current compatibility access", ErrInvalid)
	}
	next := ""
	switch input.Access {
	case api.LegacyAccessLevelAdmin:
		next = "write"
	case api.LegacyAccessLevelWrite:
		next = "read"
	case api.LegacyAccessLevelRead:
		next = ""
	}
	if next == "" {
		if err := s.store.DeleteBinding(ctx, binding.ID); err != nil {
			return api.LegacyRevokeResult{}, err
		}
		if err := s.Sync(ctx); err != nil {
			return api.LegacyRevokeResult{}, err
		}
		decision, err := s.Check(ctx, input.UserID, catalog.ModelRead, scope)
		if err != nil {
			return api.LegacyRevokeResult{}, err
		}
		return api.LegacyRevokeResult{
			EffectiveAccess: api.LegacyRevokeResultEffectiveAccessNone,
			StillAuthorized: decision.Allowed,
		}, nil
	}
	updated, err := s.store.UpsertCompatibilityBinding(
		ctx, input.UserID, compatibilityRole(api.LegacyAccessLevel(next)), input.ModelID)
	if err != nil {
		return api.LegacyRevokeResult{}, err
	}
	if err := s.Sync(ctx); err != nil {
		return api.LegacyRevokeResult{}, err
	}
	decision, err := s.Check(ctx, input.UserID, catalog.ModelRead, scope)
	if err != nil {
		return api.LegacyRevokeResult{}, err
	}
	effective := api.LegacyRevokeResultEffectiveAccess(next)
	return api.LegacyRevokeResult{Binding: &updated, EffectiveAccess: effective, StillAuthorized: decision.Allowed}, nil
}

func (s *Service) ListResources(ctx context.Context, actor string, filter *api.ResourceType) ([]api.Resource, error) {
	items, err := s.store.ListResources(ctx, filter)
	if err != nil {
		return nil, err
	}
	var result []api.Resource
	for _, item := range items {
		permission, ok := catalog.ReadPermission(item.Type)
		if !ok {
			continue
		}
		decision, err := s.Check(ctx, actor, permission, api.ResourceRef{Type: item.Type, ID: item.ID})
		if err != nil {
			return nil, err
		}
		if decision.Allowed {
			result = append(result, item)
		}
	}
	return result, nil
}
func (s *Service) GetResource(ctx context.Context, actor string, ref api.ResourceRef) (api.Resource, error) {
	item, err := s.store.GetResource(ctx, ref.Type, ref.ID)
	if err != nil {
		return api.Resource{}, err
	}
	permission, _ := catalog.ReadPermission(ref.Type)
	if err := s.require(ctx, actor, permission, ref); err != nil {
		return api.Resource{}, err
	}
	return item, nil
}
func (s *Service) CreateResource(ctx context.Context, actor string, input api.CreateResource) (api.Resource, error) {
	if input.Type == api.Controller {
		return api.Resource{}, fmt.Errorf("%w: controller is implicit", ErrInvalid)
	}
	allowedParents := catalog.ParentRule(input.Type)
	if len(allowedParents) > 0 && input.Parent == nil {
		return api.Resource{}, fmt.Errorf("%w: parent is required", ErrInvalid)
	}
	if input.Parent != nil {
		if !containsType(allowedParents, input.Parent.Type) {
			return api.Resource{}, fmt.Errorf("%w: invalid parent type", ErrInvalid)
		}
		if input.Parent.Type != api.Controller {
			if _, err := s.store.GetResource(ctx, input.Parent.Type, input.Parent.ID); err != nil {
				return api.Resource{}, err
			}
		}
	}
	permission, _ := catalog.CreatePermission(input.Type)
	target := controllerRef()
	if input.Parent != nil {
		target = *input.Parent
	}
	if err := s.require(ctx, actor, permission, target); err != nil {
		return api.Resource{}, err
	}
	resource, err := s.store.CreateResource(ctx, input)
	if err != nil {
		return api.Resource{}, err
	}
	if err := s.Sync(ctx); err != nil {
		return api.Resource{}, err
	}
	return resource, nil
}
func (s *Service) DeleteResource(ctx context.Context, actor string, ref api.ResourceRef) error {
	_, err := s.store.GetResource(ctx, ref.Type, ref.ID)
	if err != nil {
		return err
	}
	permission, _ := catalog.DeletePermission(ref.Type)
	if err := s.require(ctx, actor, permission, ref); err != nil {
		return err
	}
	if children, err := s.store.HasChildren(ctx, ref); err != nil {
		return err
	} else if children {
		return store.ErrConflict
	}
	if err := s.store.DeleteResource(ctx, ref); err != nil {
		return err
	}
	return s.Sync(ctx)
}
func (s *Service) GetApplicationConfig(ctx context.Context, actor, id string) (api.ApplicationConfig, error) {
	ref := api.ResourceRef{Type: api.Application, ID: id}
	if _, err := s.store.GetResource(ctx, ref.Type, ref.ID); err != nil {
		return nil, err
	}
	if err := s.require(ctx, actor, catalog.ApplicationConfigRead, ref); err != nil {
		return nil, err
	}
	return s.store.GetApplicationConfig(ctx, id)
}
func (s *Service) UpdateApplicationConfig(ctx context.Context, actor, id string, config api.ApplicationConfig) (api.ApplicationConfig, error) {
	ref := api.ResourceRef{Type: api.Application, ID: id}
	if _, err := s.store.GetResource(ctx, ref.Type, ref.ID); err != nil {
		return nil, err
	}
	if err := s.require(ctx, actor, catalog.ApplicationConfigWrite, ref); err != nil {
		return nil, err
	}
	if err := s.store.SetApplicationConfig(ctx, id, config); err != nil {
		return nil, err
	}
	return config, nil
}
func (s *Service) SSH(ctx context.Context, actor string, typ api.ResourceType, id string) (string, error) {
	ref := api.ResourceRef{Type: typ, ID: id}
	resource, err := s.store.GetResource(ctx, typ, id)
	if err != nil {
		return "", err
	}
	permission := catalog.UnitSSH
	if typ == api.Machine {
		permission = catalog.MachineSSH
	}
	if err := s.require(ctx, actor, permission, ref); err != nil {
		return "", err
	}
	return fmt.Sprintf("simulated SSH session to %s %q as %s", typ, resource.Name, actor), nil
}

func validatePermissions(permissions []string) error {
	if len(permissions) == 0 {
		return fmt.Errorf("%w: at least one permission is required", ErrInvalid)
	}
	for _, permission := range permissions {
		if _, ok := catalog.Permission(permission); !ok {
			return fmt.Errorf("%w: unknown permission %q", ErrInvalid, permission)
		}
	}
	return nil
}

func compatibilityRole(access api.LegacyAccessLevel) string {
	switch access {
	case api.LegacyAccessLevelRead:
		return "model-reader"
	case api.LegacyAccessLevelWrite:
		return "model-writer"
	case api.LegacyAccessLevelAdmin:
		return "model-admin"
	default:
		return ""
	}
}
func diff(oldValues, newValues []string) ([]string, []string) {
	oldSet, newSet := map[string]bool{}, map[string]bool{}
	for _, v := range oldValues {
		oldSet[v] = true
	}
	for _, v := range newValues {
		newSet[v] = true
	}
	var added, removed []string
	for v := range newSet {
		if !oldSet[v] {
			added = append(added, v)
		}
	}
	for v := range oldSet {
		if !newSet[v] {
			removed = append(removed, v)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}
func containsType(values []api.ResourceType, target api.ResourceType) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func tupleDiff(current, desired []fga.Tuple) ([]fga.Tuple, []fga.Tuple) {
	key := func(tuple fga.Tuple) string { return tuple.User + "|" + tuple.Relation + "|" + tuple.Object }
	currentSet, desiredSet := map[string]fga.Tuple{}, map[string]fga.Tuple{}
	for _, tuple := range current {
		currentSet[key(tuple)] = tuple
	}
	for _, tuple := range desired {
		desiredSet[key(tuple)] = tuple
	}
	var writes, deletes []fga.Tuple
	for id, tuple := range desiredSet {
		if _, ok := currentSet[id]; !ok {
			writes = append(writes, tuple)
		}
	}
	for id, tuple := range currentSet {
		if _, ok := desiredSet[id]; !ok {
			deletes = append(deletes, tuple)
		}
	}
	return writes, deletes
}
