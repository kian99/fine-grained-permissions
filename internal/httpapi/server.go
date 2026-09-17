package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/juju/juju/permissions-demo/api"
	"github.com/juju/juju/permissions-demo/internal/catalog"
	"github.com/juju/juju/permissions-demo/internal/service"
	"github.com/juju/juju/permissions-demo/internal/store"
)

type principalKey struct{}

type Server struct {
	service *service.Service
}

var _ api.StrictServerInterface = (*Server)(nil)

func New(service *service.Service) *Server { return &Server{service: service} }

func DemoIdentityMiddleware(next api.StrictHandlerFunc, operationID string) api.StrictHandlerFunc {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
		if operationID == "GetHealth" {
			return next(ctx, w, r, request)
		}
		principal := r.Header.Get("X-Demo-User")
		if principal == "" {
			return unauthorized(operationID), nil
		}
		return next(context.WithValue(ctx, principalKey{}, principal), w, r, request)
	}
}

func actor(ctx context.Context) string { value, _ := ctx.Value(principalKey{}).(string); return value }
func problem(code string, err error) api.Problem {
	return api.Problem{Code: code, Message: err.Error()}
}

func unauthorized(operationID string) any {
	p := api.UnauthorizedJSONResponse(problem("unauthorized", errors.New("X-Demo-User header is required")))
	switch operationID {
	case "ListPermissions":
		return api.ListPermissions401JSONResponse{UnauthorizedJSONResponse: p}
	case "ListUsers":
		return api.ListUsers401JSONResponse{UnauthorizedJSONResponse: p}
	case "CreateUser":
		return api.CreateUser401JSONResponse{UnauthorizedJSONResponse: p}
	case "ListGroups":
		return api.ListGroups401JSONResponse{UnauthorizedJSONResponse: p}
	case "CreateGroup":
		return api.CreateGroup401JSONResponse{UnauthorizedJSONResponse: p}
	case "AddGroupMember":
		return api.AddGroupMember401JSONResponse{UnauthorizedJSONResponse: p}
	case "RemoveGroupMember":
		return api.RemoveGroupMember401JSONResponse{UnauthorizedJSONResponse: p}
	case "ListRoles":
		return api.ListRoles401JSONResponse{UnauthorizedJSONResponse: p}
	case "CreateRole":
		return api.CreateRole401JSONResponse{UnauthorizedJSONResponse: p}
	case "GetRole":
		return api.GetRole401JSONResponse{UnauthorizedJSONResponse: p}
	case "UpdateRole":
		return api.UpdateRole401JSONResponse{UnauthorizedJSONResponse: p}
	case "PreviewRoleUpdate":
		return api.PreviewRoleUpdate401JSONResponse{UnauthorizedJSONResponse: p}
	case "ListBindings":
		return api.ListBindings401JSONResponse{UnauthorizedJSONResponse: p}
	case "CreateBinding":
		return api.CreateBinding401JSONResponse{UnauthorizedJSONResponse: p}
	case "DeleteBinding":
		return api.DeleteBinding401JSONResponse{UnauthorizedJSONResponse: p}
	case "CheckAuthorization":
		return api.CheckAuthorization401JSONResponse{UnauthorizedJSONResponse: p}
	case "CheckAuthorizationBatch":
		return api.CheckAuthorizationBatch401JSONResponse{UnauthorizedJSONResponse: p}
	case "GrantLegacyAccess":
		return api.GrantLegacyAccess401JSONResponse{UnauthorizedJSONResponse: p}
	case "RevokeLegacyAccess":
		return api.RevokeLegacyAccess401JSONResponse{UnauthorizedJSONResponse: p}
	case "ListResources":
		return api.ListResources401JSONResponse{UnauthorizedJSONResponse: p}
	case "CreateResource":
		return api.CreateResource401JSONResponse{UnauthorizedJSONResponse: p}
	case "GetResource":
		return api.GetResource401JSONResponse{UnauthorizedJSONResponse: p}
	case "DeleteResource":
		return api.DeleteResource401JSONResponse{UnauthorizedJSONResponse: p}
	case "GetApplicationConfig":
		return api.GetApplicationConfig401JSONResponse{UnauthorizedJSONResponse: p}
	case "UpdateApplicationConfig":
		return api.UpdateApplicationConfig401JSONResponse{UnauthorizedJSONResponse: p}
	case "SSHUnit":
		return api.SSHUnit401JSONResponse{UnauthorizedJSONResponse: p}
	case "SSHMachine":
		return api.SSHMachine401JSONResponse{UnauthorizedJSONResponse: p}
	default:
		return nil
	}
}

func (s *Server) GetHealth(ctx context.Context, _ api.GetHealthRequestObject) (api.GetHealthResponseObject, error) {
	if err := s.service.Health(ctx); err != nil {
		return api.GetHealth503JSONResponse{ServiceUnavailableJSONResponse: api.ServiceUnavailableJSONResponse(problem("openfga_unavailable", err))}, nil
	}
	return api.GetHealth200JSONResponse{Status: api.HealthStatusOk, Openfga: api.HealthOpenfgaOk}, nil
}
func (s *Server) ListPermissions(_ context.Context, _ api.ListPermissionsRequestObject) (api.ListPermissionsResponseObject, error) {
	return api.ListPermissions200JSONResponse(catalog.Permissions()), nil
}
func (s *Server) ListUsers(ctx context.Context, _ api.ListUsersRequestObject) (api.ListUsersResponseObject, error) {
	items, err := s.service.ListUsers(ctx, actor(ctx))
	if err != nil {
		return listUsersError(err), nil
	}
	return api.ListUsers200JSONResponse(items), nil
}
func (s *Server) CreateUser(ctx context.Context, request api.CreateUserRequestObject) (api.CreateUserResponseObject, error) {
	if request.Body == nil {
		return api.CreateUser400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", errors.New("body is required")))}, nil
	}
	item, err := s.service.CreateUser(ctx, actor(ctx), *request.Body)
	if err != nil {
		return createUserError(err), nil
	}
	return api.CreateUser201JSONResponse(item), nil
}
func (s *Server) ListGroups(ctx context.Context, _ api.ListGroupsRequestObject) (api.ListGroupsResponseObject, error) {
	items, err := s.service.ListGroups(ctx, actor(ctx))
	if err != nil {
		return listGroupsError(err), nil
	}
	return api.ListGroups200JSONResponse(items), nil
}
func (s *Server) CreateGroup(ctx context.Context, request api.CreateGroupRequestObject) (api.CreateGroupResponseObject, error) {
	if request.Body == nil {
		return api.CreateGroup400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", errors.New("body is required")))}, nil
	}
	item, err := s.service.CreateGroup(ctx, actor(ctx), *request.Body)
	if err != nil {
		return createGroupError(err), nil
	}
	return api.CreateGroup201JSONResponse(item), nil
}
func (s *Server) AddGroupMember(ctx context.Context, request api.AddGroupMemberRequestObject) (api.AddGroupMemberResponseObject, error) {
	if request.Body == nil {
		return api.AddGroupMember400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", errors.New("body is required")))}, nil
	}
	if err := s.service.AddGroupMember(ctx, actor(ctx), request.GroupID, request.Body.UserID); err != nil {
		return addGroupMemberError(err), nil
	}
	return api.AddGroupMember204Response{}, nil
}
func (s *Server) RemoveGroupMember(ctx context.Context, request api.RemoveGroupMemberRequestObject) (api.RemoveGroupMemberResponseObject, error) {
	if request.Body == nil {
		return api.RemoveGroupMember400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", errors.New("body is required")))}, nil
	}
	if err := s.service.RemoveGroupMember(ctx, actor(ctx), request.GroupID, request.Body.UserID); err != nil {
		return removeGroupMemberError(err), nil
	}
	return api.RemoveGroupMember204Response{}, nil
}
func (s *Server) ListRoles(ctx context.Context, _ api.ListRolesRequestObject) (api.ListRolesResponseObject, error) {
	items, err := s.service.ListRoles(ctx, actor(ctx))
	if err != nil {
		return listRolesError(err), nil
	}
	return api.ListRoles200JSONResponse(items), nil
}
func (s *Server) CreateRole(ctx context.Context, request api.CreateRoleRequestObject) (api.CreateRoleResponseObject, error) {
	if request.Body == nil {
		return api.CreateRole400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", errors.New("body is required")))}, nil
	}
	item, err := s.service.CreateRole(ctx, actor(ctx), *request.Body)
	if err != nil {
		return createRoleError(err), nil
	}
	return api.CreateRole201JSONResponse(item), nil
}
func (s *Server) GetRole(ctx context.Context, request api.GetRoleRequestObject) (api.GetRoleResponseObject, error) {
	item, err := s.service.GetRole(ctx, actor(ctx), request.RoleID)
	if err != nil {
		return getRoleError(err), nil
	}
	return api.GetRole200JSONResponse(item), nil
}
func (s *Server) PreviewRoleUpdate(ctx context.Context, request api.PreviewRoleUpdateRequestObject) (api.PreviewRoleUpdateResponseObject, error) {
	if request.Body == nil {
		return api.PreviewRoleUpdate400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", errors.New("body is required")))}, nil
	}
	item, err := s.service.PreviewRoleUpdate(ctx, actor(ctx), request.RoleID, request.Params.IfMatch, *request.Body)
	if err != nil {
		return previewRoleError(err), nil
	}
	return api.PreviewRoleUpdate200JSONResponse(item), nil
}
func (s *Server) UpdateRole(ctx context.Context, request api.UpdateRoleRequestObject) (api.UpdateRoleResponseObject, error) {
	if request.Body == nil {
		return api.UpdateRole400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", errors.New("body is required")))}, nil
	}
	item, err := s.service.UpdateRole(ctx, actor(ctx), request.RoleID, request.Params.IfMatch, *request.Body)
	if err != nil {
		return updateRoleError(err), nil
	}
	return api.UpdateRole200JSONResponse(item), nil
}
func (s *Server) ListBindings(ctx context.Context, _ api.ListBindingsRequestObject) (api.ListBindingsResponseObject, error) {
	items, err := s.service.ListBindings(ctx, actor(ctx))
	if err != nil {
		return listBindingsError(err), nil
	}
	return api.ListBindings200JSONResponse(items), nil
}
func (s *Server) CreateBinding(ctx context.Context, request api.CreateBindingRequestObject) (api.CreateBindingResponseObject, error) {
	if request.Body == nil {
		return api.CreateBinding400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", errors.New("body is required")))}, nil
	}
	item, err := s.service.CreateBinding(ctx, actor(ctx), *request.Body)
	if err != nil {
		return createBindingError(err), nil
	}
	return api.CreateBinding201JSONResponse(item), nil
}
func (s *Server) DeleteBinding(ctx context.Context, request api.DeleteBindingRequestObject) (api.DeleteBindingResponseObject, error) {
	if err := s.service.DeleteBinding(ctx, actor(ctx), request.BindingID); err != nil {
		return deleteBindingError(err), nil
	}
	return api.DeleteBinding204Response{}, nil
}
func (s *Server) CheckAuthorization(ctx context.Context, request api.CheckAuthorizationRequestObject) (api.CheckAuthorizationResponseObject, error) {
	if request.Body == nil {
		return api.CheckAuthorization400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", errors.New("body is required")))}, nil
	}
	item, err := s.service.Check(ctx, request.Body.Principal, request.Body.Permission, request.Body.Resource)
	if err != nil {
		return api.CheckAuthorization503JSONResponse{ServiceUnavailableJSONResponse: api.ServiceUnavailableJSONResponse(problem("authorization_error", err))}, nil
	}
	return api.CheckAuthorization200JSONResponse(item), nil
}
func (s *Server) CheckAuthorizationBatch(ctx context.Context, request api.CheckAuthorizationBatchRequestObject) (api.CheckAuthorizationBatchResponseObject, error) {
	if request.Body == nil {
		return api.CheckAuthorizationBatch400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", errors.New("body is required")))}, nil
	}
	items, err := s.service.CheckBatch(ctx, request.Body.Checks)
	if err != nil {
		return api.CheckAuthorizationBatch503JSONResponse{ServiceUnavailableJSONResponse: api.ServiceUnavailableJSONResponse(problem("authorization_error", err))}, nil
	}
	return api.CheckAuthorizationBatch200JSONResponse(items), nil
}
func (s *Server) GrantLegacyAccess(ctx context.Context, request api.GrantLegacyAccessRequestObject) (api.GrantLegacyAccessResponseObject, error) {
	if request.Body == nil {
		return api.GrantLegacyAccess400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", errors.New("body is required")))}, nil
	}
	item, err := s.service.GrantLegacy(ctx, actor(ctx), *request.Body)
	if err != nil {
		return grantLegacyError(err), nil
	}
	return api.GrantLegacyAccess200JSONResponse(item), nil
}
func (s *Server) RevokeLegacyAccess(ctx context.Context, request api.RevokeLegacyAccessRequestObject) (api.RevokeLegacyAccessResponseObject, error) {
	if request.Body == nil {
		return api.RevokeLegacyAccess400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", errors.New("body is required")))}, nil
	}
	item, err := s.service.RevokeLegacy(ctx, actor(ctx), *request.Body)
	if err != nil {
		return revokeLegacyError(err), nil
	}
	return api.RevokeLegacyAccess200JSONResponse(item), nil
}
func (s *Server) ListResources(ctx context.Context, request api.ListResourcesRequestObject) (api.ListResourcesResponseObject, error) {
	items, err := s.service.ListResources(ctx, actor(ctx), request.Params.Type)
	if err != nil {
		return api.ListResources503JSONResponse{ServiceUnavailableJSONResponse: api.ServiceUnavailableJSONResponse(problem("authorization_error", err))}, nil
	}
	return api.ListResources200JSONResponse(items), nil
}
func (s *Server) CreateResource(ctx context.Context, request api.CreateResourceRequestObject) (api.CreateResourceResponseObject, error) {
	if request.Body == nil {
		return api.CreateResource400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", errors.New("body is required")))}, nil
	}
	item, err := s.service.CreateResource(ctx, actor(ctx), *request.Body)
	if err != nil {
		return createResourceError(err), nil
	}
	return api.CreateResource201JSONResponse(item), nil
}
func (s *Server) GetResource(ctx context.Context, request api.GetResourceRequestObject) (api.GetResourceResponseObject, error) {
	item, err := s.service.GetResource(ctx, actor(ctx), api.ResourceRef{Type: request.ResourceType, ID: request.ResourceID})
	if err != nil {
		return getResourceError(err), nil
	}
	return api.GetResource200JSONResponse(item), nil
}
func (s *Server) DeleteResource(ctx context.Context, request api.DeleteResourceRequestObject) (api.DeleteResourceResponseObject, error) {
	if err := s.service.DeleteResource(ctx, actor(ctx), api.ResourceRef{Type: request.ResourceType, ID: request.ResourceID}); err != nil {
		return deleteResourceError(err), nil
	}
	return api.DeleteResource204Response{}, nil
}
func (s *Server) GetApplicationConfig(ctx context.Context, request api.GetApplicationConfigRequestObject) (api.GetApplicationConfigResponseObject, error) {
	item, err := s.service.GetApplicationConfig(ctx, actor(ctx), request.ApplicationID)
	if err != nil {
		return getConfigError(err), nil
	}
	return api.GetApplicationConfig200JSONResponse(item), nil
}
func (s *Server) UpdateApplicationConfig(ctx context.Context, request api.UpdateApplicationConfigRequestObject) (api.UpdateApplicationConfigResponseObject, error) {
	if request.Body == nil {
		return api.UpdateApplicationConfig400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", errors.New("body is required")))}, nil
	}
	item, err := s.service.UpdateApplicationConfig(ctx, actor(ctx), request.ApplicationID, *request.Body)
	if err != nil {
		return updateConfigError(err), nil
	}
	return api.UpdateApplicationConfig200JSONResponse(item), nil
}
func (s *Server) SSHUnit(ctx context.Context, request api.SSHUnitRequestObject) (api.SSHUnitResponseObject, error) {
	message, err := s.service.SSH(ctx, actor(ctx), api.Unit, request.UnitID)
	if err != nil {
		return sshUnitError(err), nil
	}
	return api.SSHUnit200JSONResponse{Message: message}, nil
}
func (s *Server) SSHMachine(ctx context.Context, request api.SSHMachineRequestObject) (api.SSHMachineResponseObject, error) {
	message, err := s.service.SSH(ctx, actor(ctx), api.Machine, request.MachineID)
	if err != nil {
		return sshMachineError(err), nil
	}
	return api.SSHMachine200JSONResponse{Message: message}, nil
}

func is(err, target error) bool { return errors.Is(err, target) }
func listUsersError(err error) api.ListUsersResponseObject {
	if is(err, service.ErrForbidden) {
		return api.ListUsers403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	return nil
}
func createUserError(err error) api.CreateUserResponseObject {
	if is(err, service.ErrForbidden) {
		return api.CreateUser403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	if is(err, store.ErrConflict) {
		return api.CreateUser409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(problem("conflict", err))}
	}
	return api.CreateUser400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", err))}
}
func listGroupsError(err error) api.ListGroupsResponseObject {
	if is(err, service.ErrForbidden) {
		return api.ListGroups403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	return nil
}
func createGroupError(err error) api.CreateGroupResponseObject {
	if is(err, service.ErrForbidden) {
		return api.CreateGroup403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	if is(err, store.ErrConflict) {
		return api.CreateGroup409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(problem("conflict", err))}
	}
	return api.CreateGroup400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", err))}
}
func addGroupMemberError(err error) api.AddGroupMemberResponseObject {
	if is(err, service.ErrForbidden) {
		return api.AddGroupMember403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	if is(err, store.ErrNotFound) {
		return api.AddGroupMember404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(problem("not_found", err))}
	}
	return api.AddGroupMember400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", err))}
}
func removeGroupMemberError(err error) api.RemoveGroupMemberResponseObject {
	if is(err, service.ErrForbidden) {
		return api.RemoveGroupMember403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	if is(err, store.ErrNotFound) {
		return api.RemoveGroupMember404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(problem("not_found", err))}
	}
	return api.RemoveGroupMember400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", err))}
}
func listRolesError(err error) api.ListRolesResponseObject {
	if is(err, service.ErrForbidden) {
		return api.ListRoles403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	return nil
}
func createRoleError(err error) api.CreateRoleResponseObject {
	if is(err, service.ErrForbidden) {
		return api.CreateRole403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	if is(err, store.ErrConflict) {
		return api.CreateRole409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(problem("conflict", err))}
	}
	return api.CreateRole400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", err))}
}
func getRoleError(err error) api.GetRoleResponseObject {
	if is(err, service.ErrForbidden) {
		return api.GetRole403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	return api.GetRole404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(problem("not_found", err))}
}
func previewRoleError(err error) api.PreviewRoleUpdateResponseObject {
	if is(err, service.ErrForbidden) {
		return api.PreviewRoleUpdate403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	if is(err, store.ErrNotFound) {
		return api.PreviewRoleUpdate404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(problem("not_found", err))}
	}
	if is(err, store.ErrConflict) {
		return api.PreviewRoleUpdate409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(problem("conflict", err))}
	}
	return api.PreviewRoleUpdate400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", err))}
}
func updateRoleError(err error) api.UpdateRoleResponseObject {
	if is(err, service.ErrForbidden) {
		return api.UpdateRole403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	if is(err, store.ErrNotFound) {
		return api.UpdateRole404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(problem("not_found", err))}
	}
	if is(err, store.ErrConflict) {
		return api.UpdateRole409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(problem("conflict", err))}
	}
	return api.UpdateRole400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", err))}
}
func listBindingsError(err error) api.ListBindingsResponseObject {
	if is(err, service.ErrForbidden) {
		return api.ListBindings403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	return nil
}
func createBindingError(err error) api.CreateBindingResponseObject {
	if is(err, service.ErrForbidden) {
		return api.CreateBinding403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	if is(err, store.ErrNotFound) {
		return api.CreateBinding404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(problem("not_found", err))}
	}
	if is(err, store.ErrConflict) {
		return api.CreateBinding409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(problem("conflict", err))}
	}
	return api.CreateBinding400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", err))}
}
func deleteBindingError(err error) api.DeleteBindingResponseObject {
	if is(err, service.ErrForbidden) {
		return api.DeleteBinding403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	return api.DeleteBinding404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(problem("not_found", err))}
}
func grantLegacyError(err error) api.GrantLegacyAccessResponseObject {
	if is(err, service.ErrForbidden) {
		return api.GrantLegacyAccess403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	if is(err, store.ErrNotFound) {
		return api.GrantLegacyAccess404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(problem("not_found", err))}
	}
	return api.GrantLegacyAccess400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", err))}
}
func revokeLegacyError(err error) api.RevokeLegacyAccessResponseObject {
	if is(err, service.ErrForbidden) {
		return api.RevokeLegacyAccess403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	if is(err, store.ErrNotFound) {
		return api.RevokeLegacyAccess404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(problem("not_found", err))}
	}
	return api.RevokeLegacyAccess400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", err))}
}
func createResourceError(err error) api.CreateResourceResponseObject {
	if is(err, service.ErrForbidden) {
		return api.CreateResource403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	if is(err, store.ErrNotFound) {
		return api.CreateResource404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(problem("not_found", err))}
	}
	if is(err, store.ErrConflict) {
		return api.CreateResource409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(problem("conflict", err))}
	}
	return api.CreateResource400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(problem("bad_request", err))}
}
func getResourceError(err error) api.GetResourceResponseObject {
	if is(err, service.ErrForbidden) {
		return api.GetResource403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	return api.GetResource404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(problem("not_found", err))}
}
func deleteResourceError(err error) api.DeleteResourceResponseObject {
	if is(err, service.ErrForbidden) {
		return api.DeleteResource403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	if is(err, store.ErrConflict) {
		return api.DeleteResource409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(problem("conflict", err))}
	}
	return api.DeleteResource404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(problem("not_found", err))}
}
func getConfigError(err error) api.GetApplicationConfigResponseObject {
	if is(err, service.ErrForbidden) {
		return api.GetApplicationConfig403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	return api.GetApplicationConfig404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(problem("not_found", err))}
}
func updateConfigError(err error) api.UpdateApplicationConfigResponseObject {
	if is(err, service.ErrForbidden) {
		return api.UpdateApplicationConfig403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	return api.UpdateApplicationConfig404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(problem("not_found", err))}
}
func sshUnitError(err error) api.SSHUnitResponseObject {
	if is(err, service.ErrForbidden) {
		return api.SSHUnit403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	return api.SSHUnit404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(problem("not_found", err))}
}
func sshMachineError(err error) api.SSHMachineResponseObject {
	if is(err, service.ErrForbidden) {
		return api.SSHMachine403JSONResponse{ForbiddenJSONResponse: api.ForbiddenJSONResponse(problem("forbidden", err))}
	}
	return api.SSHMachine404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(problem("not_found", err))}
}
