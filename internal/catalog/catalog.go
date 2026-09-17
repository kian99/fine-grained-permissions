package catalog

import (
	"fmt"
	"sort"
	"strings"

	"github.com/juju/juju/permissions-demo/api"
)

const (
	ControllerID = "juju"

	PolicyRead   = "policy.read"
	PolicyManage = "policy.manage"

	ModelRead   = "model.read"
	ModelCreate = "model.create"
	ModelDelete = "model.delete"

	ApplicationRead        = "application.read"
	ApplicationCreate      = "application.create"
	ApplicationDelete      = "application.delete"
	ApplicationConfigRead  = "application.config.read"
	ApplicationConfigWrite = "application.config.write"

	UnitRead   = "unit.read"
	UnitCreate = "unit.create"
	UnitDelete = "unit.delete"
	UnitSSH    = "unit.ssh"

	MachineRead   = "machine.read"
	MachineCreate = "machine.create"
	MachineDelete = "machine.delete"
	MachineSSH    = "machine.ssh"

	CloudCredentialRead   = "cloud-credential.read"
	CloudCredentialCreate = "cloud-credential.create"
	CloudCredentialDelete = "cloud-credential.delete"
)

var permissions = []api.Permission{
	{Name: PolicyRead, ResourceTypes: []api.ResourceType{api.Controller, api.Model}, Description: "Inspect roles, groups and bindings."},
	{Name: PolicyManage, ResourceTypes: []api.ResourceType{api.Controller, api.Model}, Description: "Manage roles, groups and bindings."},
	{Name: ModelRead, ResourceTypes: []api.ResourceType{api.Model}, Description: "Read model status and metadata."},
	{Name: ModelCreate, ResourceTypes: []api.ResourceType{api.Controller}, Description: "Create a model under the controller."},
	{Name: ModelDelete, ResourceTypes: []api.ResourceType{api.Model}, Description: "Delete a model."},
	{Name: ApplicationRead, ResourceTypes: []api.ResourceType{api.Application}, Description: "Read application status and metadata."},
	{Name: ApplicationCreate, ResourceTypes: []api.ResourceType{api.Model}, Description: "Create an application in a model."},
	{Name: ApplicationDelete, ResourceTypes: []api.ResourceType{api.Application}, Description: "Delete an application."},
	{Name: ApplicationConfigRead, ResourceTypes: []api.ResourceType{api.Application}, Description: "Read application configuration."},
	{Name: ApplicationConfigWrite, ResourceTypes: []api.ResourceType{api.Application}, Description: "Update application configuration."},
	{Name: UnitRead, ResourceTypes: []api.ResourceType{api.Unit}, Description: "Read unit status and metadata."},
	{Name: UnitCreate, ResourceTypes: []api.ResourceType{api.Application}, Description: "Create a unit under an application."},
	{Name: UnitDelete, ResourceTypes: []api.ResourceType{api.Unit}, Description: "Delete a unit."},
	{Name: UnitSSH, ResourceTypes: []api.ResourceType{api.Unit}, Description: "Open a simulated SSH session to a unit."},
	{Name: MachineRead, ResourceTypes: []api.ResourceType{api.Machine}, Description: "Read machine status and metadata."},
	{Name: MachineCreate, ResourceTypes: []api.ResourceType{api.Model, api.Application}, Description: "Create a machine under a model or application."},
	{Name: MachineDelete, ResourceTypes: []api.ResourceType{api.Machine}, Description: "Delete a machine."},
	{Name: MachineSSH, ResourceTypes: []api.ResourceType{api.Machine}, Description: "Open a simulated SSH session to a machine."},
	{Name: CloudCredentialRead, ResourceTypes: []api.ResourceType{api.CloudCredential}, Description: "Read cloud credential metadata."},
	{Name: CloudCredentialCreate, ResourceTypes: []api.ResourceType{api.Controller}, Description: "Create a cloud credential."},
	{Name: CloudCredentialDelete, ResourceTypes: []api.ResourceType{api.CloudCredential}, Description: "Delete a cloud credential."},
}

var relationByPermission = map[string]string{
	PolicyRead: "policy_read", PolicyManage: "policy_manage",
	ModelRead: "read", ModelCreate: "model_create", ModelDelete: "delete",
	ApplicationRead: "read", ApplicationCreate: "application_create", ApplicationDelete: "delete",
	ApplicationConfigRead: "config_read", ApplicationConfigWrite: "config_write",
	UnitRead: "read", UnitCreate: "unit_create", UnitDelete: "delete", UnitSSH: "ssh",
	MachineRead: "read", MachineCreate: "machine_create", MachineDelete: "delete", MachineSSH: "ssh",
	CloudCredentialRead: "read", CloudCredentialCreate: "cloud_credential_create", CloudCredentialDelete: "delete",
}

func Permissions() []api.Permission {
	result := append([]api.Permission(nil), permissions...)
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func Permission(name string) (api.Permission, bool) {
	for _, permission := range permissions {
		if permission.Name == name {
			return permission, true
		}
	}
	return api.Permission{}, false
}

func Relation(permission string) (string, error) {
	relation, ok := relationByPermission[permission]
	if !ok {
		return "", fmt.Errorf("unknown permission %q", permission)
	}
	return relation, nil
}

func Supports(permission string, resourceType api.ResourceType) bool {
	item, ok := Permission(permission)
	if !ok {
		return false
	}
	for _, supported := range item.ResourceTypes {
		if supported == resourceType {
			return true
		}
	}
	return false
}

func ResourceObject(ref api.ResourceRef) string {
	return OpenFGAType(ref.Type) + ":" + ref.ID
}

func OpenFGAType(resourceType api.ResourceType) string {
	return strings.ReplaceAll(string(resourceType), "-", "_")
}

func ParentRule(resourceType api.ResourceType) []api.ResourceType {
	switch resourceType {
	case api.Model, api.CloudCredential:
		return []api.ResourceType{api.Controller}
	case api.Application:
		return []api.ResourceType{api.Model}
	case api.Unit:
		return []api.ResourceType{api.Application}
	case api.Machine:
		return []api.ResourceType{api.Model, api.Application}
	default:
		return nil
	}
}

func CreatePermission(resourceType api.ResourceType) (string, bool) {
	switch resourceType {
	case api.Model:
		return ModelCreate, true
	case api.Application:
		return ApplicationCreate, true
	case api.Unit:
		return UnitCreate, true
	case api.Machine:
		return MachineCreate, true
	case api.CloudCredential:
		return CloudCredentialCreate, true
	default:
		return "", false
	}
}

func ReadPermission(resourceType api.ResourceType) (string, bool) {
	switch resourceType {
	case api.Model:
		return ModelRead, true
	case api.Application:
		return ApplicationRead, true
	case api.Unit:
		return UnitRead, true
	case api.Machine:
		return MachineRead, true
	case api.CloudCredential:
		return CloudCredentialRead, true
	default:
		return "", false
	}
}

func DeletePermission(resourceType api.ResourceType) (string, bool) {
	switch resourceType {
	case api.Model:
		return ModelDelete, true
	case api.Application:
		return ApplicationDelete, true
	case api.Unit:
		return UnitDelete, true
	case api.Machine:
		return MachineDelete, true
	case api.CloudCredential:
		return CloudCredentialDelete, true
	default:
		return "", false
	}
}
