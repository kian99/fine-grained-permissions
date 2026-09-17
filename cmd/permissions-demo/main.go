package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/juju/juju/permissions-demo/api"
)

func main() {
	global := flag.NewFlagSet("permissions-demo", flag.ExitOnError)
	as := global.String("as", "admin", "demo user identity")
	server := global.String("server", env("PERMISSIONS_DEMO_URL", "http://localhost:8088/v1"), "server URL")
	global.Usage = usage
	_ = global.Parse(os.Args[1:])
	args := global.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}
	client, err := api.NewClientWithResponses(*server, api.WithHTTPClient(httpClient), api.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
		req.Header.Set("X-Demo-User", *as)
		return nil
	}))
	fatal(err)
	fatal(run(context.Background(), client, args))
}

func run(ctx context.Context, client *api.ClientWithResponses, args []string) error {
	switch args[0] {
	case "permissions":
		response, err := client.ListPermissionsWithResponse(ctx)
		return printResponse(response, err)
	case "users":
		if len(args) == 1 || args[1] == "list" {
			response, err := client.ListUsersWithResponse(ctx)
			return printResponse(response, err)
		}
		if len(args) == 3 && args[1] == "create" {
			response, err := client.CreateUserWithResponse(ctx, api.CreateUser{Name: args[2]})
			return printResponse(response, err)
		}
	case "groups":
		if len(args) == 1 || args[1] == "list" {
			response, err := client.ListGroupsWithResponse(ctx)
			return printResponse(response, err)
		}
		if len(args) == 3 && args[1] == "create" {
			response, err := client.CreateGroupWithResponse(ctx, api.CreateGroup{Name: args[2]})
			return printResponse(response, err)
		}
		if len(args) == 4 && (args[1] == "add-member" || args[1] == "remove-member") {
			body := api.GroupMemberChange{UserID: args[3]}
			if args[1] == "add-member" {
				response, err := client.AddGroupMemberWithResponse(ctx, args[2], body)
				return printResponse(response, err)
			}
			response, err := client.RemoveGroupMemberWithResponse(ctx, args[2], body)
			return printResponse(response, err)
		}
	case "roles":
		if len(args) == 1 || args[1] == "list" {
			response, err := client.ListRolesWithResponse(ctx)
			return printResponse(response, err)
		}
		if len(args) == 3 && args[1] == "show" {
			response, err := client.GetRoleWithResponse(ctx, args[2])
			return printResponse(response, err)
		}
		if len(args) == 5 && args[1] == "create" {
			response, err := client.CreateRoleWithResponse(ctx, api.CreateRole{Name: args[2], Description: args[3], Permissions: csv(args[4])})
			return printResponse(response, err)
		}
		if len(args) == 6 && (args[1] == "preview" || args[1] == "update") {
			revision, err := strconv.Atoi(args[3])
			if err != nil {
				return fmt.Errorf("revision: %w", err)
			}
			body := api.UpdateRole{Description: args[4], Permissions: csv(args[5])}
			if args[1] == "preview" {
				response, err := client.PreviewRoleUpdateWithResponse(ctx, args[2], &api.PreviewRoleUpdateParams{IfMatch: revision}, body)
				return printResponse(response, err)
			}
			response, err := client.UpdateRoleWithResponse(ctx, args[2], &api.UpdateRoleParams{IfMatch: revision}, body)
			return printResponse(response, err)
		}
	case "bindings":
		if len(args) == 1 || args[1] == "list" {
			response, err := client.ListBindingsWithResponse(ctx)
			return printResponse(response, err)
		}
		if len(args) == 3 && args[1] == "delete" {
			response, err := client.DeleteBindingWithResponse(ctx, args[2])
			return printResponse(response, err)
		}
		if len(args) >= 7 && args[1] == "create" {
			scope, err := parseRef(args[5])
			if err != nil {
				return err
			}
			selector := api.Selector{Match: api.SelectorMatch(args[6])}
			if selector.Match == api.Exact {
				refs := make([]api.ResourceRef, 0, len(args)-7)
				for _, raw := range args[7:] {
					ref, err := parseRef(raw)
					if err != nil {
						return err
					}
					refs = append(refs, ref)
				}
				selector.Resources = &refs
			}
			response, err := client.CreateBindingWithResponse(ctx, api.CreateBinding{SubjectType: api.SubjectType(args[2]), SubjectID: args[3], RoleID: args[4], Scope: scope, Selector: selector})
			return printResponse(response, err)
		}
	case "grant", "revoke":
		if len(args) == 4 {
			access := api.LegacyAccessLevel(args[2])
			body := api.LegacyAccessChange{UserID: args[1], Access: access, ModelID: args[3]}
			if args[0] == "grant" {
				response, err := client.GrantLegacyAccessWithResponse(ctx, body)
				return printResponse(response, err)
			}
			response, err := client.RevokeLegacyAccessWithResponse(ctx, body)
			return printResponse(response, err)
		}
	case "can":
		if len(args) == 4 {
			ref, err := parseRef(args[3])
			if err != nil {
				return err
			}
			response, err := client.CheckAuthorizationWithResponse(ctx, api.AuthorizationCheck{Principal: args[1], Permission: args[2], Resource: ref})
			return printResponse(response, err)
		}
	case "resources":
		if len(args) == 1 || args[1] == "list" {
			var params api.ListResourcesParams
			if len(args) == 3 {
				typ := api.ResourceType(args[2])
				params.Type = &typ
			}
			response, err := client.ListResourcesWithResponse(ctx, &params)
			return printResponse(response, err)
		}
		if len(args) >= 4 && args[1] == "create" {
			input := api.CreateResource{Type: api.ResourceType(args[2]), Name: args[3]}
			if len(args) == 5 {
				parent, err := parseRef(args[4])
				if err != nil {
					return err
				}
				input.Parent = &parent
			}
			response, err := client.CreateResourceWithResponse(ctx, input)
			return printResponse(response, err)
		}
		if len(args) == 4 && args[1] == "delete" {
			response, err := client.DeleteResourceWithResponse(ctx, api.ResourceType(args[2]), args[3])
			return printResponse(response, err)
		}
	case "config":
		if len(args) == 3 && args[1] == "get" {
			response, err := client.GetApplicationConfigWithResponse(ctx, args[2])
			return printResponse(response, err)
		}
		if len(args) >= 4 && args[1] == "set" {
			config := api.ApplicationConfig{}
			for _, pair := range args[3:] {
				parts := strings.SplitN(pair, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("config must be key=value")
				}
				config[parts[0]] = parts[1]
			}
			response, err := client.UpdateApplicationConfigWithResponse(ctx, args[2], config)
			return printResponse(response, err)
		}
	case "ssh":
		if len(args) == 3 && args[1] == "unit" {
			response, err := client.SSHUnitWithResponse(ctx, args[2])
			return printResponse(response, err)
		}
		if len(args) == 3 && args[1] == "machine" {
			response, err := client.SSHMachineWithResponse(ctx, args[2])
			return printResponse(response, err)
		}
	}
	usage()
	return errors.New("invalid command")
}

func printResponse(response interface {
	GetBody() []byte
	Status() string
	StatusCode() int
}, err error) error {
	if err != nil {
		return err
	}
	if response.StatusCode() >= 400 {
		return fmt.Errorf("%s: %s", response.Status(), strings.TrimSpace(string(response.GetBody())))
	}
	if len(response.GetBody()) == 0 {
		fmt.Println("ok")
		return nil
	}
	var value any
	if err := json.Unmarshal(response.GetBody(), &value); err != nil {
		return err
	}
	formatted, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(formatted))
	return nil
}
func parseRef(raw string) (api.ResourceRef, error) {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 || parts[1] == "" {
		return api.ResourceRef{}, fmt.Errorf("resource must be TYPE:ID")
	}
	typ := api.ResourceType(parts[0])
	if !typ.Valid() {
		return api.ResourceRef{}, fmt.Errorf("unknown resource type %q", parts[0])
	}
	return api.ResourceRef{Type: typ, ID: parts[1]}, nil
}
func csv(raw string) []string {
	var result []string
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}
func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
func usage() {
	fmt.Fprintln(os.Stderr, `Usage: permissions-demo [--as USER] [--server URL] COMMAND

  permissions
  users list | users create NAME
  groups list | groups create NAME
  groups add-member GROUP USER | groups remove-member GROUP USER
  roles list | roles show ROLE
  roles create NAME DESCRIPTION PERMISSION[,PERMISSION...]
  roles preview ROLE REVISION DESCRIPTION PERMISSION[,PERMISSION...]
  roles update ROLE REVISION DESCRIPTION PERMISSION[,PERMISSION...]
  bindings list | bindings delete ID
  bindings create user|group SUBJECT ROLE SCOPE scope
  bindings create user|group SUBJECT ROLE SCOPE exact RESOURCE [RESOURCE...]
  grant USER read|write|admin MODEL-ID
  revoke USER read|write|admin MODEL-ID
  can USER PERMISSION TYPE:ID
  resources list [TYPE]
  resources create TYPE NAME [PARENT-TYPE:PARENT-ID]
  resources delete TYPE ID
  config get APPLICATION-ID | config set APPLICATION-ID KEY=VALUE [...]
  ssh unit UNIT-ID | ssh machine MACHINE-ID`)
}
