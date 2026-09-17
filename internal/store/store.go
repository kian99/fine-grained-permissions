package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"github.com/juju/juju/permissions-demo/api"
	"github.com/juju/juju/permissions-demo/internal/catalog"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

type Store struct {
	db *sql.DB
}

func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if err := store.init(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) init(ctx context.Context) error {
	const schema = `
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS synced_tuples (
	tuple_key TEXT PRIMARY KEY, user TEXT NOT NULL, relation TEXT NOT NULL, object TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS groups (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS group_members (group_id TEXT NOT NULL, user_id TEXT NOT NULL,
  PRIMARY KEY (group_id, user_id), FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS roles (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL, revision INTEGER NOT NULL, built_in INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS role_permissions (role_id TEXT NOT NULL, permission TEXT NOT NULL,
  PRIMARY KEY (role_id, permission), FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS bindings (id TEXT PRIMARY KEY, subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL, role_id TEXT NOT NULL, scope_type TEXT NOT NULL, scope_id TEXT NOT NULL,
  selector_match TEXT NOT NULL, selector_resources TEXT NOT NULL, compatibility INTEGER NOT NULL,
  UNIQUE (subject_type, subject_id, role_id, scope_type, scope_id, compatibility),
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS resources (type TEXT NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL,
  status TEXT NOT NULL, parent_type TEXT, parent_id TEXT, config TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY (type, id), UNIQUE (type, name));
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL,
  action TEXT NOT NULL, object TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("initialize sqlite schema: %w", err)
	}
	return s.seed(ctx)
}

func (s *Store) seed(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO users(id, name) VALUES ('admin', 'admin')`)
	if err != nil {
		return err
	}
	roles := []struct {
		id, name, description string
		permissions           []string
	}{
		{"controller-superuser", "controller-superuser", "All demo administration and resource operations.", permissionNames()},
		{"model-reader", "model-reader", "Legacy model read compatibility role.", []string{catalog.ModelRead, catalog.ApplicationRead, catalog.UnitRead, catalog.MachineRead}},
		{"model-writer", "model-writer", "Legacy model write compatibility role.", []string{catalog.ModelRead, catalog.ApplicationRead, catalog.ApplicationCreate, catalog.ApplicationDelete, catalog.ApplicationConfigRead, catalog.ApplicationConfigWrite, catalog.UnitRead, catalog.UnitCreate, catalog.UnitDelete, catalog.MachineRead, catalog.MachineCreate, catalog.MachineDelete}},
		{"model-admin", "model-admin", "Legacy model admin compatibility role.", []string{catalog.ModelRead, catalog.ModelDelete, catalog.ApplicationRead, catalog.ApplicationCreate, catalog.ApplicationDelete, catalog.ApplicationConfigRead, catalog.ApplicationConfigWrite, catalog.UnitRead, catalog.UnitCreate, catalog.UnitDelete, catalog.UnitSSH, catalog.MachineRead, catalog.MachineCreate, catalog.MachineDelete, catalog.MachineSSH, catalog.PolicyRead, catalog.PolicyManage}},
		{"application-observer", "application-observer", "Read selected applications and their descendants.", []string{catalog.ApplicationRead, catalog.UnitRead, catalog.MachineRead}},
		{"application-config-editor", "application-config-editor", "Read and update selected application configuration.", []string{catalog.ApplicationRead, catalog.ApplicationConfigRead, catalog.ApplicationConfigWrite}},
		{"ssh-operator", "ssh-operator", "Read and SSH to selected units or machines.", []string{catalog.UnitRead, catalog.UnitSSH, catalog.MachineRead, catalog.MachineSSH}},
	}
	for _, role := range roles {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO roles(id,name,description,revision,built_in) VALUES(?,?,?,1,1)`, role.id, role.name, role.description); err != nil {
			return err
		}
		for _, permission := range role.permissions {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO role_permissions(role_id,permission) VALUES(?,?)`, role.id, permission); err != nil {
				return err
			}
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO bindings(id,subject_type,subject_id,role_id,scope_type,scope_id,selector_match,selector_resources,compatibility) VALUES('bootstrap-admin','user','admin','controller-superuser','controller',?,'scope','[]',1)`, catalog.ControllerID)
	if err != nil {
		return err
	}
	resources := []struct{ typ, id, name, parentType, parentID string }{
		{"model", "production", "production", "controller", catalog.ControllerID},
		{"application", "payments", "payments", "model", "production"},
		{"unit", "payments-0", "payments/0", "application", "payments"},
		{"machine", "model-0", "0", "model", "production"},
		{"machine", "payments-machine", "payments-machine", "application", "payments"},
		{"cloud-credential", "aws-production", "aws-production", "controller", catalog.ControllerID},
	}
	for _, resource := range resources {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO resources(type,id,name,status,parent_type,parent_id,config) VALUES(?,?,?,'active',?,?, '{}')`,
			resource.typ, resource.id, resource.name, resource.parentType, resource.parentID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func permissionNames() []string {
	items := catalog.Permissions()
	result := make([]string, len(items))
	for i := range items {
		result[i] = items[i].Name
	}
	return result
}

func (s *Store) Setting(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return value, err == nil, err
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *Store) ListSyncedTuples(ctx context.Context, prefix string) ([][3]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT user,relation,object FROM synced_tuples WHERE tuple_key LIKE ? ORDER BY tuple_key`, prefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result [][3]string
	for rows.Next() {
		var item [3]string
		if err := rows.Scan(&item[0], &item[1], &item[2]); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) ReplaceSyncedTuples(ctx context.Context, prefix string, tuples [][3]string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM synced_tuples WHERE tuple_key LIKE ?`, prefix+"%"); err != nil {
		return err
	}
	for _, tuple := range tuples {
		key := prefix + tuple[0] + "|" + tuple[1] + "|" + tuple[2]
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO synced_tuples(tuple_key,user,relation,object) VALUES(?,?,?,?)`,
			key, tuple[0], tuple[1], tuple[2]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) CreateUser(ctx context.Context, name string) (api.User, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return api.User{}, fmt.Errorf("name is required")
	}
	item := api.User{ID: slug(name), Name: name}
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(id,name) VALUES(?,?)`, item.ID, item.Name)
	if isUniqueError(err) {
		return api.User{}, ErrConflict
	}
	return item, err
}

func (s *Store) ListUsers(ctx context.Context) ([]api.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []api.User
	for rows.Next() {
		var item api.User
		if err := rows.Scan(&item.ID, &item.Name); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) UserExists(ctx context.Context, id string) (bool, error) {
	return exists(ctx, s.db, `SELECT 1 FROM users WHERE id=?`, id)
}

func (s *Store) CreateGroup(ctx context.Context, name string) (api.Group, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return api.Group{}, fmt.Errorf("name is required")
	}
	item := api.Group{ID: slug(name), Name: name, Members: []string{}}
	_, err := s.db.ExecContext(ctx, `INSERT INTO groups(id,name) VALUES(?,?)`, item.ID, item.Name)
	if isUniqueError(err) {
		return api.Group{}, ErrConflict
	}
	return item, err
}

func (s *Store) ListGroups(ctx context.Context) ([]api.Group, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var result []api.Group
	for rows.Next() {
		var item api.Group
		if err := rows.Scan(&item.ID, &item.Name); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range result {
		members, err := s.groupMembers(ctx, result[i].ID)
		if err != nil {
			return nil, err
		}
		result[i].Members = members
	}
	return result, nil
}

func (s *Store) groupMembers(ctx context.Context, id string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT user_id FROM group_members WHERE group_id=? ORDER BY user_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func (s *Store) GroupExists(ctx context.Context, id string) (bool, error) {
	return exists(ctx, s.db, `SELECT 1 FROM groups WHERE id=?`, id)
}
func (s *Store) AddGroupMember(ctx context.Context, groupID, userID string) error {
	if ok, _ := s.GroupExists(ctx, groupID); !ok {
		return ErrNotFound
	}
	if ok, _ := s.UserExists(ctx, userID); !ok {
		return ErrNotFound
	}
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO group_members(group_id,user_id) VALUES(?,?)`, groupID, userID)
	return err
}
func (s *Store) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM group_members WHERE group_id=? AND user_id=?`, groupID, userID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListMemberships(ctx context.Context) ([][2]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT group_id,user_id FROM group_members ORDER BY group_id,user_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result [][2]string
	for rows.Next() {
		var item [2]string
		if err := rows.Scan(&item[0], &item[1]); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) CreateRole(ctx context.Context, input api.CreateRole) (api.Role, error) {
	id := slug(input.Name)
	if id == "" {
		return api.Role{}, fmt.Errorf("name is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return api.Role{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO roles(id,name,description,revision,built_in) VALUES(?,?,?,1,0)`, id, input.Name, input.Description)
	if isUniqueError(err) {
		return api.Role{}, ErrConflict
	}
	if err != nil {
		return api.Role{}, err
	}
	if err = replacePermissions(ctx, tx, id, input.Permissions); err != nil {
		return api.Role{}, err
	}
	if err = tx.Commit(); err != nil {
		return api.Role{}, err
	}
	return s.GetRole(ctx, id)
}

func (s *Store) GetRole(ctx context.Context, id string) (api.Role, error) {
	var item api.Role
	var builtIn int
	err := s.db.QueryRowContext(ctx, `SELECT id,name,description,revision,built_in FROM roles WHERE id=?`, id).Scan(&item.ID, &item.Name, &item.Description, &item.Revision, &builtIn)
	if errors.Is(err, sql.ErrNoRows) {
		return api.Role{}, ErrNotFound
	}
	if err != nil {
		return api.Role{}, err
	}
	item.BuiltIn = builtIn != 0
	rows, err := s.db.QueryContext(ctx, `SELECT permission FROM role_permissions WHERE role_id=? ORDER BY permission`, id)
	if err != nil {
		return api.Role{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return api.Role{}, err
		}
		item.Permissions = append(item.Permissions, p)
	}
	return item, rows.Err()
}

func (s *Store) ListRoles(ctx context.Context) ([]api.Role, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM roles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	var result []api.Role
	for _, id := range ids {
		item, err := s.GetRole(ctx, id)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) UpdateRole(ctx context.Context, actor, id string, expected int, input api.UpdateRole) (api.Role, error) {
	current, err := s.GetRole(ctx, id)
	if err != nil {
		return api.Role{}, err
	}
	if current.BuiltIn {
		return api.Role{}, fmt.Errorf("built-in roles cannot be changed")
	}
	if current.Revision != expected {
		return api.Role{}, ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return api.Role{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE roles SET description=?,revision=revision+1 WHERE id=? AND revision=?`, input.Description, id, expected)
	if err != nil {
		return api.Role{}, err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return api.Role{}, ErrConflict
	}
	if err = replacePermissions(ctx, tx, id, input.Permissions); err != nil {
		return api.Role{}, err
	}
	detail, _ := json.Marshal(map[string]any{"old": current.Permissions, "new": input.Permissions, "revision": expected + 1})
	_, err = tx.ExecContext(ctx, `INSERT INTO audit(actor,action,object,detail,created_at) VALUES(?,?,?,?,?)`, actor, "role.update", id, string(detail), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return api.Role{}, err
	}
	if err = tx.Commit(); err != nil {
		return api.Role{}, err
	}
	return s.GetRole(ctx, id)
}

func replacePermissions(ctx context.Context, tx *sql.Tx, id string, permissions []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM role_permissions WHERE role_id=?`, id); err != nil {
		return err
	}
	for _, p := range unique(permissions) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO role_permissions(role_id,permission) VALUES(?,?)`, id, p); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) CountBindings(ctx context.Context, roleID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM bindings WHERE role_id=?`, roleID).Scan(&count)
	return count, err
}

func (s *Store) CreateBinding(ctx context.Context, input api.CreateBinding, compatibility bool) (api.Binding, error) {
	item := api.Binding{ID: uuid.NewString(), SubjectType: input.SubjectType, SubjectID: input.SubjectID, RoleID: input.RoleID, Scope: input.Scope, Selector: input.Selector, Compatibility: compatibility}
	data, _ := json.Marshal(input.Selector.Resources)
	_, err := s.db.ExecContext(ctx, `INSERT INTO bindings(id,subject_type,subject_id,role_id,scope_type,scope_id,selector_match,selector_resources,compatibility) VALUES(?,?,?,?,?,?,?,?,?)`, item.ID, item.SubjectType, item.SubjectID, item.RoleID, item.Scope.Type, item.Scope.ID, item.Selector.Match, string(data), boolInt(compatibility))
	if isUniqueError(err) {
		return api.Binding{}, ErrConflict
	}
	return item, err
}

func (s *Store) UpsertCompatibilityBinding(ctx context.Context, userID, roleID, modelID string) (api.Binding, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return api.Binding{}, err
	}
	defer tx.Rollback()
	var id string
	err = tx.QueryRowContext(ctx, `SELECT id FROM bindings WHERE subject_type='user' AND subject_id=? AND scope_type='model' AND scope_id=? AND compatibility=1`, userID, modelID).Scan(&id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return api.Binding{}, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		id = uuid.NewString()
		_, err = tx.ExecContext(ctx, `INSERT INTO bindings(id,subject_type,subject_id,role_id,scope_type,scope_id,selector_match,selector_resources,compatibility) VALUES(?,'user',?,?, 'model',?,'scope','[]',1)`, id, userID, roleID, modelID)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE bindings SET role_id=? WHERE id=?`, roleID, id)
	}
	if err != nil {
		return api.Binding{}, err
	}
	if err = tx.Commit(); err != nil {
		return api.Binding{}, err
	}
	return s.GetBinding(ctx, id)
}

func (s *Store) GetCompatibilityBinding(ctx context.Context, userID, modelID string) (api.Binding, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM bindings WHERE subject_type='user' AND subject_id=? AND scope_type='model' AND scope_id=? AND compatibility=1`, userID, modelID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return api.Binding{}, ErrNotFound
	}
	if err != nil {
		return api.Binding{}, err
	}
	return s.GetBinding(ctx, id)
}
func (s *Store) GetBinding(ctx context.Context, id string) (api.Binding, error) {
	var item api.Binding
	var data string
	var compatibility int
	err := s.db.QueryRowContext(ctx, `SELECT id,subject_type,subject_id,role_id,scope_type,scope_id,selector_match,selector_resources,compatibility FROM bindings WHERE id=?`, id).Scan(&item.ID, &item.SubjectType, &item.SubjectID, &item.RoleID, &item.Scope.Type, &item.Scope.ID, &item.Selector.Match, &data, &compatibility)
	if errors.Is(err, sql.ErrNoRows) {
		return api.Binding{}, ErrNotFound
	}
	if err != nil {
		return api.Binding{}, err
	}
	item.Compatibility = compatibility != 0
	var resources []api.ResourceRef
	if err = json.Unmarshal([]byte(data), &resources); err != nil {
		return api.Binding{}, err
	}
	if len(resources) > 0 {
		item.Selector.Resources = &resources
	}
	return item, nil
}
func (s *Store) ListBindings(ctx context.Context) ([]api.Binding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM bindings ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	var result []api.Binding
	for _, id := range ids {
		item, err := s.GetBinding(ctx, id)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}
func (s *Store) DeleteBinding(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM bindings WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CreateResource(ctx context.Context, input api.CreateResource) (api.Resource, error) {
	item := api.Resource{ID: uuid.NewString(), Type: input.Type, Name: strings.TrimSpace(input.Name), Status: "active", Parent: input.Parent}
	var pt, pi any
	if input.Parent != nil {
		pt = input.Parent.Type
		pi = input.Parent.ID
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO resources(type,id,name,status,parent_type,parent_id,config) VALUES(?,?,?,?,?,?,?)`, item.Type, item.ID, item.Name, item.Status, pt, pi, `{}`)
	if isUniqueError(err) {
		return api.Resource{}, ErrConflict
	}
	return item, err
}
func (s *Store) GetResource(ctx context.Context, typ api.ResourceType, id string) (api.Resource, error) {
	var item api.Resource
	var pt, pi sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT type,id,name,status,parent_type,parent_id FROM resources WHERE type=? AND id=?`, typ, id).Scan(&item.Type, &item.ID, &item.Name, &item.Status, &pt, &pi)
	if errors.Is(err, sql.ErrNoRows) {
		return api.Resource{}, ErrNotFound
	}
	if err != nil {
		return api.Resource{}, err
	}
	if pt.Valid {
		item.Parent = &api.ResourceRef{Type: api.ResourceType(pt.String), ID: pi.String}
	}
	return item, nil
}
func (s *Store) ListResources(ctx context.Context, filter *api.ResourceType) ([]api.Resource, error) {
	query := `SELECT type,id FROM resources`
	var args []any
	if filter != nil {
		query += ` WHERE type=?`
		args = append(args, *filter)
	}
	query += ` ORDER BY type,name`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var refs []api.ResourceRef
	for rows.Next() {
		var ref api.ResourceRef
		if err := rows.Scan(&ref.Type, &ref.ID); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	var result []api.Resource
	for _, ref := range refs {
		item, err := s.GetResource(ctx, ref.Type, ref.ID)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}
func (s *Store) HasChildren(ctx context.Context, ref api.ResourceRef) (bool, error) {
	return exists(ctx, s.db, `SELECT 1 FROM resources WHERE parent_type=? AND parent_id=?`, ref.Type, ref.ID)
}
func (s *Store) DeleteResource(ctx context.Context, ref api.ResourceRef) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM resources WHERE type=? AND id=?`, ref.Type, ref.ID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
func (s *Store) GetApplicationConfig(ctx context.Context, id string) (api.ApplicationConfig, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT config FROM resources WHERE type='application' AND id=?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var config api.ApplicationConfig
	if err = json.Unmarshal([]byte(raw), &config); err != nil {
		return nil, err
	}
	return config, nil
}
func (s *Store) SetApplicationConfig(ctx context.Context, id string, config api.ApplicationConfig) error {
	raw, err := json.Marshal(config)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE resources SET config=? WHERE type='application' AND id=?`, string(raw), id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) BindingPermissions(ctx context.Context, binding api.Binding) ([]string, error) {
	role, err := s.GetRole(ctx, binding.RoleID)
	if err != nil {
		return nil, err
	}
	return role.Permissions, nil
}

func (s *Store) Reset(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM synced_tuples; DELETE FROM bindings; DELETE FROM group_members; DELETE FROM groups; DELETE FROM users; DELETE FROM role_permissions; DELETE FROM roles; DELETE FROM resources; DELETE FROM settings; DELETE FROM audit;`)
	if err != nil {
		return err
	}
	return s.seed(ctx)
}

func exists(ctx context.Context, db *sql.DB, query string, args ...any) (bool, error) {
	var one int
	err := db.QueryRowContext(ctx, query, args...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
func slug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	dash := false
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}
func unique(values []string) []string {
	seen := map[string]struct{}{}
	var result []string
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	sort.Strings(result)
	return result
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func isUniqueError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique")
}
