package store_test

import (
	"reflect"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/store"
)

func TestAdministrativeRoleModelNullableScope(t *testing.T) {
	db, _ := fixture(t)
	principals(t, db)
	local, err := store.New(db).GetLocalEndpoint(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	exec(t, db, `INSERT INTO administrative_roles(id,user_id,role) VALUES ('global','u1','super_admin')`)
	exec(t, db, `INSERT INTO administrative_roles(id,user_id,role,endpoint_id) VALUES ('scoped','u2','endpoint_admin',?)`, local.ID)
	for _, tc := range []struct {
		id       string
		endpoint *domain.EndpointID
	}{
		{id: "global"},
		{id: "scoped", endpoint: &local.ID},
	} {
		t.Run(tc.id, func(t *testing.T) {
			var role store.AdministrativeRole
			err := db.QueryRowContext(t.Context(), `SELECT id,user_id,role,endpoint_id,state,authority_generation FROM administrative_roles WHERE id=?`, tc.id).Scan(
				&role.ID, &role.UserID, &role.Role, &role.EndpointID, &role.State, &role.AuthorityGeneration)
			if err != nil {
				t.Fatalf("generated role model cannot scan SQL scope: %v", err)
			}
			if !reflect.DeepEqual(role.EndpointID, tc.endpoint) || role.State != "quarantined" || role.AuthorityGeneration != 0 {
				t.Fatal("generated role model lost nullable scope or inactive defaults")
			}
			// Round-trip the actual generated field through database/sql binding.
			exec(t, db, `UPDATE administrative_roles SET endpoint_id=? WHERE id=?`, role.EndpointID, tc.id)
		})
	}
	rejects(t, db, `UPDATE administrative_roles SET endpoint_id=? WHERE id='global'`, local.ID)
	rejects(t, db, `UPDATE administrative_roles SET endpoint_id=NULL WHERE id='scoped'`)
	rejects(t, db, `UPDATE administrative_roles SET state='active',authority_generation=1 WHERE id='scoped'`)
	exec(t, db, `UPDATE administrative_roles SET state='active',authority_generation=1 WHERE id='global'`)
	rejects(t, db, `INSERT INTO administrative_roles(id,user_id,role,state,authority_generation) VALUES ('second','u2','super_admin','active',1)`)
}
