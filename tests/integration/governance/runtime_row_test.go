// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package governance

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/thunder-id/thunderid/tests/integration/testutils"
)

// RuntimeRowTestSuite checks what the runtime row is and is not built from: an unknown identifier
// allocates nothing, a management read writes nothing, a sign-in seeds a missing row, and a profile
// attribute named like the runtime document governs nothing. It runs under the shipped policy. The
// row itself is read through the runtime database CLI (sqlite3 or psql).
type RuntimeRowTestSuite struct {
	suite.Suite
	users *userFixture
}

func TestRuntimeRowTestSuite(t *testing.T) {
	suite.Run(t, new(RuntimeRowTestSuite))
}

// storedPostSuspensionReason is the reason the runtime document stores on the lock an unsuspend
// leaves; a management read reports it as SUSPENSION_RELEASE_LOCK. A profile planting it must not
// make it reach the runtime row.
const storedPostSuspensionReason = "POST_SUSPENDED"

// runtimeRowSchema carries a profile attribute shaped like the runtime access-state document, so a
// profile can claim a suspension and a lock it does not have.
var runtimeRowSchema = credentialsSchema(map[string]interface{}{
	"accessState": map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"suspend": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"suspendedAt":  stringAttribute,
					"operatorNote": stringAttribute,
				},
			},
			"lock": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"entity": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"unlockAt": stringAttribute,
							"reason":   stringAttribute,
						},
					},
				},
			},
		},
	},
})

func (ts *RuntimeRowTestSuite) SetupSuite() {
	ts.users = newUserFixture(ts.T(), "runtime_row", testutils.UserType{Schema: runtimeRowSchema})
}

// Failed sign-ins for an identifier that names no account allocate no runtime row. Creating an account
// in the same span allocates exactly one, so the count is seen to move with an allocation and with
// nothing else: the package's tests run one at a time, and nothing writes runtime rows in the
// background.
func (ts *RuntimeRowTestSuite) TestAnUnknownIdentifierAllocatesNoRuntimeRow() {
	before := ts.runtimeRowCount("")
	failAuthentication(ts.T(), "username", "no_such_user_"+ts.users.suffix, 6)
	ts.users.newUser(ts.T(), "allocation_control", nil)
	ts.Equal(before+1, ts.runtimeRowCount(""),
		"only the account created alongside the failures may have allocated a runtime row")
}

// A management read of an identity with no runtime row reports the starting
// state and writes nothing; the governance read behind a sign-in seeds the row.
func (ts *RuntimeRowTestSuite) TestAManagementReadWritesNothingAndASignInSeedsTheRow() {
	userID, username, password := ts.users.newUser(ts.T(), "seed", nil)
	ts.Require().Equal(1, ts.runtimeRowCount(userID), "creating an identity must create its runtime row")
	ts.Require().NoError(testutils.DeleteRuntimeRow(userID))

	ts.Equal("ACTIVE", readStatus(ts.T(), userID).Value, "a missing row must read as the starting state")
	getManagement(ts.T(), "/users?limit=100")
	ts.Equal(0, ts.runtimeRowCount(userID), "management reads must write nothing")

	ts.Require().True(authenticate(ts.T(), "username", username, password).succeeded(),
		"a sign-in must be admitted on a missing row")
	ts.Equal(1, ts.runtimeRowCount(userID), "the governance read behind a sign-in must seed the row")
	ts.Equal("ACTIVE", ts.queryRuntimeDB(fmt.Sprintf(
		`SELECT STATE FROM "ENTITY_RUNTIME_DATA" WHERE ENTITY_ID = '%s';`, userID)),
		"a database identity's row must be seeded ACTIVE")
}

// A profile attribute named accessState is ordinary profile data: it is stored as written, it
// neither suspends nor locks, and a row seeded later takes nothing from it.
func (ts *RuntimeRowTestSuite) TestAnAccessStateProfileAttributeGovernsNothing() {
	claimed := map[string]interface{}{
		"suspend": map[string]interface{}{
			"suspendedAt": "2026-01-01T00:00:00Z", "operatorNote": "claimed by the profile",
		},
		"lock": map[string]interface{}{
			"entity": map[string]interface{}{
				"unlockAt": "9999-12-31T23:59:59Z", "reason": storedPostSuspensionReason,
			},
		},
	}
	userID, username, password := ts.users.newUser(ts.T(), "claimed",
		map[string]interface{}{"accessState": claimed})

	ts.Equal("ACTIVE", readStatus(ts.T(), userID).Value, "the profile attribute must not be a hold")
	ts.True(authenticate(ts.T(), "username", username, password).succeeded(),
		"the profile attribute must not refuse a sign-in")
	ts.Contains(ts.userAttributes(userID), "claimed by the profile",
		"the attribute must be stored as ordinary profile data")

	ts.Require().NoError(testutils.DeleteRuntimeRow(userID))
	ts.True(authenticate(ts.T(), "username", username, password).succeeded(),
		"a row seeded with the attribute present must not refuse a sign-in")
	row := ts.queryRuntimeDB(fmt.Sprintf(
		`SELECT STATE || '|' || RUNTIME_ATTRIBUTES FROM "ENTITY_RUNTIME_DATA" WHERE ENTITY_ID = '%s';`, userID))
	ts.Contains(row, "ACTIVE|", "the seeded row must start ACTIVE")
	ts.NotContains(row, "suspend", "the seeded row must take no suspension from the profile")
	ts.NotContains(row, storedPostSuspensionReason, "the seeded row must take no lock from the profile")
}

func (ts *RuntimeRowTestSuite) queryRuntimeDB(query string) string {
	ts.T().Helper()
	out, err := testutils.QueryRuntimeDB(query)
	ts.Require().NoError(err)
	return out
}

// runtimeRowCount counts runtime rows, for one entity or, with an empty ID, all of them.
func (ts *RuntimeRowTestSuite) runtimeRowCount(entityID string) int {
	ts.T().Helper()

	query := `SELECT COUNT(*) FROM "ENTITY_RUNTIME_DATA";`
	if entityID != "" {
		query = fmt.Sprintf(`SELECT COUNT(*) FROM "ENTITY_RUNTIME_DATA" WHERE ENTITY_ID = '%s';`, entityID)
	}
	count, err := strconv.Atoi(ts.queryRuntimeDB(query))
	ts.Require().NoError(err)
	return count
}

// userAttributes returns the raw profile attributes a management read returns.
func (ts *RuntimeRowTestSuite) userAttributes(userID string) string {
	ts.T().Helper()

	var user struct {
		Attributes json.RawMessage `json:"attributes"`
	}
	ts.Require().NoError(json.Unmarshal(getManagement(ts.T(), "/users/"+userID), &user))
	return string(user.Attributes)
}
