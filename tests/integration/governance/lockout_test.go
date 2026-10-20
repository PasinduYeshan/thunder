// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package governance

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/thunder-id/thunderid/tests/integration/testutils"
)

// LockoutTestSuite checks what a wrong secret costs and the two non-recovery exits: the clock and
// an operator. The recovery exit is in recovery_release_test.go.
type LockoutTestSuite struct {
	suite.Suite
	users *userFixture
}

func TestLockoutTestSuite(t *testing.T) {
	suite.Run(t, new(LockoutTestSuite))
}

func (ts *LockoutTestSuite) SetupSuite() {
	applyLockoutPolicy(ts.T())
	ts.users = newUserFixture(ts.T(), "lockout", testutils.UserType{Schema: credentialsSchema(nil)})
}

// newUser creates an account no other test touches, and returns its id, username and password, so
// one test's lockout cannot decide another's outcome.
func (ts *LockoutTestSuite) newUser(name string) (userID, username, password string) {
	ts.T().Helper()
	userID, username, password = ts.users.newUser(ts.T(), name, nil)
	return userID, username, password
}

// Below the threshold the account is untouched.
func (ts *LockoutTestSuite) TestFailuresBelowTheThresholdLeaveTheAccountUsable() {
	_, username, password := ts.newUser("below")

	failAuthentication(ts.T(), "username", username, lockThreshold-1)

	ts.True(authenticate(ts.T(), "username", username, password).succeeded(),
		"the correct secret must still authenticate below the threshold")
}

// The threshold makes the account unusable, and that includes the correct secret,
// a lock that only refused wrong secrets would protect nothing.
func (ts *LockoutTestSuite) TestTheThresholdRefusesEvenTheCorrectSecret() {
	userID, username, password := ts.newUser("threshold")

	failAuthentication(ts.T(), "username", username, lockThreshold)

	ts.False(authenticate(ts.T(), "username", username, password).succeeded(),
		"the correct secret must be refused while the lock is live")

	status := readStatus(ts.T(), userID)
	ts.Equal("LOCKED", status.Value, "the management read must report the lock")
	ts.Contains(status.lockedMethods(), "credential",
		"the lock must be held against the authentication_method that failed")
}

// A locked account is told it is locked whichever password it presents, the correct one or a wrong
// one, with the status a wrong secret on an unlocked account gets, and is not told which method is
// locked or when the lock ends.
func (ts *LockoutTestSuite) TestALockedAccountStatesTheLock() {
	_, lockedUser, lockedSecret := ts.newUser("oracle")
	_, liveUser, _ := ts.newUser("oracle_live")

	failAuthentication(ts.T(), "username", lockedUser, lockThreshold)

	wrong := authenticate(ts.T(), "username", liveUser, "WrongSecret1!")
	for _, presented := range []struct{ name, secret string }{
		{"the correct password", lockedSecret},
		{"a wrong password", "WrongSecret1!"},
	} {
		locked := authenticate(ts.T(), "username", lockedUser, presented.secret)
		requireStatedHold(ts.T(), wrong, locked, statedLockCode)
		ts.NotContains(locked.body, statedSuspensionCode, "%s: a lock must not be stated as a suspension",
			presented.name)
		ts.NotContains(locked.body, "credential", "%s: the refusal must not name the locked sign-in method",
			presented.name)
	}
}

// A successful authentication clears the count, so the next run needs the full threshold again.
func (ts *LockoutTestSuite) TestASuccessfulAuthenticationClearsTheCount() {
	userID, username, password := ts.newUser("reset")

	failAuthentication(ts.T(), "username", username, lockThreshold-1)
	ts.Require().True(authenticate(ts.T(), "username", username, password).succeeded(),
		"the clearing authentication must itself succeed")

	// One more failure would have been the threshold had the count survived.
	failAuthentication(ts.T(), "username", username, 1)

	ts.True(authenticate(ts.T(), "username", username, password).succeeded(),
		"proof of control must have cleared the count")
	ts.Equal("ACTIVE", readStatus(ts.T(), userID).Value, "nothing should be held")
}

// A lock lapses on its own, with nothing run against the account in between.
func (ts *LockoutTestSuite) TestALockLapsesOnItsOwn() {
	userID, username, password := ts.newUser("lapse")

	failAuthentication(ts.T(), "username", username, lockThreshold)
	ts.Require().False(authenticate(ts.T(), "username", username, password).succeeded(),
		"the account must be locked before the lapse is meaningful")

	expiry, reported := readStatus(ts.T(), userID).expiryOf("credential")
	ts.Require().True(reported, "a lock that lifts on its own must report when")
	time.Sleep(time.Until(expiry) + rungLapseTolerance)

	ts.True(authenticate(ts.T(), "username", username, password).succeeded(),
		"the same correct secret must work once the rung has elapsed")
}

// A second lockout, with no proof of control in between, serves the second, longer rung.
// No sign-in succeeds between them, since that steps the ladder back to the bottom.
func (ts *LockoutTestSuite) TestRepeatedLockoutsServeLongerRungs() {
	userID, username, _ := ts.newUser("ladder")

	failAuthentication(ts.T(), "username", username, lockThreshold)
	ts.Require().Equal(firstRungSeconds*time.Second, servedRung(ts.T(), userID, "credential"),
		"the first lockout must serve the first rung")
	firstExpiry, reported := readStatus(ts.T(), userID).expiryOf("credential")
	ts.Require().True(reported, "the first lock must report an expiry")

	time.Sleep(time.Until(firstExpiry) + rungLapseTolerance)
	ts.Require().Equal("ACTIVE", readStatus(ts.T(), userID).Value,
		"the first rung must have lapsed before the second lockout is meaningful")

	failAuthentication(ts.T(), "username", username, lockThreshold)
	ts.Equal(secondRungSeconds*time.Second, servedRung(ts.T(), userID, "credential"),
		"a second lockout with no proof of control in between must serve the second rung")
}

// A successful authentication steps the ladder back to the bottom, so a user who was locked,
// waited it out and signed in does not serve a longer rung the next time they mistype.
func (ts *LockoutTestSuite) TestProofOfControlResetsTheLadder() {
	userID, username, password := ts.newUser("ladder_reset")

	failAuthentication(ts.T(), "username", username, lockThreshold)
	firstExpiry, reported := readStatus(ts.T(), userID).expiryOf("credential")
	ts.Require().True(reported, "the first lock must report an expiry")

	time.Sleep(time.Until(firstExpiry) + rungLapseTolerance)
	ts.Require().True(authenticate(ts.T(), "username", username, password).succeeded(),
		"the account must be usable again once the rung has lapsed")

	failAuthentication(ts.T(), "username", username, lockThreshold)
	ts.Equal(firstRungSeconds*time.Second, servedRung(ts.T(), userID, "credential"),
		"after proof of control the ladder must serve the first rung again")
}

// Attempts naming an account that does not exist lock nobody.
func (ts *LockoutTestSuite) TestAttemptsAgainstAnUnknownAccountLockNobody() {
	userID, username, password := ts.newUser("unknown")

	unknown := "ghost_" + ts.users.suffix
	failAuthentication(ts.T(), "username", unknown, lockThreshold*2)

	ts.True(authenticate(ts.T(), "username", username, password).succeeded(),
		"a real account must be unaffected by failures against a name that does not exist")
	ts.Equal("ACTIVE", readStatus(ts.T(), userID).Value, "nothing may be held")
}

// A correct or a wrong secret presented during a lock does not extend it.
func (ts *LockoutTestSuite) TestACorrectSecretDoesNotExtendTheLock() {
	userID, username, password := ts.newUser("extend")

	failAuthentication(ts.T(), "username", username, lockThreshold)
	before, reported := readStatus(ts.T(), userID).expiryOf("credential")
	ts.Require().True(reported, "the lock must report an expiry")

	// The expiry is stored to the second, so an extension shows only from the next second on.
	time.Sleep(time.Second)
	for range 3 {
		ts.Require().False(authenticate(ts.T(), "username", username, password).succeeded(),
			"a locked account must refuse the correct secret")
	}
	failHeldAuthentication(ts.T(), "username", username, lockThreshold, statedLockCode)
	ts.Require().True(time.Now().Before(before), "the attempts must all fall inside the rung")

	status := readStatus(ts.T(), userID)
	ts.Equal([]string{"credential"}, status.lockedMethods(), "the lock must still be the only one held")
	after, reported := status.expiryOf("credential")
	ts.Require().True(reported, "the lock must still be reported")
	ts.Equal(before, after, "presenting the correct or a wrong secret must not push the lock out")
}

// Operator unlock releases the account immediately: the correct secret works before the rung
// could have lapsed on its own.
func (ts *LockoutTestSuite) TestUnlockReleasesTheAccount() {
	userID, username, password := ts.newUser("unlock")

	failAuthentication(ts.T(), "username", username, lockThreshold)
	status := readStatus(ts.T(), userID)
	ts.Require().Equal("LOCKED", status.Value, "the account must be locked first")
	expiry, reported := status.expiryOf("credential")
	ts.Require().True(reported, "the lock must report an expiry")

	runAdministrationFlow(ts.T(), unlockFlowHandle, userID)

	ts.True(authenticate(ts.T(), "username", username, password).succeeded(),
		"unlock must release the account immediately")
	ts.Require().True(time.Now().Before(expiry),
		"the sign-in must fall inside the rung, or the lapse rather than the unlock released it")
	ts.Equal("ACTIVE", readStatus(ts.T(), userID).Value, "nothing may still be held")
}

// Unlock resets the ladder, so the next lockout serves the first rung again. No sign-in
// succeeds in between, since that resets the ladder too.
func (ts *LockoutTestSuite) TestUnlockResetsTheLadder() {
	userID, username, _ := ts.newUser("unlock_ladder")

	failAuthentication(ts.T(), "username", username, lockThreshold)
	firstExpiry, reported := readStatus(ts.T(), userID).expiryOf("credential")
	ts.Require().True(reported, "the first lock must report an expiry")

	runAdministrationFlow(ts.T(), unlockFlowHandle, userID)
	ts.Require().True(time.Now().Before(firstExpiry),
		"the unlock must fall inside the rung, or the lapse rather than the unlock released it")
	ts.Equal("ACTIVE", readStatus(ts.T(), userID).Value, "the unlock must have released the first lock")

	failAuthentication(ts.T(), "username", username, lockThreshold)
	ts.Equal(firstRungSeconds*time.Second, servedRung(ts.T(), userID, "credential"),
		"after an unlock the ladder must serve the first rung again, not the next one")
}

// Unlocking an account with nothing locked is accepted and changes nothing.
func (ts *LockoutTestSuite) TestUnlockingAnUnlockedAccountIsHarmless() {
	userID, username, password := ts.newUser("noop_unlock")

	runAdministrationFlow(ts.T(), unlockFlowHandle, userID)

	ts.Equal("ACTIVE", readStatus(ts.T(), userID).Value, "the account must stay active")
	ts.True(authenticate(ts.T(), "username", username, password).succeeded(),
		"the account must stay usable")
}
