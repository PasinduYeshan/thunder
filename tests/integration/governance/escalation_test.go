// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package governance

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/thunder-id/thunderid/tests/integration/testutils"
)

// EscalationTestSuite checks how the ladder moves over time: the last rung repeats, decay returns it
// to the bottom, a quiet window restarts the count, and failures during a live lock count for nothing.
// Every value is in seconds so the clock can be waited out. The rung a lock serves is read from the
// lock itself, so no assertion depends on how long the test took to read it.
type EscalationTestSuite struct {
	suite.Suite
	users *userFixture
}

func TestEscalationTestSuite(t *testing.T) {
	suite.Run(t, new(EscalationTestSuite))
}

const (
	escalationThreshold    = 2
	escalationWindowSecs   = 5
	escalationDecaySeconds = 8

	// escalationLapseWait is how long past a reported expiry a case waits before relying on the lapse.
	// It stays well under escalationDecaySeconds, so waiting out a rung does not also decay the ladder.
	escalationLapseWait = 2 * time.Second

	// escalationCeiling is the consecutive-failure ceiling the ceiling cases set: two lockouts' worth.
	escalationCeiling = 2 * escalationThreshold
)

// escalationRungs is the ladder. The last rung is shorter than the one before it, so a repeat of the
// last rung is told apart from a step that ran off the end or back to the second.
var escalationRungs = []int{5, 15, 10}

// escalationPolicy is a password policy with a short window, a three-rung ladder and a short decay.
func escalationPolicy() map[string]interface{} {
	return lockoutPolicyWith(userDefaults(map[string]interface{}{
		"threshold":            escalationThreshold,
		"failureWindowSeconds": escalationWindowSecs,
		"lockDurationsSeconds": escalationRungs,
		"lockDecaySeconds":     escalationDecaySeconds,
	}))
}

// escalationCeilingPolicy is escalationPolicy with a consecutive-failure ceiling.
func escalationCeilingPolicy() map[string]interface{} {
	return mergeJSONObjects(escalationPolicy(),
		userDefaults(map[string]interface{}{"maxConsecutiveFailures": escalationCeiling}))
}

func (ts *EscalationTestSuite) SetupSuite() {
	applyPolicy(ts.T(), escalationPolicy())
	ts.users = newUserFixture(ts.T(), "escalation", testutils.UserType{Schema: credentialsSchema(nil)})
}

// Lockouts with no proof of control in between serve the rungs in order, and once the
// list is exhausted the last rung repeats.
func (ts *EscalationTestSuite) TestTheLastRungRepeats() {
	userID, username := ts.newUser("repeat")

	expected := append(append([]int{}, escalationRungs...), escalationRungs[len(escalationRungs)-1])
	for i, rung := range expected {
		failAuthentication(ts.T(), "username", username, escalationThreshold)
		expiry := ts.requireRung(userID, rung, fmt.Sprintf("lockout %d must serve rung %d", i+1, rung))
		if i < len(expected)-1 {
			ts.waitOut(userID, expiry)
		}
	}
}

// Once a finite lock has ended and the decay interval has passed, the next lock serves the
// first rung again.
func (ts *EscalationTestSuite) TestDecayReturnsTheLadderToTheFirstRung() {
	userID, username := ts.newUser("decay")

	failAuthentication(ts.T(), "username", username, escalationThreshold)
	expiry := ts.requireRung(userID, escalationRungs[0], "the first lock must serve the first rung")

	time.Sleep(time.Until(expiry) + escalationDecaySeconds*time.Second + escalationLapseWait)

	failAuthentication(ts.T(), "username", username, escalationThreshold)
	ts.requireRung(userID, escalationRungs[0], "after the decay interval the ladder must start again")
}

// The failure window. A failure followed by a quiet window restarts the count, so one more failure
// does not lock; a failure inside the window still does.
func (ts *EscalationTestSuite) TestAQuietWindowRestartsTheCount() {
	userID, username := ts.newUser("window")

	failAuthentication(ts.T(), "username", username, escalationThreshold-1)
	time.Sleep(escalationWindowSecs*time.Second + escalationLapseWait)

	failAuthentication(ts.T(), "username", username, 1)
	ts.Equal("ACTIVE", readStatus(ts.T(), userID).Value,
		"a failure after a quiet window must start the count again")

	failAuthentication(ts.T(), "username", username, 1)
	ts.Equal("LOCKED", readStatus(ts.T(), userID).Value,
		"a failure inside the window must still count toward the threshold")
}

// Wrong-secret failures during a live lock are refused with the lock stated and are not counted: they
// neither extend the lock nor advance the ladder, so the next lockout serves the second rung, not the
// third.
func (ts *EscalationTestSuite) TestFailuresDuringALiveLockCountForNothing() {
	userID, username := ts.newUser("live_failures")

	failAuthentication(ts.T(), "username", username, escalationThreshold)
	expiry := ts.requireRung(userID, escalationRungs[0], "the first lock must serve the first rung")

	// The store keeps whole seconds, so an extension is visible only from the next second on.
	time.Sleep(time.Second)
	failHeldAuthentication(ts.T(), "username", username, escalationThreshold*2, statedLockCode)
	ts.Require().True(time.Now().Before(expiry), "the failures must all fall inside the rung")

	after, reported := readStatus(ts.T(), userID).expiryOf("credential")
	ts.Require().True(reported, "the lock must still be reported")
	ts.Equal(expiry, after, "failures during a live lock must not extend it")

	ts.waitOut(userID, expiry)
	failAuthentication(ts.T(), "username", username, escalationThreshold)
	ts.requireRung(userID, escalationRungs[1],
		"failures during a live lock must not advance the ladder past the second rung")
}

// The consecutive ceiling. Failures with no success in between reach it across a lapsed lock, and the
// lock it forms does not lapse: the correct password is refused with the lock stated until an unlock.
func (ts *EscalationTestSuite) TestTheConsecutiveCeilingHoldsUntilAnUnlock() {
	applyPolicy(ts.T(), escalationCeilingPolicy())
	userID, username := ts.newUser("ceiling")

	failAuthentication(ts.T(), "username", username, escalationThreshold)
	ts.waitOut(userID, ts.requireRung(userID, escalationRungs[0], "the first lock must serve the first rung"))

	failAuthentication(ts.T(), "username", username, escalationCeiling-escalationThreshold)
	status := readStatus(ts.T(), userID)
	ts.Require().Equal([]string{"credential"}, status.lockedMethods(), "the ceiling must lock the password")
	_, reported := status.expiryOf("credential")
	ts.False(reported, "a lock at the ceiling must not lapse, so it reports no expiry")

	wrong := authenticate(ts.T(), "username", username, "wrong-password")
	held := authenticate(ts.T(), "username", username, ts.password("ceiling"))
	requireStatedHold(ts.T(), wrong, held, statedLockCode)

	runAdministrationFlow(ts.T(), unlockFlowHandle, userID)
	ts.True(authenticate(ts.T(), "username", username, ts.password("ceiling")).succeeded(),
		"an unlock must release the ceiling's lock")
}

// A success with the method resets the consecutive count, so the same number of failures with a success
// between them forms only a finite lock.
func (ts *EscalationTestSuite) TestASuccessResetsTheConsecutiveCount() {
	applyPolicy(ts.T(), escalationCeilingPolicy())
	userID, username := ts.newUser("ceiling_reset")

	failAuthentication(ts.T(), "username", username, escalationThreshold)
	ts.waitOut(userID, ts.requireRung(userID, escalationRungs[0], "the first lock must serve the first rung"))
	ts.Require().True(authenticate(ts.T(), "username", username, ts.password("ceiling_reset")).succeeded(),
		"the lapsed lock must admit the correct password")

	failAuthentication(ts.T(), "username", username, escalationCeiling-escalationThreshold)
	ts.requireRung(userID, escalationRungs[0],
		"after a success the ceiling must not be reached, and the ladder starts again")
}

// requireRung requires the user's password lock to serve the given rung, read as the lock's unlock
// time less the failure that formed it, and returns the expiry the status read reports.
func (ts *EscalationTestSuite) requireRung(userID string, rungSeconds int, msg string) time.Time {
	ts.T().Helper()

	status := readStatus(ts.T(), userID)
	ts.Require().Equal([]string{"credential"}, status.lockedMethods(), msg+": the password must be locked")
	expiry, reported := status.expiryOf("credential")
	ts.Require().True(reported, msg+": a finite rung must report its expiry")
	ts.Require().Equal(time.Duration(rungSeconds)*time.Second, servedRung(ts.T(), userID, "credential"), msg)
	return expiry
}

// waitOut sleeps past a lock's expiry, inside the decay interval, and requires the lock to have
// lapsed.
func (ts *EscalationTestSuite) waitOut(userID string, expiry time.Time) {
	ts.T().Helper()

	time.Sleep(time.Until(expiry) + escalationLapseWait)
	ts.Require().Equal("ACTIVE", readStatus(ts.T(), userID).Value, "the rung must have lapsed")
}

// newUser creates an account no other test touches, and returns its id and username. Only a case
// about resetting signs in successfully, since a success resets the ladder.
func (ts *EscalationTestSuite) newUser(name string) (userID, username string) {
	ts.T().Helper()
	userID, username, _ = ts.users.newUser(ts.T(), name, nil)
	return userID, username
}

// password is the correct password newUser gives the account it creates under name.
func (ts *EscalationTestSuite) password(name string) string {
	return "Correct-Horse-" + name + "1!"
}
