// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package identitygovernance

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/serverconfig"
	"github.com/thunder-id/thunderid/tests/mocks/entitytypemock"
	"github.com/thunder-id/thunderid/tests/mocks/notification/notificationmock"
	"github.com/thunder-id/thunderid/tests/mocks/serverconfigmock"
)

type InitTestSuite struct {
	suite.Suite
}

func TestInitTestSuite(t *testing.T) {
	suite.Run(t, new(InitTestSuite))
}

func (s *InitTestSuite) TestInitializeRequiresAnEntityStateProvider() {
	svc, handler, stop, err := Initialize(nil, Config{}, nil, nil, nil)
	s.Require().ErrorIs(err, errNoEntityStateProvider)
	s.Nil(svc)
	s.Nil(handler)
	s.Nil(stop)
}

// Without notification dependencies the service is built and the stop function does nothing.
func (s *InitTestSuite) TestInitializeWithoutNotificationsBuildsTheService() {
	svc, handler, stop, err := Initialize(newEntityStateProviderMock(s.T()), Config{}, nil, nil, nil)
	s.Require().NoError(err)
	s.NotNil(svc)
	s.NotNil(handler)
	s.Require().NotNil(stop)
	s.NotPanics(stop)
}

// With notification dependencies the stop function closes the notifier, so a later notice is dropped.
func (s *InitTestSuite) TestStopClosesTheNotifier() {
	svc, _, stop, err := Initialize(newEntityStateProviderMock(s.T()), Config{},
		&NotificationDependencies{
			Templates:   newNotificationTemplateRendererMock(s.T()),
			Senders:     notificationmock.NewNotificationSenderServiceInterfaceMock(s.T()),
			EntityTypes: entitytypemock.NewEntityTypeServiceInterfaceMock(s.T()),
		}, nil, nil)
	s.Require().NoError(err)

	stop()

	notifier, ok := svc.(*identityGovernanceService).notifier.(*lockEmailNotifier)
	s.Require().True(ok)
	s.True(notifier.closed)
	s.NotPanics(stop, "stopping twice is safe")
}

// The handler is built over the deployment configuration, which every merge is laid over.
func (s *InitTestSuite) TestInitializeReturnsTheHandlerOverTheDeploymentBase() {
	_, handler, _, err := Initialize(newEntityStateProviderMock(s.T()),
		Config{AccountAccess: testAccountAccessConfig()}, nil, nil, nil)
	s.Require().NoError(err)

	merged, ok := handler.Merge(nil, accountAccessValue{}).(accountAccessValue)

	s.Require().True(ok)
	s.Equal(testAccountAccessConfig(), merged)
}

// The deployment configuration applies until the server-config service is set; then the section does.
func (s *InitTestSuite) TestTheSectionIsReadOnceTheServerConfigServiceIsSet() {
	svc, _, _, err := Initialize(newEntityStateProviderMock(s.T()),
		Config{AccountAccess: testAccountAccessConfig()}, nil, nil, nil)
	s.Require().NoError(err)
	source := svc.(*identityGovernanceService).source
	s.Equal(testAccountAccessConfig(), source.Current(context.Background()))

	section := accountAccessValue{User: &accountAccessCategory{Default: &accountAccessPolicy{Threshold: new(3)}}}
	reader := serverconfigmock.NewServerConfigServiceMock(s.T())
	reader.EXPECT().GetMergedConfig(mock.Anything, string(serverconfig.ConfigNameAccountAccess)).
		Return(section, nil).Once()
	svc.SetServerConfigService(reader)

	s.Equal(section, source.Current(context.Background()))
}
