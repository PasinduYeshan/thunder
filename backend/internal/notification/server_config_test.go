// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/notification/common"
	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
)

type ServerConfigTestSuite struct {
	suite.Suite
	senders *NotificationSenderMgtSvcInterfaceMock
	handler *ServerConfigHandler
}

func TestServerConfigTestSuite(t *testing.T) {
	suite.Run(t, new(ServerConfigTestSuite))
}

func (s *ServerConfigTestSuite) SetupTest() {
	s.senders = NewNotificationSenderMgtSvcInterfaceMock(s.T())
	s.handler = NewServerConfigHandler(s.senders)
}

func (s *ServerConfigTestSuite) TestDecode() {
	value, err := s.handler.Decode(nil)
	s.Require().NoError(err)
	s.Equal(ServerConfig{}, value)

	value, err = s.handler.Decode(json.RawMessage(`{"defaultEmailSenderId":"sender-1"}`))
	s.Require().NoError(err)
	s.Equal(ServerConfig{DefaultEmailSenderID: "sender-1"}, value)

	_, err = s.handler.Decode(json.RawMessage(`not json`))
	s.Error(err)
}

func (s *ServerConfigTestSuite) TestValidateAcceptsAnEmailSender() {
	s.senders.EXPECT().GetSender(mock.Anything, "sender-1").
		Return(&common.NotificationSenderDTO{ID: "sender-1", Type: common.NotificationSenderTypeEmail}, nil)

	s.NoError(s.handler.Validate(ServerConfig{DefaultEmailSenderID: "sender-1"}, ServerConfig{}, ServerConfig{}))
}

func (s *ServerConfigTestSuite) TestValidateAcceptsClearingTheSender() {
	s.NoError(s.handler.Validate(ServerConfig{}, ServerConfig{}, ServerConfig{}))
}

func (s *ServerConfigTestSuite) TestValidateRejectsAnUnknownSender() {
	s.senders.EXPECT().GetSender(mock.Anything, "missing").Return(nil, &ErrorSenderNotFound)

	s.ErrorIs(s.handler.Validate(ServerConfig{DefaultEmailSenderID: "missing"}, nil, nil),
		errUnknownDefaultEmailSender)
}

func (s *ServerConfigTestSuite) TestValidateRejectsAFailedLookup() {
	s.senders.EXPECT().GetSender(mock.Anything, "sender-1").Return(nil, &tidcommon.InternalServerError)

	s.ErrorIs(s.handler.Validate(ServerConfig{DefaultEmailSenderID: "sender-1"}, nil, nil),
		errDefaultSenderLookupFailed)
}

func (s *ServerConfigTestSuite) TestValidateRejectsAMessageSender() {
	s.senders.EXPECT().GetSender(mock.Anything, "sms-1").
		Return(&common.NotificationSenderDTO{ID: "sms-1", Type: common.NotificationSenderTypeMessage}, nil)

	s.ErrorIs(s.handler.Validate(ServerConfig{DefaultEmailSenderID: "sms-1"}, nil, nil),
		errDefaultSenderNotEmail)
}

// A declarative sender locks the section.
func (s *ServerConfigTestSuite) TestValidateRejectsAWriteOverADeclarativeSender() {
	s.ErrorIs(s.handler.Validate(ServerConfig{DefaultEmailSenderID: "sender-2"},
		ServerConfig{DefaultEmailSenderID: "sender-1"}, ServerConfig{}), errDeclarativeSenderLocked)
}

func (s *ServerConfigTestSuite) TestMerge() {
	declarative := ServerConfig{DefaultEmailSenderID: "file"}
	writable := ServerConfig{DefaultEmailSenderID: "db"}

	s.Equal(declarative, s.handler.Merge(declarative, writable))
	s.Equal(writable, s.handler.Merge(ServerConfig{}, writable))
	s.Equal(ServerConfig{}, s.handler.Merge(nil, nil))
}
