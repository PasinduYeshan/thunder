// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/thunder-id/thunderid/internal/notification/common"
)

// ServerConfigHandler decodes, validates and merges the "notification" section.
type ServerConfigHandler struct {
	senders NotificationSenderMgtSvcInterface
}

// NewServerConfigHandler creates the "notification" section handler.
func NewServerConfigHandler(senders NotificationSenderMgtSvcInterface) *ServerConfigHandler {
	return &ServerConfigHandler{senders: senders}
}

// Decode parses a raw section value. Empty input yields the zero value.
func (*ServerConfigHandler) Decode(raw json.RawMessage) (any, error) {
	if len(raw) == 0 {
		return ServerConfig{}, nil
	}
	var cfg ServerConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate refuses a write while the sender is set declaratively, and checks that a named sender
// exists and sends email.
func (h *ServerConfigHandler) Validate(incoming, readOnly, _ any) error {
	if ro, ok := readOnly.(ServerConfig); ok && ro.DefaultEmailSenderID != "" {
		return errDeclarativeSenderLocked
	}
	cfg, _ := incoming.(ServerConfig)
	senderID := strings.TrimSpace(cfg.DefaultEmailSenderID)
	if senderID == "" {
		return nil
	}
	sender, svcErr := h.senders.GetSender(context.Background(), senderID)
	if svcErr != nil {
		if svcErr.Code == ErrorSenderNotFound.Code {
			return errUnknownDefaultEmailSender
		}
		return errDefaultSenderLookupFailed
	}
	if sender.Type != common.NotificationSenderTypeEmail {
		return errDefaultSenderNotEmail
	}
	return nil
}

// Merge returns the declarative layer when it names a sender, otherwise the writable layer.
func (*ServerConfigHandler) Merge(readOnly, writable any) any {
	if ro, ok := readOnly.(ServerConfig); ok && ro.DefaultEmailSenderID != "" {
		return ro
	}
	if wr, ok := writable.(ServerConfig); ok {
		return wr
	}
	return ServerConfig{}
}
