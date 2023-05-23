package handler

import (
	"context"
	"fmt"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/services/auth/web/core/domain"
	"github.com/ONLYOFFICE/onlyoffice-box/services/auth/web/core/port"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
)

type UserInsertHandler struct {
	service port.UserAccessService
	logger  log.Logger
}

func NewUserInsertHandler(service port.UserAccessService, logger log.Logger) UserInsertHandler {
	return UserInsertHandler{
		service: service,
		logger:  logger,
	}
}

func (i UserInsertHandler) InsertUser(ctx context.Context, req request.BoxUser, res *domain.UserAccess) error {
	_, err, _ := group.Do(fmt.Sprintf("insert-%s", req.ID), func() (interface{}, error) {
		if _, err := i.service.UpdateUser(ctx, domain.UserAccess{
			ID:           req.ID,
			AccessToken:  req.AccessToken,
			RefreshToken: req.RefreshToken,
			TokenType:    req.TokenType,
			ExpiresAt:    time.Now().UnixMilli() + req.ExpiresIn*int64(1000),
		}); err != nil {
			i.logger.Errorf("could not update user: %s", err.Error())
			return nil, err
		}

		return nil, nil
	})

	return err
}
