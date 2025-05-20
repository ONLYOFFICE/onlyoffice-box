/**
 *
 * (c) Copyright Ascensio System SIA 2025
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package handler

import (
	"context"
	"fmt"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/services/auth/web/core/domain"
	"github.com/ONLYOFFICE/onlyoffice-box/services/auth/web/core/port"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"go-micro.dev/v4/client"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

var group singleflight.Group

type UserSelectHandler struct {
	service     port.UserAccessService
	client      client.Client
	boxClient   shared.BoxAPI
	credentials *oauth2.Config
	logger      log.Logger
}

func NewUserSelectHandler(
	service port.UserAccessService,
	client client.Client,
	boxClient shared.BoxAPI,
	credentials *oauth2.Config,
	logger log.Logger,
) UserSelectHandler {
	return UserSelectHandler{
		service:     service,
		client:      client,
		boxClient:   boxClient,
		credentials: credentials,
		logger:      logger,
	}
}

func (u UserSelectHandler) GetUser(ctx context.Context, uid *string, res *domain.UserAccess) error {
	user, err, _ := group.Do(fmt.Sprintf("select-%s", *uid), func() (interface{}, error) {
		user, err := u.service.GetUser(ctx, *uid)
		if err != nil {
			u.logger.Debugf("could not get user with id: %s. Reason: %s", *uid, err.Error())
			return nil, err
		}

		if user.ExpiresAt-12000 <= time.Now().UnixMilli() {
			credentials, err := u.boxClient.
				RefreshAuthCredentials(ctx, user.RefreshToken, u.credentials.ClientID, u.credentials.ClientSecret)
			if err != nil {
				return user, err
			}

			return u.service.UpdateUser(ctx, domain.UserAccess{
				ID:           user.ID,
				AccessToken:  credentials.AccessToken,
				RefreshToken: credentials.RefreshToken,
				TokenType:    credentials.TokenType,
				ExpiresAt:    time.Now().UnixMilli() + credentials.ExpiresIn*int64(1000),
			})
		}

		return user, nil
	})

	if usr, ok := user.(domain.UserAccess); ok {
		*res = usr
		return nil
	}

	return err
}
