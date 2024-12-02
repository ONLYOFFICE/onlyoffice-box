/**
 *
 * (c) Copyright Ascensio System SIA 2024
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

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/services/shared"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"go-micro.dev/v4/client"
)

type ShareController struct {
	server    *config.ServerConfig
	boxClient shared.BoxAPI
	client    client.Client
	logger    log.Logger
}

func NewShareController(
	server *config.ServerConfig,
	boxClient shared.BoxAPI,
	client client.Client,
	logger log.Logger,
) ShareController {
	return ShareController{
		server:    server,
		client:    client,
		boxClient: boxClient,
		logger:    logger,
	}
}

func (c ShareController) getUserAccessToken(
	ctx context.Context,
	userID string,
) (response.UserResponse, error) {
	var ures response.UserResponse
	if err := c.client.Call(ctx, c.client.NewRequest(
		fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser",
		userID,
	), &ures); err != nil {
		c.logger.Debugf("could not get user %s access info: %s", userID, err.Error())
		return ures, err
	}
	return ures, nil
}

func (c ShareController) BuildInviteUser() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		var body request.InviteUserRequest
		userID := r.URL.Query().Get("user")

		status, _, _ := group.Do(fmt.Sprintf("invite:%s", userID), func() (interface{}, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()

			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				c.logger.Errorf("could not unmarshal request body: %s", err.Error())
				rw.WriteHeader(http.StatusBadRequest)
				return http.StatusBadRequest, nil
			}

			if len(body.Users) > 10 {
				return http.StatusRequestEntityTooLarge, nil
			}

			user, err := c.getUserAccessToken(ctx, userID)
			if err != nil {
				c.logger.Errorf("could not get current user: %s", err.Error())
				return http.StatusBadRequest, nil
			}

			if info, err := c.boxClient.GetFileInfo(ctx, user.AccessToken, body.FileID); err != nil || info.CreatedBy.ID != userID {
				return http.StatusForbidden, nil
			}

			for _, usr := range body.Users {
				role := shared.Viewer
				if usr.Editor {
					role = shared.Editor
				}

				if err := c.boxClient.InviteUser(ctx, user.AccessToken, body.FileID, usr.Email, role); err != nil {
					c.logger.Warnf("could not invite a new user %s to the file %s: %s", usr.Email, body.FileID, err.Error())
				}
			}

			return http.StatusCreated, nil
		})

		if code, ok := status.(int); ok {
			rw.WriteHeader(code)
			return
		}

		rw.WriteHeader(http.StatusInternalServerError)
	}
}

func (c ShareController) BuildGetInvitations() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		userID, fileID := r.URL.Query().Get("user"), r.URL.Query().Get("file")
		group.Do(fmt.Sprintf("invitations:%s:%s", userID, fileID), func() (interface{}, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()

			user, err := c.getUserAccessToken(ctx, userID)
			if err != nil {
				c.logger.Errorf("could not get current user: %s", err.Error())
				rw.WriteHeader(http.StatusBadRequest)
				return nil, nil
			}

			collaborations, err := c.boxClient.GetInvitations(ctx, user.AccessToken, fileID)
			if err != nil {
				c.logger.Errorf("could not get file collaborations: %s", err.Error())
				rw.WriteHeader(http.StatusBadRequest)
				return nil, nil
			}

			rw.Header().Set("Content-Type", "application/json")
			rw.Write(collaborations.ToJSON())
			return nil, nil
		})
	}
}
