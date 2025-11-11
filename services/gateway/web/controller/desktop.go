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

package controller

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/services/gateway/web/embeddable"
	"github.com/ONLYOFFICE/onlyoffice-box/services/gateway/web/middleware"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"go-micro.dev/v4/client"
)

type DesktopController struct {
	client    client.Client
	boxClient shared.BoxAPI
	server    *config.ServerConfig
	logger    log.Logger
}

func NewDesktopController(
	client client.Client,
	boxClient shared.BoxAPI,
	server *config.ServerConfig,
	logger log.Logger,
) DesktopController {
	return DesktopController{
		client:    client,
		boxClient: boxClient,
		server:    server,
		logger:    logger,
	}
}

func (c *DesktopController) BuildEntryPage() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/html")

		uid, ok := r.Context().Value(middleware.UserIDKey).(string)
		if !ok || uid == "" {
			c.logger.Error("user id not found")
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		var ures response.UserResponse
		if err := c.client.Call(ctx, c.client.NewRequest(
			fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser",
			uid,
		), &ures); err != nil {
			c.logger.Errorf("could not get user %s access info: %s", uid, err.Error())
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		usr, err := c.boxClient.GetMe(ctx, ures.AccessToken)
		if err != nil {
			c.logger.Errorf("could not get dropbox user profile: %s", err.Error())
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		locale := usr.Language
		if locale == "" {
			locale = "en"
		}

		loc := i18n.NewLocalizer(embeddable.Bundle, locale)
		loading, _ := loc.Localize(&i18n.LocalizeConfig{
			MessageID:      "loading",
			DefaultMessage: &i18n.Message{ID: "loading", Other: "Loading..."},
		})

		if err := embeddable.DesktopPage.Execute(rw, map[string]any{
			"displayName": usr.Name,
			"email":       usr.Login,
			"domain":      r.Host,
			"provider":    "box",
			"userId":      usr.ID,
			"loading":     loading,
		}); err != nil {
			c.logger.Errorf("could not execute desktop template: %s", err.Error())
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
		}
	}
}
