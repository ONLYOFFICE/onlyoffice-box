/**
 *
 * (c) Copyright Ascensio System SIA 2023
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
	"net/url"

	"github.com/ONLYOFFICE/onlyoffice-box/pkg/config"
	"github.com/ONLYOFFICE/onlyoffice-box/pkg/crypto"
	"github.com/ONLYOFFICE/onlyoffice-box/pkg/log"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/request"
	"github.com/gorilla/sessions"
	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"go-micro.dev/v4/client"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

var group singleflight.Group

type AuthController struct {
	client         client.Client
	boxClient      shared.BoxAPI
	jwtManager     crypto.JwtManager
	stateGenerator crypto.StateGenerator
	store          *sessions.CookieStore
	config         *config.ServerConfig
	oauth          *oauth2.Config
	logger         log.Logger
}

func NewAuthController(
	client client.Client,
	boxClient shared.BoxAPI,
	jwtManager crypto.JwtManager,
	stateGenerator crypto.StateGenerator,
	config *config.ServerConfig,
	oauth *oauth2.Config,
	logger log.Logger,
) AuthController {
	return AuthController{
		client:         client,
		boxClient:      boxClient,
		jwtManager:     jwtManager,
		stateGenerator: stateGenerator,
		store:          sessions.NewCookieStore([]byte(oauth.ClientSecret)),
		config:         config,
		oauth:          oauth,
		logger:         logger,
	}
}

func (c AuthController) BuildGetAuth() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		v, _ := cv.CreateCodeVerifier()
		verifier := v.String()

		session, err := c.store.Get(r, "auth-session")
		if err != nil {
			// TODO: Error page
			c.logger.Errorf("could not get session store: %s", err.Error())
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		state, err := c.stateGenerator.GenerateState(verifier)
		if err != nil {
			c.logger.Errorf("could not generate a new state: %s", err.Error())
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		session.Values["state"] = state
		if err := session.Save(r, rw); err != nil {
			c.logger.Errorf("could not save session: %s", err.Error())
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		http.Redirect(
			rw, r,
			fmt.Sprintf(
				"https://account.box.com/api/oauth2/authorize?client_id=%s&response_type=code&state=%s",
				c.oauth.ClientID, url.QueryEscape(state),
			),
			http.StatusMovedPermanently,
		)
	}
}

func (c AuthController) BuildGetRedirect() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		code, state := query.Get("code"), query.Get("state")
		if code == "" {
			c.logger.Warn("could not request auth credentials. Invalid authorization code")
			// TODO: Error page
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		if state == "" {
			c.logger.Warn("could not request auth credentials. Invalid state")
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		session, err := c.store.Get(r, "auth-session")
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			c.logger.Errorf("could not get session: %s", err.Error())
			return
		}

		if state != session.Values["state"] {
			http.Redirect(rw, r, "/oauth/auth", http.StatusMovedPermanently)
			return
		}

		c.logger.Debugf("auth state is valid: %s", state)

		session.Options.MaxAge = -1
		if err := session.Save(r, rw); err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			c.logger.Errorf("could not remove session. Reason: %s", err.Error())
			return
		}

		credentials, err := c.boxClient.
			GetAuthCredentials(context.Background(), code, c.oauth.ClientID, c.oauth.ClientSecret)
		if err != nil {
			c.logger.Errorf("could not get user credentials: %s", err.Error())
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		user, err := c.boxClient.GetMe(context.Background(), credentials.AccessToken)
		if err != nil {
			c.logger.Errorf("could not get user info: %s", err.Error())
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		req := c.client.NewRequest(fmt.Sprintf("%s:auth", c.config.Namespace), "UserInsertHandler.InsertUser", request.BoxUser{
			ID:           user.ID,
			AccessToken:  credentials.AccessToken,
			RefreshToken: credentials.RefreshToken,
			TokenType:    credentials.TokenType,
			ExpiresIn:    credentials.ExpiresIn,
		})

		var resp interface{}
		if err := c.client.Call(r.Context(), req, &resp, client.WithRetries(3)); err != nil {
			c.logger.Errorf("could not insert a new user: %s", err.Error())
		}

		// TODO: Render success page
		rw.WriteHeader(http.StatusOK)
	}
}
