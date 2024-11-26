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
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/services/gateway/web/embeddable"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"go-micro.dev/v4/client"
	"golang.org/x/oauth2"
)

type AuthController struct {
	client         client.Client
	boxClient      shared.BoxAPI
	jwtManager     crypto.JwtManager
	store          *sessions.CookieStore
	stateGenerator crypto.StateGenerator
	config         *config.ServerConfig
	onlyoffice     *shared.OnlyofficeConfig
	oauth          *oauth2.Config
	logger         log.Logger
	session        *sessions.CookieStore
}

func NewAuthController(
	client client.Client,
	boxClient shared.BoxAPI,
	jwtManager crypto.JwtManager,
	store *sessions.CookieStore,
	stateGenerator crypto.StateGenerator,
	config *config.ServerConfig,
	onlyoffice *shared.OnlyofficeConfig,
	oauth *oauth2.Config,
	logger log.Logger,
	session *sessions.CookieStore,
) AuthController {
	return AuthController{
		client:         client,
		boxClient:      boxClient,
		jwtManager:     jwtManager,
		store:          store,
		stateGenerator: stateGenerator,
		config:         config,
		onlyoffice:     onlyoffice,
		oauth:          oauth,
		logger:         logger,
		session:        session,
	}
}

func (c AuthController) getRedirectURL(rw http.ResponseWriter, r *http.Request) string {
	session, _ := c.session.Get(r, "url")
	url := "https://app.box.com"

	if val, ok := session.Values["redirect"].(string); ok {
		url = val
	}

	session.Options.MaxAge = -1
	session.Save(r, rw)

	return url
}

func (c AuthController) BuildGetAuth() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/html")
		v, _ := cv.CreateCodeVerifier()
		verifier := v.String()
		errMsgs := map[string]interface{}{
			"errorMain":    "Installation Failed",
			"errorSubtext": "Please try again or contact admin",
			"closeButton":  "Close",
		}

		session, _ := c.store.Get(r, "onlyoffice-auth")
		state, err := c.stateGenerator.GenerateState(verifier)
		if err != nil {
			embeddable.InstallationErrorPage.Execute(rw, errMsgs)
			return
		}

		session.Values["state"] = state
		if err := session.Save(r, rw); err != nil {
			embeddable.InstallationErrorPage.Execute(rw, errMsgs)
			return
		}

		c.logger.Debug("redirecting to auth page")

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
		rw.Header().Set("Content-Type", "text/html")
		query := r.URL.Query()
		code, state := query.Get("code"), query.Get("state")
		errMsgs := map[string]interface{}{
			"errorMain":    "Installation Failed",
			"errorSubtext": "Please try again or contact admin",
			"closeButton":  "Close",
		}

		if code == "" {
			c.logger.Warn("could not request auth credentials. Invalid authorization code")
			embeddable.InstallationErrorPage.Execute(rw, errMsgs)
			return
		}

		c.logger.Debugf("auth code is valid: %s", code)

		if state == "" {
			c.logger.Warn("could not request auth credentials. Invalid state")
			embeddable.InstallationErrorPage.Execute(rw, errMsgs)
			return
		}

		c.logger.Debugf("auth state is not empty: %s", state)

		session, _ := c.store.Get(r, "onlyoffice-auth")
		sessState, ok := session.Values["state"].(string)
		if !ok {
			c.logger.Debug("can't cast session state")
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		if state != sessState {
			c.logger.Debugf("auth state %s doesn't match %s", state, sessState)
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		c.logger.Debugf("auth state is valid: %s", state)

		session.Options.MaxAge = -1
		if err := session.Save(r, rw); err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			embeddable.InstallationErrorPage.Execute(rw, errMsgs)
			return
		}

		c.logger.Debugf("auth state %s has been removed", state)

		credentials, err := c.boxClient.
			GetAuthCredentials(context.Background(), code, c.oauth.ClientID, c.oauth.ClientSecret)
		if err != nil {
			c.logger.Errorf("could not get user credentials: %s", err.Error())
			embeddable.InstallationErrorPage.Execute(rw, errMsgs)
			return
		}

		user, err := c.boxClient.GetMe(context.Background(), credentials.AccessToken)
		if err != nil {
			c.logger.Errorf("could not get user info: %s", err.Error())
			embeddable.InstallationErrorPage.Execute(rw, errMsgs)
			return
		}

		var resp interface{}
		if err := c.client.Call(
			r.Context(),
			c.client.NewRequest(
				fmt.Sprintf("%s:auth", c.config.Namespace), "UserInsertHandler.InsertUser", request.BoxUser{
					ID:           user.ID,
					AccessToken:  credentials.AccessToken,
					RefreshToken: credentials.RefreshToken,
					TokenType:    credentials.TokenType,
					ExpiresIn:    credentials.ExpiresIn,
				},
			), &resp, client.WithRetries(3)); err != nil {
			c.logger.Errorf("could not insert a new user: %s", err.Error())
			embeddable.InstallationErrorPage.Execute(rw, errMsgs)
			return
		}

		signature, err := c.jwtManager.Sign(c.oauth.ClientSecret, jwt.RegisteredClaims{
			ID:        user.ID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
		})

		if err != nil {
			c.logger.Errorf("could not issue a new jwt: %s", err.Error())
			embeddable.InstallationErrorPage.Execute(rw, errMsgs)
			return
		}

		session.Values["token"] = signature
		session.Values["locale"] = user.Language
		session.Options.MaxAge = 60 * 60 * 23 * 7
		if err := session.Save(r, rw); err != nil {
			c.logger.Errorf("could not save a new session cookie: %s", err.Error())
			embeddable.InstallationErrorPage.Execute(rw, errMsgs)
			return
		}

		http.Redirect(rw, r, c.getRedirectURL(rw, r), http.StatusMovedPermanently)
	}
}
