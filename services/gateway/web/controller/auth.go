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

func (c AuthController) renderErrorPage(rw http.ResponseWriter, errMsgs map[string]interface{}, err error) {
	c.logger.Warnf("rendeting error page due to: %v", err)
	embeddable.InstallationErrorPage.Execute(rw, errMsgs)
}

func (c AuthController) saveSession(rw http.ResponseWriter, r *http.Request, session *sessions.Session, errMsgs map[string]interface{}) error {
	if err := session.Save(r, rw); err != nil {
		c.renderErrorPage(rw, errMsgs, err)
		return err
	}

	return nil
}

func (c AuthController) getRedirectURL(rw http.ResponseWriter, r *http.Request) string {
	session, _ := c.session.Get(r, "url")
	redirectURL := session.Values["redirect"]
	session.Options.MaxAge = -1
	session.Save(r, rw)

	if url, ok := redirectURL.(string); ok {
		return url
	}

	return "https://app.box.com"
}

func (c AuthController) BuildGetAuth() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/html")

		verifier, _ := cv.CreateCodeVerifier()
		state, err := c.stateGenerator.GenerateState(verifier.String())
		errMsgs := map[string]interface{}{
			"errorMain":    "Installation Failed",
			"errorSubtext": "Please try again or contact admin",
			"closeButton":  "Close",
		}

		if err != nil {
			c.renderErrorPage(rw, errMsgs, err)
			return
		}

		session, _ := c.store.Get(r, "onlyoffice-auth")
		session.Values["state"] = state
		if err := c.saveSession(rw, r, session, errMsgs); err != nil {
			return
		}

		authURL := fmt.Sprintf(
			"https://account.box.com/api/oauth2/authorize?client_id=%s&response_type=code&state=%s",
			c.oauth.ClientID, url.QueryEscape(state),
		)

		http.Redirect(rw, r, authURL, http.StatusFound)
	}
}

func (c AuthController) BuildGetRedirect() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()

		rw.Header().Set("Content-Type", "text/html")
		query := r.URL.Query()
		code, state := query.Get("code"), query.Get("state")

		errMsgs := map[string]interface{}{
			"errorMain":    "Installation Failed",
			"errorSubtext": "Please try again or contact admin",
			"closeButton":  "Close",
		}

		if code == "" || state == "" {
			c.renderErrorPage(rw, errMsgs, fmt.Errorf("missing code or state"))
			return
		}

		session, _ := c.store.Get(r, "onlyoffice-auth")
		sessState, ok := session.Values["state"].(string)
		if !ok || state != sessState {
			c.renderErrorPage(rw, errMsgs, fmt.Errorf("state mismatch"))
			return
		}

		session.Options.MaxAge = -1
		if err := c.saveSession(rw, r, session, errMsgs); err != nil {
			return
		}

		credentials, err := c.boxClient.GetAuthCredentials(ctx, code, c.oauth.ClientID, c.oauth.ClientSecret)
		if err != nil {
			c.renderErrorPage(rw, errMsgs, err)
			return
		}

		user, err := c.boxClient.GetMe(ctx, credentials.AccessToken)
		if err != nil {
			c.renderErrorPage(rw, errMsgs, err)
			return
		}

		req := c.client.NewRequest(fmt.Sprintf("%s:auth", c.config.Namespace), "UserInsertHandler.InsertUser", request.BoxUser{
			ID:           user.ID,
			AccessToken:  credentials.AccessToken,
			RefreshToken: credentials.RefreshToken,
			TokenType:    credentials.TokenType,
			ExpiresIn:    credentials.ExpiresIn,
		})
		if err := c.client.Call(ctx, req, nil, client.WithRetries(3)); err != nil {
			c.renderErrorPage(rw, errMsgs, err)
			return
		}

		jwtToken, err := c.jwtManager.Sign(c.oauth.ClientSecret, jwt.RegisteredClaims{
			ID:        user.ID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
		})
		if err != nil {
			c.renderErrorPage(rw, errMsgs, err)
			return
		}

		session.Values["token"] = jwtToken
		session.Values["locale"] = user.Language
		session.Options.MaxAge = 60 * 60 * 23 * 7
		if err := c.saveSession(rw, r, session, errMsgs); err != nil {
			return
		}

		http.Redirect(rw, r, c.getRedirectURL(rw, r), http.StatusFound)
	}
}
