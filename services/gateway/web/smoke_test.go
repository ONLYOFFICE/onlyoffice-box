/**
 *
 * (c) Copyright Ascensio System SIA 2026
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

package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/services/gateway/web/controller"
	"github.com/ONLYOFFICE/onlyoffice-box/services/gateway/web/middleware"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const (
	smokeSecret    = "smoke-client-secret-of-32-bytes!"
	smokeUser      = "1001"
	desktopUA      = "Mozilla/5.0 AscDesktopEditor/9.0"
	installPath    = "/oauth/install"
	boxAuthorizeAt = "https://account.box.com/api/oauth2/authorize"
)

func newSmokeGateway(t *testing.T) (http.Handler, func(userID string) *http.Cookie) {
	t.Helper()

	logger := log.NewEmptyLogger()
	jwtManager := crypto.NewJwtManager(&config.CryptoConfig{})
	credentials := &oauth2.Config{ClientID: "smoke-client", ClientSecret: smokeSecret}
	onlyoffice := &shared.OnlyofficeConfig{}
	onlyoffice.Onlyoffice.Builder.GatewayURL = "https://gateway.example"
	server := &config.ServerConfig{}
	server.Namespace = "box"

	store := middleware.NewSessionStore(credentials)
	srv := NewServer(
		controller.NewAuthController(
			nil, nil, jwtManager, store, crypto.NewStateGenerator(),
			server, onlyoffice, credentials, logger, store,
		),
		controller.NewDesktopController(nil, nil, server, logger),
		controller.NewEditorController(nil, server, store, logger),
		controller.FileController{},
		controller.NewShareController(server, nil, nil, logger),
		middleware.NewSessionMiddleware(jwtManager, store, credentials, onlyoffice, logger),
		middleware.NewDesktopMiddleware(logger),
		credentials,
	)

	signIn := func(userID string) *http.Cookie {
		token, err := jwtManager.Sign(smokeSecret, jwt.RegisteredClaims{
			ID:        userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rw := httptest.NewRecorder()
		session, _ := store.Get(req, "onlyoffice-auth")
		session.Values["token"] = token
		require.NoError(t, session.Save(req, rw))

		cookies := rw.Result().Cookies()
		require.NotEmpty(t, cookies)
		return cookies[0]
	}

	return srv.NewHandler(), signIn
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	return rw
}

func TestSmokeGateway(t *testing.T) {
	h, signIn := newSmokeGateway(t)

	t.Run("root leads to the installation", func(t *testing.T) {
		rw := serve(h, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, http.StatusMovedPermanently, rw.Code)
		assert.Equal(t, installPath, rw.Header().Get("Location"))
	})

	t.Run("unknown page answers 404", func(t *testing.T) {
		rw := serve(h, httptest.NewRequest(http.MethodGet, "/no-such-page", nil))
		assert.Equal(t, http.StatusNotFound, rw.Code)
	})

	t.Run("installation redirects to Box OAuth with a state", func(t *testing.T) {
		rw := serve(h, httptest.NewRequest(http.MethodGet, installPath, nil))
		require.Equal(t, http.StatusFound, rw.Code)

		location, err := url.Parse(rw.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, boxAuthorizeAt, location.Scheme+"://"+location.Host+location.Path)
		assert.Equal(t, "smoke-client", location.Query().Get("client_id"))
		assert.Equal(t, "code", location.Query().Get("response_type"))
		assert.NotEmpty(t, location.Query().Get("state"))
		assert.NotEmpty(t, rw.Result().Cookies(), "the state must be kept in a session cookie")
	})

	t.Run("oauth redirect refuses a foreign state", func(t *testing.T) {
		rw := serve(h, httptest.NewRequest(http.MethodGet, "/oauth/redirect?code=c&state=forged", nil))
		assert.NotEqual(t, http.StatusFound, rw.Code, "must render an error page, not sign in")
	})

	t.Run("editor without a session leads to the installation", func(t *testing.T) {
		rw := serve(h, httptest.NewRequest(http.MethodGet, "/editor?state={}", nil))
		assert.Equal(t, http.StatusMovedPermanently, rw.Code)
		assert.Equal(t, installPath, rw.Header().Get("Location"))
	})

	t.Run("editor for another user leads to the installation", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/editor?user=2002&state={}", nil)
		req.AddCookie(signIn(smokeUser))
		rw := serve(h, req)
		assert.Equal(t, http.StatusMovedPermanently, rw.Code)
		assert.Equal(t, installPath, rw.Header().Get("Location"))
	})

	t.Run("editor refuses a state naming another user", func(t *testing.T) {
		state := url.QueryEscape(`{"action":"edit","user_id":"2002","file_id":"1"}`)
		req := httptest.NewRequest(http.MethodGet, "/editor?state="+state, nil)
		req.AddCookie(signIn(smokeUser))
		rw := serve(h, req)
		assert.Equal(t, http.StatusForbidden, rw.Code)
	})

	t.Run("desktop endpoints refuse browsers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/app/ai", nil)
		req.AddCookie(signIn(smokeUser))
		rw := serve(h, req)
		assert.Equal(t, http.StatusForbidden, rw.Code)
	})

	t.Run("desktop endpoints need a session", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/app/ai", nil)
		req.Header.Set("User-Agent", desktopUA)
		rw := serve(h, req)
		assert.Equal(t, http.StatusMovedPermanently, rw.Code)
		assert.Equal(t, installPath, rw.Header().Get("Location"))
	})

	t.Run("desktop AI capabilities answer a signed-in desktop", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/app/ai", nil)
		req.Header.Set("User-Agent", desktopUA)
		req.Header.Set("Origin", "onlyoffice://plugin")
		req.AddCookie(signIn(smokeUser))
		rw := serve(h, req)

		require.Equal(t, http.StatusOK, rw.Code)
		assert.Equal(t, "onlyoffice://plugin", rw.Header().Get("Access-Control-Allow-Origin"))
		var body map[string]any
		require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &body))
		assert.Equal(t, "box", body["provider"])
	})

	t.Run("desktop download refuses a non-numeric file id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/app/download?file=../etc", nil)
		req.Header.Set("User-Agent", desktopUA)
		req.AddCookie(signIn(smokeUser))
		rw := serve(h, req)
		assert.Equal(t, http.StatusBadRequest, rw.Code)
	})
}
