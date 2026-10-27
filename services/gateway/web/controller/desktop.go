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

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
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

const aiInterfaceVersion = 1
const desktopPluginOrigin = "onlyoffice://plugin"

var boxAPIURL = "https://api.box.com/2.0"
var boxFileID = regexp.MustCompile(`^[0-9]+$`)

var errBoxFileNotFound = errors.New("box file not found")

// downloadClient asks Box for a download without following its redirect: the
// redirect's target, a short-lived signed URL, is the answer.
var downloadClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

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

// allowDesktopPlugin lets ONLYOFFICE Desktop's plugins read a response sent to
// their session cookie. A wildcard Access-Control-Allow-Origin never exposes a
// response to a request with credentials, so the plugin origin is allowed by
// name and every other origin is denied.
func allowDesktopPlugin(rw http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") == desktopPluginOrigin {
		rw.Header().Set("Access-Control-Allow-Origin", desktopPluginOrigin)
		rw.Header().Set("Access-Control-Allow-Credentials", "true")
		return
	}

	rw.Header().Del("Access-Control-Allow-Origin")
	rw.Header().Del("Access-Control-Allow-Credentials")
}

func resolveBoxDownload(ctx context.Context, token, fileID string) (string, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, fmt.Sprintf("%s/files/%s/content", boxAPIURL, fileID), nil,
	)

	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	res, err := downloadClient.Do(req)
	if err != nil {
		return "", err
	}

	defer res.Body.Close()

	switch {
	case res.StatusCode >= 300 && res.StatusCode < 400 && res.Header.Get("Location") != "":
		return res.Header.Get("Location"), nil
	case res.StatusCode == http.StatusNotFound:
		return "", errBoxFileNotFound
	default:
		return "", fmt.Errorf("box answered %d to a download of file %s", res.StatusCode, fileID)
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

		ctx, cancel := context.WithTimeout(r.Context(), userCallTimeout)
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

// BuildGetCapabilities tells ONLYOFFICE Desktop's AI agent that this
// integration supports its cloud interface: the agent lists a signed-in cloud
// in the chat only when its gateway answers here with the provider it expects.
func (c *DesktopController) BuildGetCapabilities() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		allowDesktopPlugin(rw, r)
		rw.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(rw).Encode(map[string]any{
			"provider": "box",
			"version":  aiInterfaceVersion,
		}); err != nil {
			c.logger.Errorf("could not encode the AI capabilities: %s", err.Error())
		}
	}
}

// BuildGetToken hands ONLYOFFICE Desktop's AI agent the current Box access
// token of the signed-in user, with the user id the editor links carry, so
// the agent can call Box itself. The auth service refreshes the token before
// it expires.
func (c *DesktopController) BuildGetToken() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		allowDesktopPlugin(rw, r)

		rw.Header().Set("Content-Type", "application/json")
		uid, ok := r.Context().Value(middleware.UserIDKey).(string)
		if !ok || uid == "" {
			http.Error(rw, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), userCallTimeout)
		defer cancel()

		var ures response.UserResponse
		if err := c.client.Call(ctx, c.client.NewRequest(
			fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser",
			uid,
		), &ures); err != nil {
			c.logger.Errorf("could not get user %s access info: %s", uid, err.Error())
			http.Error(rw, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		if err := json.NewEncoder(rw).Encode(map[string]string{
			"access_token": ures.AccessToken,
			"expires_at":   time.UnixMilli(ures.ExpiresAt).UTC().Format(time.RFC3339),
			"user_id":      uid,
		}); err != nil {
			c.logger.Errorf("could not encode the access token of user %s: %s", uid, err.Error())
		}
	}
}

// userToken is the signed-in user's Box access token, refreshed by the auth
// service when it is about to expire.
func (c *DesktopController) userToken(ctx context.Context, uid string) (string, error) {
	var ures response.UserResponse
	if err := c.client.Call(ctx, c.client.NewRequest(
		fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser",
		uid,
	), &ures); err != nil {
		return "", err
	}

	return ures.AccessToken, nil
}

func (c *DesktopController) buildGetDownload(
	token func(ctx context.Context, uid string) (string, error),
) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		uid, ok := r.Context().Value(middleware.UserIDKey).(string)
		if !ok || uid == "" {
			http.Error(rw, "unauthorized", http.StatusUnauthorized)
			return
		}

		fileID := r.URL.Query().Get("file")
		if !boxFileID.MatchString(fileID) {
			http.Error(rw, "file must be a Box file id", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		accessToken, err := token(ctx, uid)
		if err != nil {
			c.logger.Errorf("could not get user %s access info: %s", uid, err.Error())
			http.Error(rw, "unauthorized", http.StatusUnauthorized)
			return
		}

		location, err := resolveBoxDownload(ctx, accessToken, fileID)
		if errors.Is(err, errBoxFileNotFound) {
			http.Error(rw, "not found", http.StatusNotFound)
			return
		}
		if err != nil {
			c.logger.Errorf("could not resolve a download of file %s for user %s: %s", fileID, uid, err.Error())
			http.Error(rw, "box is unavailable", http.StatusBadGateway)
			return
		}

		http.Redirect(rw, r, location, http.StatusFound)
	}
}

// BuildGetDownload lets ONLYOFFICE Desktop's native downloader fetch a Box file
// for the AI agent: the downloader sends the session cookie but no
// Authorization, so the gateway asks Box with the user's token and redirects
// to the signed URL Box answers with.
func (c *DesktopController) BuildGetDownload() http.HandlerFunc {
	return c.buildGetDownload(c.userToken)
}
