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

	"github.com/ONLYOFFICE/onlyoffice-box/services/gateway/web/embeddable"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/gorilla/sessions"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"go-micro.dev/v4/client"
)

type EditorController struct {
	client client.Client
	server *config.ServerConfig
	store  *sessions.CookieStore
	logger log.Logger
}

func NewEditorController(
	client client.Client,
	server *config.ServerConfig,
	store *sessions.CookieStore,
	logger log.Logger,
) EditorController {
	return EditorController{
		client: client,
		server: server,
		store:  store,
		logger: logger,
	}
}

func (c EditorController) BuildGetEditor() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		var state request.ConvertRequestBody
		session, err := c.store.Get(r, "onlyoffice-auth")
		lang := "en"
		if err == nil {
			if ln, ok := session.Values["locale"].(string); ok {
				lang = ln
			}
		}

		loc := i18n.NewLocalizer(embeddable.Bundle, lang)
		errMsg := map[string]interface{}{
			"errorMain": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "errorMain",
			}),
			"errorSubtext": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "errorSubtext",
			}),
			"reloadButton": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "reloadButton",
			}),
		}

		if err := json.Unmarshal([]byte(r.URL.Query().Get("state")), &state); err != nil {
			embeddable.ErrorPage.ExecuteTemplate(rw, "error", errMsg)
			return
		}

		tctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		var config response.BuildConfigResponse
		if err := c.client.Call(tctx, c.client.NewRequest(
			fmt.Sprintf("%s:builder", c.server.Namespace), "ConfigHandler.BuildConfig", request.BoxState{
				UserID:    state.UserID,
				FileID:    state.FileID,
				UserAgent: r.UserAgent(),
				ForceEdit: state.ForceEdit,
			}), &config, client.WithRetries(3)); err != nil {
			c.logger.Errorf("could not build an editor config: %s", err.Error())
			embeddable.ErrorPage.ExecuteTemplate(rw, "error", errMsg)
			return
		}

		rw.Header().Set("Content-Type", "text/html")
		embeddable.EditorPage.Execute(rw, map[string]interface{}{
			"apijs":   fmt.Sprintf("%s/web-apps/apps/api/documents/api.js", config.ServerURL),
			"config":  string(config.ToJSON()),
			"docType": config.DocumentType,
			"cancelButton": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "cancelButton",
			}),
		})
	}
}
