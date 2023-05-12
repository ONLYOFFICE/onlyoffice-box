package controller

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/pkg/config"
	"github.com/ONLYOFFICE/onlyoffice-box/pkg/crypto"
	"github.com/ONLYOFFICE/onlyoffice-box/pkg/log"
	"github.com/ONLYOFFICE/onlyoffice-box/services/gateway/web/embeddable"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/response"
	"github.com/gorilla/sessions"
	"go-micro.dev/v4/client"
)

type EditorController struct {
	client     client.Client
	jwtManager crypto.JwtManager
	store      *sessions.CookieStore
	server     *config.ServerConfig
	logger     log.Logger
}

func NewEditorController(
	client client.Client,
	jwtManager crypto.JwtManager,
	server *config.ServerConfig,
	logger log.Logger,
) EditorController {
	return EditorController{
		client:     client,
		jwtManager: jwtManager,
		server:     server,
		logger:     logger,
	}
}

func (c EditorController) BuildGetEditor() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/html")
		query := r.URL.Query()
		fileID, userID := query.Get("file"), query.Get("user")

		if fileID == "" || userID == "" {
			embeddable.ErrorPage.ExecuteTemplate(rw, "error", map[string]interface{}{
				"errorMain":    "Something went wrong",
				"errorSubtext": "Please reload the page",
				"reloadButton": "Reload",
			})
			return
		}

		tctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		var config response.BuildConfigResponse
		if err := c.client.Call(tctx, c.client.NewRequest(
			fmt.Sprintf("%s:builder", c.server.Namespace), "ConfigHandler.BuildConfig", request.BoxState{
				UserID:    userID,
				FileID:    fileID,
				UserAgent: r.UserAgent(),
			}), &config, client.WithRetries(3)); err != nil {
			c.logger.Errorf("could not build an editor config: %s", err.Error())
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		embeddable.EditorPage.Execute(rw, map[string]interface{}{
			"apijs":        fmt.Sprintf("%s/web-apps/apps/api/documents/api.js", config.ServerURL),
			"config":       string(config.ToJSON()),
			"docType":      config.DocumentType,
			"cancelButton": "Cancel",
		})
	}
}
