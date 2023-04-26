package controller

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"path"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/pkg/config"
	"github.com/ONLYOFFICE/onlyoffice-box/pkg/crypto"
	"github.com/ONLYOFFICE/onlyoffice-box/pkg/log"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/response"
	"github.com/gorilla/sessions"
	"go-micro.dev/v4/client"
)

var (
	_, b, _, _ = runtime.Caller(0)
	basepath   = filepath.Dir(b)
	editorPage = template.Must(template.ParseFiles(path.Join(basepath, "../", "templates", "editor.html")))
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
		query := r.URL.Query()
		fileID, userID := query.Get("file"), query.Get("user")

		if fileID == "" || userID == "" {
			// TODO: Render error page
			rw.WriteHeader(http.StatusBadRequest)
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

		rw.Header().Set("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval'; connect-src * 'unsafe-inline'; img-src * data: blob: 'unsafe-inline'; frame-src *; style-src * 'unsafe-inline'; script-src-elem * 'unsafe-inline'")
		editorPage.Execute(rw, map[string]interface{}{
			"apijs":   fmt.Sprintf("%s/web-apps/apps/api/documents/api.js", config.ServerURL),
			"config":  string(config.ToJSON()),
			"docType": config.DocumentType,
		})
	}
}
