package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/pkg/config"
	"github.com/ONLYOFFICE/onlyoffice-box/pkg/log"
	"github.com/ONLYOFFICE/onlyoffice-box/services/gateway/web/embeddable"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/response"
	"go-micro.dev/v4/client"
)

type EditorController struct {
	client client.Client
	server *config.ServerConfig
	logger log.Logger
}

func NewEditorController(
	client client.Client,
	server *config.ServerConfig,
	logger log.Logger,
) EditorController {
	return EditorController{
		client: client,
		server: server,
		logger: logger,
	}
}

func (c EditorController) BuildGetEditor() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/html")
		var state request.ConvertRequestBody
		if err := json.Unmarshal([]byte(r.URL.Query().Get("state")), &state); err != nil {
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
				UserID:    state.UserID,
				FileID:    state.FileID,
				UserAgent: r.UserAgent(),
				ForceEdit: state.ForceEdit,
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
