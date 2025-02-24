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

package handler

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/services/shared"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/format"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	plog "github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/mileusna/useragent"
	"go-micro.dev/v4/client"
	"golang.org/x/sync/singleflight"
)

var (
	errOperationTimeout   = errors.New("operation timeout")
	errFormatNotSupported = errors.New("current format is not supported")
	group                 singleflight.Group
)

type ConfigHandler struct {
	client        client.Client
	boxClient     shared.BoxAPI
	jwtManager    crypto.JwtManager
	hasher        crypto.Hasher
	formatManager format.FormatManager
	server        *config.ServerConfig
	onlyoffice    *shared.OnlyofficeConfig
	logger        plog.Logger
}

func NewConfigHandler(
	client client.Client,
	boxClient shared.BoxAPI,
	jwtManager crypto.JwtManager,
	hasher crypto.Hasher,
	formatManager format.FormatManager,
	server *config.ServerConfig,
	onlyoffice *shared.OnlyofficeConfig,
	logger plog.Logger,
) ConfigHandler {
	return ConfigHandler{
		client:        client,
		boxClient:     boxClient,
		jwtManager:    jwtManager,
		hasher:        hasher,
		formatManager: formatManager,
		server:        server,
		onlyoffice:    onlyoffice,
		logger:        logger,
	}
}

func (c ConfigHandler) processConfig(
	ctx context.Context,
	user response.UserResponse,
	req request.BoxState,
) (response.BuildConfigResponse, error) {
	var config response.BuildConfigResponse
	var wg sync.WaitGroup

	wg.Add(2)
	errChan := make(chan error, 2)
	userChan := make(chan response.BoxUserResponse, 1)
	fileChan := make(chan response.BoxFileResponse, 1)

	go func() {
		defer wg.Done()
		userResp, err := c.boxClient.GetMe(ctx, user.AccessToken)
		if err != nil {
			errChan <- err
			return
		}

		userChan <- userResp
	}()

	go func() {
		defer wg.Done()
		fileResp, err := c.boxClient.GetFileInfo(ctx, user.AccessToken, req.FileID)
		if err != nil {
			errChan <- err
			return
		}

		fileChan <- fileResp
	}()

	c.logger.Debug("waiting for goroutines to finish")
	wg.Wait()
	c.logger.Debug("goroutines have finished")

	select {
	case err := <-errChan:
		return config, err
	case <-ctx.Done():
		return config, errOperationTimeout
	default:
	}

	eType := "desktop"
	ua := useragent.Parse(req.UserAgent)

	if ua.Mobile || ua.Tablet {
		eType = "mobile"
	}

	file := <-fileChan
	usr := <-userChan

	url, err := c.boxClient.GetFilePublicUrl(ctx, user.AccessToken, file.ID)
	if err != nil {
		return config, err
	}

	filename := c.formatManager.EscapeFileName(file.Name)
	config = response.BuildConfigResponse{
		Document: response.Document{
			Key:   string(c.hasher.Hash(file.ModifiedAt + file.ID)),
			Title: filename,
			URL:   url,
		},
		EditorConfig: response.EditorConfig{
			User: response.User{
				ID:   usr.ID,
				Name: usr.Name,
			},
			CallbackURL: fmt.Sprintf(
				"%s/callback?id=%s&name=%s",
				c.onlyoffice.Onlyoffice.Builder.CallbackURL, file.ID, file.Name,
			),
			Customization: response.Customization{
				Goback: response.Goback{
					RequestClose: false,
				},
				Plugins:       false,
				HideRightMenu: false,
			},
			Lang: usr.Language,
		},
		Type:      eType,
		ServerURL: c.onlyoffice.Onlyoffice.Builder.DocumentServerURL,
		Owner:     usr.ID == file.CreatedBy.ID,
	}

	if strings.TrimSpace(filename) != "" {
		format, supported := c.formatManager.GetFormatByName(file.Extension)
		if !supported {
			return config, errFormatNotSupported
		}

		config.Document.FileType = file.Extension
		config.Document.Permissions = response.Permissions{
			Edit:                 file.Permissions.CanUpload && (format.IsEditable() || (req.ForceEdit && format.IsLossyEditable())),
			Comment:              file.Permissions.CanComment,
			Download:             file.Permissions.CanDownload,
			Print:                file.Permissions.CanDownload,
			Review:               false,
			Copy:                 true,
			ModifyContentControl: true,
			ModifyFilter:         true,
			FillForms:            format.IsFillable(),
		}

		if !config.Document.Permissions.Edit {
			config.Document.Key = uuid.NewString()
		}

		config.DocumentType = format.Type
	}

	config.ExpiresAt = jwt.NewNumericDate(time.Now().Add(2 * time.Minute))
	token, err := c.jwtManager.Sign(c.onlyoffice.Onlyoffice.Builder.DocumentServerSecret, config)
	if err != nil {
		c.logger.Debugf("could not sign document server config: %s", err.Error())
		return config, err
	}

	config.Token = token
	return config, nil
}

func (c ConfigHandler) BuildConfig(
	ctx context.Context,
	payload request.BoxState,
	res *response.BuildConfigResponse,
) error {
	c.logger.Debugf("processing a docs config: %s", payload.FileID)

	config, err, _ := group.Do(fmt.Sprintf("%s:%s", payload.UserID, payload.FileID), func() (interface{}, error) {
		req := c.client.NewRequest(
			fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser",
			fmt.Sprint(payload.UserID),
		)

		var ures response.UserResponse
		if err := c.client.Call(ctx, req, &ures); err != nil {
			c.logger.Debugf("could not get user %d access info: %s", payload.UserID, err.Error())
			return nil, err
		}

		config, err := c.processConfig(ctx, ures, payload)
		if err != nil {
			return nil, err
		}

		return config, nil
	})

	if cfg, ok := config.(response.BuildConfigResponse); ok {
		*res = cfg
		return nil
	}

	return err
}
