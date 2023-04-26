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

package handler

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/ONLYOFFICE/onlyoffice-box/pkg/config"
	"github.com/ONLYOFFICE/onlyoffice-box/pkg/crypto"
	plog "github.com/ONLYOFFICE/onlyoffice-box/pkg/log"
	"github.com/ONLYOFFICE/onlyoffice-box/pkg/onlyoffice"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/response"
	"github.com/mileusna/useragent"
	"go-micro.dev/v4/client"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

var _ErrOperationTimeout = errors.New("operation timeout")

type ConfigHandler struct {
	client      client.Client
	boxClient   shared.BoxAPI
	jwtManager  crypto.JwtManager
	hasher      crypto.Hasher
	fileUtil    onlyoffice.OnlyofficeFileUtility
	server      *config.ServerConfig
	credentials *oauth2.Config
	onlyoffice  *shared.OnlyofficeConfig
	logger      plog.Logger
	group       singleflight.Group
}

func NewConfigHandler(
	client client.Client,
	boxClient shared.BoxAPI,
	jwtManager crypto.JwtManager,
	hasher crypto.Hasher,
	fileUtil onlyoffice.OnlyofficeFileUtility,
	server *config.ServerConfig,
	credentials *oauth2.Config,
	onlyoffice *shared.OnlyofficeConfig,
	logger plog.Logger,
) ConfigHandler {
	return ConfigHandler{
		client:      client,
		boxClient:   boxClient,
		jwtManager:  jwtManager,
		hasher:      hasher,
		fileUtil:    fileUtil,
		server:      server,
		credentials: credentials,
		onlyoffice:  onlyoffice,
		logger:      logger,
	}
}

func (c ConfigHandler) processConfig(user response.UserResponse, req request.BoxState, ctx context.Context) (response.BuildConfigResponse, error) {
	var config response.BuildConfigResponse

	var ures response.UserResponse
	if err := c.client.Call(ctx, c.client.NewRequest(
		fmt.Sprintf("%s:auth", c.server.Namespace),
		"UserSelectHandler.GetUser", req.UserID,
	), &ures); err != nil {
		c.logger.Debugf("could not get user %s access info: %s", req.UserID, err.Error())
		return config, err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	errChan := make(chan error, 2)
	userChan := make(chan response.BoxUser, 1)
	fileChan := make(chan response.BoxFile, 1)

	go func() {
		defer wg.Done()
		userResp, err := c.boxClient.GetMe(ctx, ures.AccessToken)
		if err != nil {
			errChan <- err
			return
		}

		userChan <- userResp
	}()

	go func() {
		defer wg.Done()
		fileResp, err := c.boxClient.GetFileInfo(ctx, ures.AccessToken, req.FileID)
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
		return config, _ErrOperationTimeout
	default:
	}

	eType := "desktop"
	ua := useragent.Parse(req.UserAgent)

	if ua.Mobile || ua.Tablet {
		eType = "mobile"
	}

	file := <-fileChan
	usr := <-userChan

	url, err := c.boxClient.GetFilePublicUrl(ctx, ures.AccessToken, file.ID)
	if err != nil {
		return config, err
	}

	filename := c.fileUtil.EscapeFilename(file.Name)
	config = response.BuildConfigResponse{
		Document: response.Document{
			Key:   string(c.hasher.Hash(file.ModifiedAt)),
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
	}

	if strings.TrimSpace(filename) != "" {
		fileType, err := c.fileUtil.GetFileType(file.Extension)
		if err != nil {
			return config, err
		}

		config.Document.FileType = file.Extension
		config.Document.Permissions = response.Permissions{
			Edit:                 c.fileUtil.IsExtensionEditable(file.Extension),
			Comment:              true,
			Download:             true,
			Print:                false,
			Review:               false,
			Copy:                 true,
			ModifyContentControl: true,
			ModifyFilter:         true,
		}
		config.DocumentType = fileType
	}

	token, err := c.jwtManager.Sign(c.onlyoffice.Onlyoffice.Builder.DocumentServerSecret, config)
	if err != nil {
		c.logger.Debugf("could not sign document server config: %s", err.Error())
		return config, err
	}

	config.Token = token
	return config, nil
}

func (c ConfigHandler) BuildConfig(ctx context.Context, payload request.BoxState, res *response.BuildConfigResponse) error {
	c.logger.Debugf("processing a docs config: %s", payload.FileID)

	config, err, _ := c.group.Do(fmt.Sprintf("%s:%s", payload.UserID, payload.FileID), func() (interface{}, error) {
		req := c.client.NewRequest(
			fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser",
			fmt.Sprint(payload.UserID),
		)

		var ures response.UserResponse
		if err := c.client.Call(ctx, req, &ures); err != nil {
			c.logger.Debugf("could not get user %d access info: %s", payload.UserID, err.Error())
			return nil, err
		}

		config, err := c.processConfig(ures, payload, ctx)
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
