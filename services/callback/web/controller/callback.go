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

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/services/shared"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	plog "github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/onlyoffice"
	"go-micro.dev/v4/client"
	"go-micro.dev/v4/util/backoff"
)

type CallbackController struct {
	client     client.Client
	jwtManger  crypto.JwtManager
	fileUtil   onlyoffice.OnlyofficeFileUtility
	boxAPI     shared.BoxAPI
	server     *config.ServerConfig
	onlyoffice *shared.OnlyofficeConfig
	logger     plog.Logger
}

func NewCallbackController(
	client client.Client,
	jwtManger crypto.JwtManager,
	fileUtil onlyoffice.OnlyofficeFileUtility,
	boxAPI shared.BoxAPI,
	server *config.ServerConfig,
	onlyoffice *shared.OnlyofficeConfig,
	logger plog.Logger,
) CallbackController {
	return CallbackController{
		client:     client,
		jwtManger:  jwtManger,
		fileUtil:   fileUtil,
		boxAPI:     boxAPI,
		server:     server,
		onlyoffice: onlyoffice,
		logger:     logger,
	}
}

func (c CallbackController) uploadFile(user, url, fileID, filename string) error {
	ctx, cancel := context.WithTimeout(
		context.Background(), time.Duration(
			c.onlyoffice.Onlyoffice.Callback.UploadTimeout,
		)*time.Second,
	)

	defer cancel()

	c.logger.Debugf("user %s is uploading a new file", user)
	var wg sync.WaitGroup
	wg.Add(2)
	errChan := make(chan error, 2)
	userChan := make(chan response.UserResponse, 1)
	fileChan := make(chan io.ReadCloser, 1)

	go func() {
		defer wg.Done()
		req := c.client.NewRequest(
			fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser", user,
		)

		var ures response.UserResponse
		if err := c.client.Call(ctx, req, &ures, client.WithRetries(3), client.WithBackoff(func(ctx context.Context, req client.Request, attempts int) (time.Duration, error) {
			return backoff.Do(attempts), nil
		})); err != nil {
			c.logger.Errorf("could not get user credentials: %s", err.Error())
			errChan <- err
			return
		}

		userChan <- ures
	}()

	go func() {
		defer wg.Done()
		resp, err := http.Get(url)
		if err != nil {
			c.logger.Errorf("could not download a new file: %s", err.Error())
			errChan <- err
			return
		}

		fileChan <- resp.Body
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		c.logger.Error("file upload timeout")
		return http.ErrHandlerTimeout
	default:
	}

	ures := <-userChan
	body := <-fileChan
	defer body.Close()

	if err := c.boxAPI.UploadFile(ctx, filename, ures.AccessToken, fileID, body); err != nil {
		c.logger.Errorf("could not upload file %s: %s", filename, err.Error())
		return err
	}

	return nil
}

func (c CallbackController) BuildPostHandleCallback() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")

		fileID := strings.TrimSpace(r.URL.Query().Get("id"))
		if fileID == "" {
			c.logger.Error("file id is empty")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write(response.CallbackResponse{
				Error: 1,
			}.ToJSON())
			return
		}

		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			c.logger.Error("file name is empty")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write(response.CallbackResponse{
				Error: 1,
			}.ToJSON())
			return
		}

		var body request.CallbackRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			c.logger.Errorf("could not decode a callback body")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write(response.CallbackResponse{
				Error: 1,
			}.ToJSON())
			return
		}

		if body.Token == "" {
			c.logger.Error("invalid callback body token")
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write(response.CallbackResponse{
				Error: 1,
			}.ToJSON())
			return
		}

		if err := c.jwtManger.Verify(c.onlyoffice.Onlyoffice.Builder.DocumentServerSecret, body.Token, &body); err != nil {
			c.logger.Errorf("could not verify callback jwt (%s). Reason: %s", body.Token, err.Error())
			rw.WriteHeader(http.StatusForbidden)
			rw.Write(response.CallbackResponse{
				Error: 1,
			}.ToJSON())
			return
		}

		if err := body.Validate(); err != nil {
			c.logger.Errorf("invalid callback body. Reason: %s", err.Error())
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write(response.CallbackResponse{
				Error: 1,
			}.ToJSON())
			return
		}

		if body.Status == 2 {
			tctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
			defer cancel()
			if err := c.fileUtil.ValidateFileSize(
				tctx, c.onlyoffice.Onlyoffice.Callback.MaxSize, body.URL,
			); err != nil {
				rw.WriteHeader(http.StatusForbidden)
				c.logger.Warnf("file %s size exceeds the limit", body.Key)
				rw.Write(response.CallbackResponse{
					Error: 1,
				}.ToJSON())
				return
			}

			usr := body.Users[0]
			if usr != "" {
				if err := c.uploadFile(usr, body.URL, fileID, name); err != nil {
					rw.WriteHeader(http.StatusBadRequest)
					rw.Write(response.CallbackResponse{
						Error: 1,
					}.ToJSON())
					return
				}

				c.logger.Debugf("user %s has uploaded a new file", usr)
			}
		}

		rw.WriteHeader(http.StatusOK)
		rw.Write(response.CallbackResponse{
			Error: 0,
		}.ToJSON())
	}
}
