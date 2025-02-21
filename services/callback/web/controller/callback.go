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
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/services/shared"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	plog "github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"go-micro.dev/v4/client"
	"go-micro.dev/v4/util/backoff"
)

var ErrInvalidContentLength = errors.New("content length exceeds the limit")

type CallbackController struct {
	client     client.Client
	jwtManager crypto.JwtManager
	boxAPI     shared.BoxAPI
	server     *config.ServerConfig
	onlyoffice *shared.OnlyofficeConfig
	logger     plog.Logger
}

func NewCallbackController(
	client client.Client,
	jwtManager crypto.JwtManager,
	boxAPI shared.BoxAPI,
	server *config.ServerConfig,
	onlyoffice *shared.OnlyofficeConfig,
	logger plog.Logger,
) CallbackController {
	return CallbackController{
		client:     client,
		jwtManager: jwtManager,
		boxAPI:     boxAPI,
		server:     server,
		onlyoffice: onlyoffice,
		logger:     logger,
	}
}

func (c *CallbackController) validateFileSize(ctx context.Context, limit int64, url string) error {
	resp, err := http.Head(url)
	if err != nil {
		return fmt.Errorf("failed to fetch file metadata: %w", err)
	}
	defer resp.Body.Close()

	contentLength, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid content-length: %w", err)
	}
	if contentLength > limit {
		return ErrInvalidContentLength
	}

	return nil
}

func (c *CallbackController) uploadFile(user, url, fileID, filename string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.onlyoffice.Onlyoffice.Callback.UploadTimeout)*time.Second)
	defer cancel()

	c.logger.Debugf("user %s is uploading a file", user)

	var wg sync.WaitGroup
	errChan := make(chan error, 2)
	userChan := make(chan response.UserResponse, 1)
	fileChan := make(chan io.ReadCloser, 1)

	wg.Add(2)

	go c.fetchUser(ctx, user, userChan, errChan, &wg)
	go c.fetchFile(url, fileChan, errChan, &wg)

	wg.Wait()
	close(errChan)

	if err := <-errChan; err != nil {
		return err
	}

	ures := <-userChan
	fileBody := <-fileChan
	defer fileBody.Close()

	return c.boxAPI.UploadFile(ctx, filename, ures.AccessToken, fileID, fileBody)
}

func (c *CallbackController) fetchUser(ctx context.Context, user string, userChan chan<- response.UserResponse, errChan chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()
	req := c.client.NewRequest(fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser", user)
	var ures response.UserResponse

	err := c.client.Call(ctx, req, &ures, client.WithRetries(3), client.WithBackoff(func(
		ctx context.Context, req client.Request, attempts int,
	) (time.Duration, error) {
		return backoff.Do(attempts), nil
	}))

	if err != nil {
		c.logger.Errorf("failed to fetch user credentials: %v", err)
		errChan <- err
		return
	}

	userChan <- ures
}

func (c *CallbackController) fetchFile(url string, fileChan chan<- io.ReadCloser, errChan chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()
	resp, err := http.Get(url)
	if err != nil {
		c.logger.Errorf("failed to download file: %v", err)
		errChan <- err
		return
	}
	fileChan <- resp.Body
}

func (c *CallbackController) handleError(rw http.ResponseWriter, statusCode int, message string, err error) {
	c.logger.Errorf("%s: %v", message, err)
	rw.WriteHeader(statusCode)
	rw.Write(response.CallbackResponse{Error: 1}.ToJSON())
}

func (c *CallbackController) BuildPostHandleCallback() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")

		fileID := strings.TrimSpace(r.URL.Query().Get("id"))
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if fileID == "" || name == "" {
			c.handleError(rw, http.StatusBadRequest, "missing file id or name", nil)
			return
		}

		var body request.CallbackRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			c.handleError(rw, http.StatusBadRequest, "invalid request body", err)
			return
		}

		if err := c.jwtManager.Verify(c.onlyoffice.Onlyoffice.Builder.DocumentServerSecret, body.Token, &body); err != nil {
			c.handleError(rw, http.StatusForbidden, "invalid JWT", err)
			return
		}

		if err := body.Validate(); err != nil {
			c.handleError(rw, http.StatusBadRequest, "invalid callback body", err)
			return
		}

		if body.Status == 2 {
			tctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
			defer cancel()

			if err := c.validateFileSize(tctx, c.onlyoffice.Onlyoffice.Callback.MaxSize, body.URL); err != nil {
				c.handleError(rw, http.StatusForbidden, "file size exceeds limit", err)
				return
			}

			if len(body.Users) > 0 && body.Users[0] != "" {
				if err := c.uploadFile(body.Users[0], body.URL, fileID, name); err != nil {
					c.handleError(rw, http.StatusInternalServerError, "file upload failed", err)
					return
				}
				c.logger.Debugf("user %s uploaded a file successfully", body.Users[0])
			}
		}

		rw.WriteHeader(http.StatusOK)
		rw.Write(response.CallbackResponse{Error: 0}.ToJSON())
	}
}
