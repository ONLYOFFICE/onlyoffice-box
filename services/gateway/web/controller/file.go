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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/services/gateway/web/embeddable"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/format"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"go-micro.dev/v4/client"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
	"golang.org/x/sync/semaphore"
)

var (
	_ErrCsvIsNotSupported  = errors.New("csv conversion is not supported")
	_ErrFormatNotSupported = errors.New("format is not supported")
)

type FileController struct {
	client        client.Client
	boxClient     shared.BoxAPI
	jwtManager    crypto.JwtManager
	formatManager format.FormatManager
	hasher        crypto.Hasher
	credentials   *oauth2.Config
	server        *config.ServerConfig
	onlyoffice    *shared.OnlyofficeConfig
	sem           *semaphore.Weighted
	store         *sessions.CookieStore
	logger        log.Logger
}

func NewFileController(
	client client.Client, boxClient shared.BoxAPI, jwtManager crypto.JwtManager,
	credentials *oauth2.Config, formatManager format.FormatManager, hasher crypto.Hasher,
	server *config.ServerConfig, onlyoffice *shared.OnlyofficeConfig,
	store *sessions.CookieStore, logger log.Logger,
) FileController {
	return FileController{
		client:        client,
		boxClient:     boxClient,
		jwtManager:    jwtManager,
		formatManager: formatManager,
		hasher:        hasher,
		credentials:   credentials,
		server:        server,
		onlyoffice:    onlyoffice,
		sem:           semaphore.NewWeighted(int64(onlyoffice.Onlyoffice.Builder.AllowedDownloads)),
		store:         store,
		logger:        logger,
	}
}

func (c FileController) saveRedirectURL(rw http.ResponseWriter, r *http.Request) {
	session, _ := c.store.Get(r, "url")
	session.Values["redirect"] = c.onlyoffice.Onlyoffice.Builder.GatewayURL + r.URL.String()
	session.Save(r, rw)
}

func (c FileController) BuildConvertPage() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		fileID, userID := query.Get("file"), query.Get("user")
		loc := i18n.NewLocalizer(embeddable.Bundle, "en")
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

		if fileID == "" || userID == "" {
			embeddable.ErrorPage.ExecuteTemplate(rw, "error", errMsg)
			return
		}

		var ures response.UserResponse
		if err := c.client.Call(r.Context(), c.client.NewRequest(
			fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser",
			userID,
		), &ures); err != nil {
			c.logger.Debugf("could not get user %s access info: %s", userID, err.Error())
			c.saveRedirectURL(rw, r)
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		var wg sync.WaitGroup
		wg.Add(2)
		errChan := make(chan error, 2)
		userChan := make(chan response.BoxUserResponse, 1)
		fileChan := make(chan response.BoxFileResponse, 1)

		go func() {
			defer wg.Done()
			ures, err := c.boxClient.GetMe(r.Context(), ures.AccessToken)
			if err != nil {
				errChan <- err
				return
			}
			userChan <- ures
		}()

		go func() {
			defer wg.Done()
			fres, err := c.boxClient.GetFileInfo(r.Context(), ures.AccessToken, fileID)
			if err != nil {
				errChan <- err
				return
			}
			fileChan <- fres
		}()

		wg.Wait()

		select {
		case <-errChan:
			c.saveRedirectURL(rw, r)
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		default:
		}

		file := <-fileChan
		user := <-userChan

		session, err := c.store.Get(r, "onlyoffice-auth")
		if err == nil {
			session.Values["locale"] = user.Language
			session.Save(r, rw)
		}

		loc = i18n.NewLocalizer(embeddable.Bundle, user.Language)

		// Format checks are handled by box. In case of an unexpected event render try again page
		format, supported := c.formatManager.GetFormatByName(file.Extension)
		if !supported {
			embeddable.ErrorPage.ExecuteTemplate(rw, "error", errMsg)
			return
		}

		if !file.Permissions.CanUpload || format.IsEditable() || format.IsViewOnly() {
			http.Redirect(rw, r, fmt.Sprintf(
				"/editor?state=%s&user=%s",
				url.QueryEscape(string(request.ConvertRequestBody{
					Action: "edit",
					UserID: ures.ID,
					FileID: fileID,
				}.ToJSON())),
				userID,
			), http.StatusMovedPermanently)
			return
		}

		rw.Header().Set("Content-Type", "text/html")
		embeddable.ConvertPage.Execute(rw, map[string]interface{}{
			"CSRF":     csrf.Token(r),
			"OOXML":    file.Extension != "csv" && (format.IsOpenXMLConvertable() || format.IsLossyEditable()),
			"LossEdit": format.IsLossyEditable(),
			"User":     userID,
			"File":     fileID,
			"openOnlyoffice": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "openOnlyoffice",
			}),
			"cannotOpen": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "cannotOpen",
			}),
			"selectAction": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "selectAction",
			}),
			"openView": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "openView",
			}),
			"createOOXML": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "createOOXML",
			}),
			"editCopy": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "editCopy",
			}),
			"openEditing": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "openEditing",
			}),
			"moreInfo": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "moreInfo",
			}),
			"dataRestrictions": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "dataRestrictions",
			}),
			"openButton": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "openButton",
			}),
			"cancelButton": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "cancelButton",
			}),
			"errorMain": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "errorMain",
			}),
			"errorSubtext": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "errorSubtext",
			}),
			"reloadButton": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "reloadButton",
			}),
		})
	}
}

func (c FileController) BuildConvertFile() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		var body request.ConvertRequestBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			c.logger.Errorf("could not parse gdrive state: %s", err.Error())
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		switch body.Action {
		case "create":
			nbody, err := c.convertFile(r.Context(), body)
			if err != nil {
				http.Redirect(rw, r, "https://app.box.com", http.StatusMovedPermanently)
				return
			}
			http.Redirect(
				rw, r,
				fmt.Sprintf("/editor?state=%s&user=%s", url.QueryEscape(string(nbody.ToJSON())), nbody.UserID),
				http.StatusMovedPermanently,
			)
			return
		case "edit":
			body.ForceEdit = true
			http.Redirect(
				rw, r,
				fmt.Sprintf("/editor?state=%s&user=%s", url.QueryEscape(string(body.ToJSON())), body.UserID),
				http.StatusMovedPermanently,
			)
			return
		case "view":
			http.Redirect(
				rw, r,
				fmt.Sprintf(
					"/editor?state=%s&user=%s", url.QueryEscape(string(body.ToJSON())), body.UserID,
				),
				http.StatusMovedPermanently,
			)
			return
		default:
			http.Redirect(rw, r, "https://app.box.com", http.StatusMovedPermanently)
			return
		}
	}
}

// TODO: Use workers for async conversion
func (c FileController) convertFile(ctx context.Context, body request.ConvertRequestBody) (request.ConvertRequestBody, error) {
	if ok := c.sem.TryAcquire(1); !ok {
		c.logger.Errorf("could not acquire semaphore")
		return body, ErrSemaphoreNotAllowed
	}

	defer c.sem.Release(1)
	var ures response.UserResponse
	if err := c.client.Call(ctx, c.client.NewRequest(
		fmt.Sprintf("%s:auth", c.server.Namespace),
		"UserSelectHandler.GetUser", body.UserID,
	), &ures); err != nil {
		c.logger.Debugf("could not get user %s access info: %s", body.UserID, err.Error())
		return body, err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	errChan := make(chan error, 2)
	fInfoChan := make(chan response.BoxFileResponse, 1)
	urlChan := make(chan string, 1)

	go func() {
		defer wg.Done()
		fileInfo, err := c.boxClient.GetFileInfo(ctx, ures.AccessToken, body.FileID)
		if err != nil {
			c.logger.Errorf("could not get file %s info: %s", fileInfo.ID, err.Error())
			errChan <- err
			return
		}

		fInfoChan <- fileInfo
	}()

	go func() {
		defer wg.Done()
		durl, err := c.boxClient.GetFilePublicUrl(ctx, ures.AccessToken, body.FileID)
		if err != nil {
			c.logger.Errorf("could not get file %s url: %s", body.FileID, err.Error())
			errChan <- err
			return
		}

		urlChan <- durl
	}()

	wg.Wait()

	fileInfo := <-fInfoChan
	durl := <-urlChan

	if fileInfo.Extension == "csv" {
		return body, _ErrCsvIsNotSupported
	}

	format, supported := c.formatManager.GetFormatByName(fileInfo.Extension)
	if !supported {
		return body, _ErrFormatNotSupported
	}

	var cresp response.ConvertResponse
	creq := request.ConvertAPIRequest{
		Async:      false,
		Key:        string(c.hasher.Hash(fileInfo.ModifiedAt + fileInfo.ID)),
		Filetype:   format.GetOpenXMLExtension(),
		Outputtype: "ooxml",
		URL:        durl,
	}
	creq.IssuedAt = jwt.NewNumericDate(time.Now())
	creq.ExpiresAt = jwt.NewNumericDate(time.Now().Add(2 * time.Minute))
	ctok, err := c.jwtManager.Sign(c.onlyoffice.Onlyoffice.Builder.DocumentServerSecret, creq)
	if err != nil {
		c.logger.Errorf("could not sign a convert api request: %s", err.Error())
		return body, err
	}

	creq.Token = ctok
	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		fmt.Sprintf(
			"%s/converter?shardkey=%s",
			c.onlyoffice.Onlyoffice.Builder.DocumentServerURL,
			creq.Key,
		),
		bytes.NewBuffer(creq.ToJSON()),
	)

	if err != nil {
		c.logger.Debugf("could not build a conversion api request: %s", err.Error())
		return body, err
	}

	req.Header.Set("Accept", "application/json")
	resp, err := otelhttp.DefaultClient.Do(req)
	if err != nil {
		c.logger.Errorf("could not send a conversion api request: %s", err.Error())
		return body, err
	}

	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&cresp); err != nil {
		c.logger.Errorf("could not decode convert response body: %s", err.Error())
		return body, err
	}

	fresp, err := http.Get(cresp.FileURL)
	if err != nil {
		c.logger.Errorf("could not download a converted file: %s", err.Error())
		return body, err
	}

	folder := fileInfo.Parent.ID
	if fileInfo.CreatedBy.ID != body.UserID {
		folder = "0" // Root folder
	}

	defer fresp.Body.Close()
	nresp, err := c.boxClient.CreateFile(
		ctx, fmt.Sprintf("%s (%s).%s",
			strings.TrimSuffix(fileInfo.Name, filepath.Ext(fileInfo.Name)),
			time.Now().Format("2006-01-02 15:04:05.000"),
			cresp.FileType,
		),
		folder, ures.AccessToken, fresp.Body,
	)

	if err != nil {
		c.logger.Errorf("could not upload a converted file: %s", err.Error())
		return body, err
	}

	return request.ConvertRequestBody{
		Action:    body.Action,
		FileID:    nresp.Entries[0].ID,
		UserID:    body.UserID,
		ForceEdit: true,
	}, nil
}
