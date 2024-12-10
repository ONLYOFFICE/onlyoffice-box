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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
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
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"golang.org/x/text/language"
)

var (
	errCsvIsNotSupported               = errors.New("csv conversion is not supported")
	errFormatNotSupported              = errors.New("format is not supported")
	errConversionErrorOccurred         = errors.New("could not convert current file")
	errConversionAutoFormatError       = errors.New("could not detect xml format automatically")
	errConversionPasswordRequiredError = errors.New("could not convert protected file")
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

func (c FileController) getUserAccessToken(
	ctx context.Context,
	userID string,
) (response.UserResponse, error) {
	var ures response.UserResponse
	if err := c.client.Call(ctx, c.client.NewRequest(
		fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser",
		userID,
	), &ures); err != nil {
		c.logger.Debugf("could not get user %s access info: %s", userID, err.Error())
		return ures, err
	}
	return ures, nil
}

func (c FileController) getBoxUserAndFileInfo(
	ctx context.Context,
	accessToken, fileID string,
) (user response.BoxUserResponse, file response.BoxFileResponse, err error) {
	var eg errgroup.Group
	var ures response.BoxUserResponse
	var fres response.BoxFileResponse

	eg.Go(func() error {
		var err error
		ures, err = c.boxClient.GetMe(ctx, accessToken)
		return err
	})

	eg.Go(func() error {
		var err error
		fres, err = c.boxClient.GetFileInfo(ctx, accessToken, fileID)
		return err
	})

	if err := eg.Wait(); err != nil {
		return response.BoxUserResponse{}, response.BoxFileResponse{}, err
	}

	return ures, fres, nil
}

func (c FileController) getLocalizedMessages(
	loc *i18n.Localizer,
	messageIDs []string,
) map[string]interface{} {
	localized := make(map[string]interface{})
	for _, msgID := range messageIDs {
		localized[msgID] = loc.MustLocalize(&i18n.LocalizeConfig{
			MessageID: msgID,
		})
	}
	return localized
}

func (c FileController) BuildConvertPage() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		fileID, userID := query.Get("file"), query.Get("user")
		loc := i18n.NewLocalizer(embeddable.Bundle, "en")

		errMessages := []string{"errorMain", "errorSubtext", "reloadButton"}
		errMsg := c.getLocalizedMessages(loc, errMessages)

		if fileID == "" || userID == "" {
			embeddable.ErrorPage.ExecuteTemplate(rw, "error", errMsg)
			return
		}

		ures, err := c.getUserAccessToken(r.Context(), userID)
		if err != nil {
			c.logger.Debugf("could not get user %s access info: %s", userID, err.Error())
			c.saveRedirectURL(rw, r)
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		user, file, err := c.getBoxUserAndFileInfo(r.Context(), ures.AccessToken, fileID)
		if err != nil {
			c.saveRedirectURL(rw, r)
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		session, err := c.store.Get(r, "onlyoffice-auth")
		if err == nil {
			session.Values["locale"] = user.Language
			session.Save(r, rw)
		}

		loc = i18n.NewLocalizer(embeddable.Bundle, user.Language)

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

		messageIDs := []string{
			"openOnlyoffice", "cannotOpen", "selectAction", "openView", "createOOXML", "editCopy",
			"openEditing", "moreInfo", "dataRestrictions", "openButton", "cancelButton",
			"errorMain", "errorSubtext", "reloadButton", "documentType", "spreadsheetType",
			"passwordRequired", "xmlInformation",
		}
		localizedMessages := c.getLocalizedMessages(loc, messageIDs)

		data := map[string]interface{}{
			"CSRF":     csrf.Token(r),
			"OOXML":    file.Extension != "csv" && (format.IsOpenXMLConvertable() || format.IsLossyEditable()),
			"IsXML":    file.Extension == "xml",
			"LossEdit": format.IsLossyEditable(),
			"User":     userID,
			"File":     fileID,
		}

		for k, v := range localizedMessages {
			data[k] = v
		}

		rw.Header().Set("Content-Type", "text/html")
		embeddable.ConvertPage.Execute(rw, data)
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

		group.Do(fmt.Sprintf("%s:%s", body.UserID, body.FileID), func() (interface{}, error) {
			switch body.Action {
			case "create":
				nbody, err := c.convertFile(r.Context(), body)
				if err != nil {
					if errors.Is(errConversionAutoFormatError, err) {
						rw.WriteHeader(http.StatusBadRequest)
						return nil, err
					}

					if errors.Is(errConversionPasswordRequiredError, err) {
						rw.WriteHeader(http.StatusLocked)
						return nil, err
					}

					rw.WriteHeader(http.StatusInternalServerError)
					return nil, err
				}
				http.Redirect(
					rw, r,
					fmt.Sprintf("/editor?state=%s&user=%s", url.QueryEscape(string(nbody.ToJSON())), nbody.UserID),
					http.StatusMovedPermanently,
				)
				return nil, nil
			case "edit":
				body.ForceEdit = true
				http.Redirect(
					rw, r,
					fmt.Sprintf("/editor?state=%s&user=%s", url.QueryEscape(string(body.ToJSON())), body.UserID),
					http.StatusMovedPermanently,
				)
				return nil, nil
			case "view":
				http.Redirect(
					rw, r,
					fmt.Sprintf(
						"/editor?state=%s&user=%s", url.QueryEscape(string(body.ToJSON())), body.UserID,
					),
					http.StatusMovedPermanently,
				)
				return nil, nil
			default:
				http.Redirect(rw, r, "https://app.box.com", http.StatusMovedPermanently)
				return nil, nil
			}
		})
	}
}

func (c FileController) convertFile(
	ctx context.Context,
	body request.ConvertRequestBody,
) (request.ConvertRequestBody, error) {
	if ok := c.sem.TryAcquire(1); !ok {
		c.logger.Errorf("could not acquire semaphore")
		return body, ErrSemaphoreNotAllowed
	}
	defer c.sem.Release(1)

	ures, err := c.getUserAccessToken(ctx, body.UserID)
	if err != nil {
		c.logger.Debugf("could not get user %s access info: %s", body.UserID, err.Error())
		return body, err
	}

	var eg errgroup.Group
	var userInfo response.BoxUserResponse
	var fileInfo response.BoxFileResponse
	var durl string

	eg.Go(func() error {
		var err error
		userInfo, err = c.boxClient.GetMe(ctx, ures.AccessToken)
		if err != nil {
			c.logger.Errorf("could not get current user: %s", err.Error())
		}
		return err
	})

	eg.Go(func() error {
		var err error
		fileInfo, err = c.boxClient.GetFileInfo(ctx, ures.AccessToken, body.FileID)
		if err != nil {
			c.logger.Errorf("could not get file %s info: %s", body.FileID, err.Error())
		}
		return err
	})

	eg.Go(func() error {
		var err error
		durl, err = c.boxClient.GetFilePublicUrl(ctx, ures.AccessToken, body.FileID)
		if err != nil {
			c.logger.Errorf("could not get file %s url: %s", body.FileID, err.Error())
		}
		return err
	})

	if err := eg.Wait(); err != nil {
		return body, err
	}

	if fileInfo.Extension == "csv" {
		return body, errCsvIsNotSupported
	}

	_, supported := c.formatManager.GetFormatByName(fileInfo.Extension)
	if !supported {
		return body, errFormatNotSupported
	}

	outputType := "ooxml"
	if _, supported := c.formatManager.GetFormatByName(body.XmlType); supported && body.XmlType != "" {
		outputType = body.XmlType
	}

	tag, err := language.Parse(userInfo.Language)
	if err != nil {
		return body, err
	}

	region, _ := tag.Region()

	var cresp response.ConvertResponse
	creq := request.ConvertAPIRequest{
		Async:      false,
		Key:        string(c.hasher.Hash(fileInfo.ModifiedAt + fileInfo.ID)),
		Filetype:   fileInfo.Extension,
		Outputtype: outputType,
		Password:   body.Password,
		URL:        durl,
		Region:     fmt.Sprintf("%s-%s", userInfo.Language, region),
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

	if cresp.Error == -9 {
		return body, errConversionAutoFormatError
	}

	if cresp.Error == -5 {
		return body, errConversionPasswordRequiredError
	}

	if cresp.Error < 0 {
		return body, errConversionErrorOccurred
	}

	fresp, err := http.Get(cresp.FileURL)
	if err != nil {
		c.logger.Errorf("could not download a converted file: %s", err.Error())
		return body, err
	}
	defer fresp.Body.Close()

	folder := fileInfo.Parent.ID
	if fileInfo.CreatedBy.ID != body.UserID {
		folder = "0" // Root folder
	}

	location, err := time.LoadLocation(userInfo.Timezone)
	if err != nil {
		location = time.UTC
	}

	nresp, err := c.boxClient.CreateFile(
		ctx, fmt.Sprintf("%s (%s).%s",
			strings.TrimSuffix(fileInfo.Name, filepath.Ext(fileInfo.Name)),
			time.Now().In(location).Format("2006-01-02 15:04:05.000"),
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
