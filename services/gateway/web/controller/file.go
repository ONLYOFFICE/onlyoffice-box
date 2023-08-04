package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/services/gateway/web/embeddable"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/onlyoffice"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"go-micro.dev/v4/client"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
	"golang.org/x/sync/semaphore"
)

type FileController struct {
	client      client.Client
	boxClient   shared.BoxAPI
	jwtManager  crypto.JwtManager
	fileUtil    onlyoffice.OnlyofficeFileUtility
	hasher      crypto.Hasher
	credentials *oauth2.Config
	server      *config.ServerConfig
	onlyoffice  *shared.OnlyofficeConfig
	sem         *semaphore.Weighted
	session     *sessions.CookieStore
	logger      log.Logger
}

func NewFileController(
	client client.Client, boxClient shared.BoxAPI, jwtManager crypto.JwtManager,
	credentials *oauth2.Config, fileUtil onlyoffice.OnlyofficeFileUtility, hasher crypto.Hasher,
	server *config.ServerConfig, onlyoffice *shared.OnlyofficeConfig,
	session *sessions.CookieStore, logger log.Logger,
) FileController {
	return FileController{
		client:      client,
		boxClient:   boxClient,
		jwtManager:  jwtManager,
		fileUtil:    fileUtil,
		hasher:      hasher,
		credentials: credentials,
		server:      server,
		onlyoffice:  onlyoffice,
		sem:         semaphore.NewWeighted(int64(onlyoffice.Onlyoffice.Builder.AllowedDownloads)),
		session:     session,
		logger:      logger,
	}
}

func (c FileController) saveRedirectURL(rw http.ResponseWriter, r *http.Request) {
	session, _ := c.session.Get(r, "url")
	session.Values["redirect"] = c.onlyoffice.Onlyoffice.Builder.GatewayURL + r.URL.String()
	session.Save(r, rw)
}

func (c FileController) BuildConvertPage() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/html")
		query := r.URL.Query()
		fileID, userID := query.Get("file"), query.Get("user")
		loc := i18n.NewLocalizer(embeddable.Bundle, r.Header.Get("Locale"))
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

		file, err := c.boxClient.GetFileInfo(r.Context(), ures.AccessToken, fileID)
		if err != nil || file.ID == "" {
			c.saveRedirectURL(rw, r)
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		if !file.Permissions.CanUpload || c.fileUtil.IsExtensionEditable(file.Extension) || c.fileUtil.IsExtensionViewOnly(file.Extension) {
			http.Redirect(rw, r, fmt.Sprintf("/editor?state=%s&user=%s", url.QueryEscape(string(request.ConvertRequestBody{
				Action: "edit",
				UserID: ures.ID,
				FileID: fileID,
			}.ToJSON())), userID), http.StatusMovedPermanently)
			return
		}

		embeddable.ConvertPage.Execute(rw, map[string]interface{}{
			"CSRF":     csrf.Token(r),
			"OOXML":    c.fileUtil.IsExtensionOOXMLConvertable(file.Extension) || c.fileUtil.IsExtensionLossEditable(file.Extension),
			"LossEdit": c.fileUtil.IsExtensionLossEditable(file.Extension),
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

	var cresp response.ConvertResponse
	fType, err := c.fileUtil.GetFileType(fileInfo.Extension)
	if err != nil {
		c.logger.Debugf("could not get file type: %s", err.Error())
		return body, err
	}

	creq := request.ConvertAPIRequest{
		Async:      false,
		Key:        string(c.hasher.Hash(fileInfo.ModifiedAt + fileInfo.ID)),
		Filetype:   fType,
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
		fmt.Sprintf("%s/ConvertService.ashx", c.onlyoffice.Onlyoffice.Builder.DocumentServerURL),
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

	defer fresp.Body.Close()
	nresp, err := c.boxClient.CreateFile(
		ctx, fmt.Sprintf("%s.%s", c.fileUtil.GetFilenameWithoutExtension(fileInfo.Name), cresp.FileType),
		fileInfo.Parent.ID, ures.AccessToken, fresp.Body,
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
