package shared

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/pkg/log"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/response"
	"github.com/go-resty/resty/v2"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

var (
	_ErrCouldNotCreatePublicURL = errors.New("could not generate a new public url")
	_ErrCouldNotUploadFile      = errors.New("could not upload a new file version")
)

type BoxAPI interface {
	GetAuthCredentials(ctx context.Context, code, clientID, clientSecret string) (response.BoxCredentials, error)
	RefreshAuthCredentials(ctx context.Context, refreshToken, clientID, clientSecret string) (response.BoxCredentials, error)
	GetMe(ctx context.Context, token string) (response.BoxUser, error)
	GetFileInfo(ctx context.Context, token, fileId string) (response.BoxFile, error)
	GetFilePublicUrl(ctx context.Context, token, fileID string) (string, error)
	UploadFile(ctx context.Context, filename, token, parentID string, file io.ReadCloser) error
}

type boxAPIClient struct {
	client *resty.Client
}

func NewBoxAPIClient() BoxAPI {
	otelClient := otelhttp.DefaultClient
	otelClient.Transport = otelhttp.NewTransport(&http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	})
	return boxAPIClient{
		client: resty.NewWithClient(otelClient).
			SetRedirectPolicy(resty.RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			})).
			SetRetryCount(3).
			SetTimeout(3 * time.Second).
			SetRetryWaitTime(120 * time.Millisecond).
			SetRetryMaxWaitTime(900 * time.Millisecond).
			SetLogger(log.NewEmptyLogger()).
			AddRetryCondition(func(r *resty.Response, err error) bool {
				return r.StatusCode() == http.StatusTooManyRequests
			}),
	}
}

func (c boxAPIClient) GetAuthCredentials(ctx context.Context, code, clientID, clientSecret string) (response.BoxCredentials, error) {
	var response response.BoxCredentials
	if _, err := c.client.SetFormData(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     clientID,
		"client_secret": clientSecret,
	}).R().
		SetResult(&response).
		Post("https://api.box.com/oauth2/token"); err != nil {
		return response, err
	}

	return response, nil
}

func (c boxAPIClient) RefreshAuthCredentials(ctx context.Context, refreshToken, clientID, clientSecret string) (response.BoxCredentials, error) {
	var response response.BoxCredentials
	if _, err := c.client.SetFormData(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     clientID,
		"client_secret": clientSecret,
	}).R().
		SetResult(&response).
		Post("https://api.box.com/oauth2/token"); err != nil {
		return response, err
	}

	return response, nil
}

func (c boxAPIClient) GetMe(ctx context.Context, token string) (response.BoxUser, error) {
	var user response.BoxUser
	if _, err := c.client.R().
		SetAuthToken(token).
		SetResult(&user).
		Get("https://api.box.com/2.0/users/me"); err != nil {
		return user, err
	}

	return user, nil
}

func (c boxAPIClient) GetFileInfo(ctx context.Context, token, fileID string) (response.BoxFile, error) {
	var file response.BoxFile
	if _, err := c.client.R().
		SetAuthToken(token).
		SetResult(&file).
		SetQueryParams(map[string]string{
			"fields": "id,name,extension,modified_at,file_version,version_number",
		}).
		SetPathParams(map[string]string{
			"fileID": fileID,
		}).
		Get("https://api.box.com/2.0/files/{fileID}"); err != nil {
		return file, err
	}

	return file, nil
}

func (c boxAPIClient) GetFilePublicUrl(ctx context.Context, token, fileID string) (string, error) {
	resp, err := c.client.R().
		SetAuthToken(token).
		SetPathParams(map[string]string{
			"fileID": fileID,
		}).
		Get("https://api.box.com/2.0/files/{fileID}/content")
	if err != nil {
		return "", err
	}

	if resp.Header().Get("Location") == "" {
		return "", _ErrCouldNotCreatePublicURL
	}

	return resp.Header().Get("Location"), nil
}

func (c boxAPIClient) UploadFile(ctx context.Context, filename, token, fileID string, file io.ReadCloser) error {
	resp, err := c.client.R().
		SetAuthToken(token).
		SetFileReader("file", filename, file).
		SetPathParams(map[string]string{
			"fileID": fileID,
		}).
		Post("https://upload.box.com/api/2.0/files/{fileID}/content")

	if err != nil {
		return err
	}

	if resp.StatusCode() != http.StatusCreated {
		return _ErrCouldNotUploadFile
	}

	return nil
}
