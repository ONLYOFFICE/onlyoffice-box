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

package shared

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/go-resty/resty/v2"
	"github.com/mitchellh/mapstructure"
	"go-micro.dev/v4/cache"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

var (
	ErrEmptyResponse           = errors.New("got an empty response")
	ErrCouldNotCreatePublicURL = errors.New("could not generate a new public URL")
	ErrCouldNotUploadFile      = errors.New("could not upload a new file version")
)

const (
	_MeKey            = "me:"
	_FileInfoKey      = "fileInfo:"
	_FilePublicUrlKey = "filePublicUrl:"
	_PartSeparator    = ":"
)

type BoxAPI interface {
	GetAuthCredentials(ctx context.Context, code, clientID, clientSecret string) (response.BoxCredentialsResponse, error)
	RefreshAuthCredentials(ctx context.Context, refreshToken, clientID, clientSecret string) (response.BoxCredentialsResponse, error)
	GetMe(ctx context.Context, token string) (response.BoxUserResponse, error)
	GetFileInfo(ctx context.Context, token, fileID string) (response.BoxFileResponse, error)
	GetFilePublicUrl(ctx context.Context, token, fileID string) (string, error)
	UploadFile(ctx context.Context, filename, token, fileID string, file io.ReadCloser) error
	CreateFile(ctx context.Context, filename, folderID, token string, file io.ReadCloser) (response.BoxCreateFileResponse, error)
	UpdateModifiedAt(ctx context.Context, token, fileID string) error
}

type boxAPIClient struct {
	client *resty.Client
	cache  cache.Cache
}

func NewBoxAPIClient(cache cache.Cache) BoxAPI {
	otelClient := otelhttp.DefaultClient
	otelClient.Transport = otelhttp.NewTransport(&http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		ExpectContinueTimeout: 4 * time.Second,
	})

	return &boxAPIClient{
		client: resty.NewWithClient(otelClient).
			SetRedirectPolicy(resty.RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			})).
			SetRetryCount(3).
			SetTimeout(10 * time.Second).
			SetRetryWaitTime(120 * time.Millisecond).
			SetRetryMaxWaitTime(900 * time.Millisecond).
			SetLogger(log.NewEmptyLogger()).
			AddRetryCondition(func(r *resty.Response, err error) bool {
				return r.StatusCode() == http.StatusTooManyRequests
			}),
		cache: cache,
	}
}

func (c *boxAPIClient) GetAuthCredentials(
	ctx context.Context, code,
	clientID, clientSecret string,
) (response.BoxCredentialsResponse, error) {
	var resp response.BoxCredentialsResponse
	_, err := c.client.R().
		SetFormData(map[string]string{
			"grant_type":    "authorization_code",
			"code":          code,
			"client_id":     clientID,
			"client_secret": clientSecret,
		}).
		SetResult(&resp).
		Post("https://api.box.com/oauth2/token")
	if err != nil {
		return resp, err
	}
	return resp, nil
}

func (c *boxAPIClient) RefreshAuthCredentials(
	ctx context.Context, refreshToken,
	clientID, clientSecret string,
) (response.BoxCredentialsResponse, error) {
	var resp response.BoxCredentialsResponse
	if _, err := c.client.R().
		SetFormData(map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": refreshToken,
			"client_id":     clientID,
			"client_secret": clientSecret,
		}).
		SetResult(&resp).
		Post("https://api.box.com/oauth2/token"); err != nil {
		return resp, err
	}

	return resp, nil
}

func (c *boxAPIClient) GetMe(ctx context.Context, token string) (response.BoxUserResponse, error) {
	var user response.BoxUserResponse
	cacheKey := _MeKey + token
	cachedValue, _, err := c.cache.Get(ctx, cacheKey)
	if err == nil {
		if err := mapstructure.Decode(cachedValue, &user); err == nil {
			return user, nil
		}
	}

	if _, err := c.client.R().
		SetAuthToken(token).
		SetResult(&user).
		Get("https://api.box.com/2.0/users/me"); err != nil {
		return user, err
	}

	if user.ID == "" {
		return user, ErrEmptyResponse
	}

	c.cache.Put(ctx, cacheKey, user, 10*time.Second)
	return user, nil
}

func (c *boxAPIClient) GetFileInfo(
	ctx context.Context, token, fileID string,
) (response.BoxFileResponse, error) {
	var file response.BoxFileResponse
	cacheKey := _FileInfoKey + token + _PartSeparator + fileID
	cachedValue, _, err := c.cache.Get(ctx, cacheKey)
	if err == nil {
		if err := mapstructure.Decode(cachedValue, &file); err == nil {
			return file, nil
		}
	}

	if _, err := c.client.R().
		SetAuthToken(token).
		SetResult(&file).
		SetQueryParams(map[string]string{
			"fields": "id,name,description,extension,modified_at,file_version,version_number,parent,permissions,created_by",
		}).
		SetPathParams(map[string]string{
			"fileID": fileID,
		}).
		Get("https://api.box.com/2.0/files/{fileID}"); err != nil {
		return file, err
	}

	if file.ID == "" {
		return file, ErrEmptyResponse
	}

	c.cache.Put(ctx, cacheKey, file, 10*time.Second)
	return file, nil
}

func (c *boxAPIClient) GetFilePublicUrl(ctx context.Context, token, fileID string) (string, error) {
	cacheKey := _FilePublicUrlKey + token + _PartSeparator + fileID
	cachedValue, _, err := c.cache.Get(ctx, cacheKey)
	if err == nil {
		var url string
		if err := mapstructure.Decode(cachedValue, &url); err == nil {
			return url, nil
		}
	}

	resp, err := c.client.R().
		SetAuthToken(token).
		SetPathParams(map[string]string{
			"fileID": fileID,
		}).
		Get("https://api.box.com/2.0/files/{fileID}/content")
	if err != nil {
		return "", err
	}

	pURL := resp.Header().Get("Location")
	if pURL == "" {
		return "", ErrCouldNotCreatePublicURL
	}

	c.cache.Put(ctx, cacheKey, pURL, 10*time.Second)
	return pURL, nil
}

func (c *boxAPIClient) UploadFile(
	ctx context.Context, filename,
	token, fileID string, file io.ReadCloser,
) error {
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
		return ErrCouldNotUploadFile
	}

	c.invalidateCacheEntries(token, fileID)
	return nil
}

func (c *boxAPIClient) CreateFile(
	ctx context.Context, filename, folderID,
	token string, file io.ReadCloser,
) (response.BoxCreateFileResponse, error) {
	var resp response.BoxCreateFileResponse
	_, err := c.client.R().
		SetAuthToken(token).
		SetQueryParams(map[string]string{
			"fields": "id,name,description,extension,modified_at,file_version,version_number,parent",
		}).
		SetFormData(map[string]string{
			"content_created_at":  time.Now().Format(time.RFC3339),
			"content_modified_at": time.Now().Format(time.RFC3339),
			"name":                filename,
			"parent_id":           folderID,
		}).
		SetFileReader("file", filename, file).
		SetResult(&resp).
		Post("https://upload.box.com/api/2.0/files/content")

	if err != nil {
		return resp, err
	}

	if len(resp.Entries) == 0 {
		return resp, ErrCouldNotUploadFile
	}

	c.invalidateCacheEntries(token, folderID)
	return resp, nil
}

func (c *boxAPIClient) UpdateModifiedAt(ctx context.Context, token, fileID string) error {
	info, _ := c.GetFileInfo(ctx, token, fileID)

	_, err := c.client.R().
		SetAuthToken(token).
		SetPathParams(map[string]string{
			"fileID": fileID,
		}).
		SetBody(map[string]string{
			"description": info.Description,
		}).
		Put("https://api.box.com/2.0/files/{fileID}")

	if err != nil {
		return err
	}

	c.invalidateCacheEntries(token, fileID)
	return nil
}

func (c *boxAPIClient) invalidateCacheEntries(token, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c.cache.Delete(ctx, _FileInfoKey+token+_PartSeparator+id)
	c.cache.Delete(ctx, _FilePublicUrlKey+token+_PartSeparator+id)
}
