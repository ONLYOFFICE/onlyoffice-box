/**
 *
 * (c) Copyright Ascensio System SIA 2026
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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/ONLYOFFICE/onlyoffice-box/services/shared"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const docsSecret = "smoke-docs-secret"

func TestSmokeCallback(t *testing.T) {
	jwtManager := crypto.NewJwtManager(&config.CryptoConfig{})
	onlyoffice := &shared.OnlyofficeConfig{}
	onlyoffice.Onlyoffice.Builder.DocumentServerSecret = docsSecret
	c := NewCallbackController(nil, jwtManager, nil, &config.ServerConfig{}, onlyoffice, log.NewEmptyLogger())

	sign := func(secret string, claims jwt.MapClaims) string {
		token, err := jwtManager.Sign(secret, claims)
		require.NoError(t, err)
		return token
	}

	post := func(state string, body map[string]any) *httptest.ResponseRecorder {
		buf, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/callback?state="+url.QueryEscape(state), bytes.NewReader(buf))
		rw := httptest.NewRecorder()
		c.BuildPostHandleCallback()(rw, req)
		return rw
	}

	state := sign(docsSecret, jwt.MapClaims{"file_id": "1", "name": "a.docx"})
	editing := jwt.MapClaims{"key": "k", "status": 1, "users": []string{"1001"}}

	t.Run("refuses a state not signed by the Docs secret", func(t *testing.T) {
		forged := sign("another-secret", jwt.MapClaims{"file_id": "1", "name": "a.docx"})
		rw := post(forged, map[string]any{"token": sign(docsSecret, editing)})
		assert.Equal(t, http.StatusForbidden, rw.Code)
		assert.JSONEq(t, `{"error":1}`, rw.Body.String())
	})

	t.Run("refuses a body not signed by the Docs secret", func(t *testing.T) {
		rw := post(state, map[string]any{"token": sign("another-secret", editing)})
		assert.Equal(t, http.StatusForbidden, rw.Code)
	})

	t.Run("acknowledges an editing status without saving", func(t *testing.T) {
		rw := post(state, map[string]any{"token": sign(docsSecret, editing)})
		assert.Equal(t, http.StatusOK, rw.Code)
		assert.JSONEq(t, `{"error":0}`, rw.Body.String())
	})
}
