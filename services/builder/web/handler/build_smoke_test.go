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

package handler

import (
	"context"
	"io"
	"testing"

	"github.com/ONLYOFFICE/onlyoffice-box/services/shared"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/format"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-box/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeBox answers the two Box calls the config builder makes.
type fakeBox struct {
	shared.BoxAPI
	user response.BoxUserResponse
	file response.BoxFileResponse
}

func (f fakeBox) GetMe(context.Context, string) (response.BoxUserResponse, error) {
	return f.user, nil
}

func (f fakeBox) GetFileInfo(context.Context, string, string) (response.BoxFileResponse, error) {
	return f.file, nil
}

func (f fakeBox) GetFilePublicUrl(context.Context, string, string) (string, error) {
	return "https://dl.box.example/file", nil
}

func (f fakeBox) UploadFile(context.Context, string, string, string, io.ReadCloser) error {
	return nil
}

func TestSmokeBuildConfig(t *testing.T) {
	formats, err := format.NewMapFormatManager()
	require.NoError(t, err, "is the document-formats submodule checked out?")

	user := response.BoxUserResponse{ID: "1001", Name: "Smoke", Language: "en"}
	build := func(t *testing.T, file response.BoxFileResponse, forceEdit bool) (response.BuildConfigResponse, error) {
		onlyoffice := &shared.OnlyofficeConfig{}
		onlyoffice.Onlyoffice.Builder.DocumentServerSecret = "smoke-docs-secret"
		onlyoffice.Onlyoffice.Builder.DocumentServerURL = "https://docs.example"
		onlyoffice.Onlyoffice.Builder.CallbackURL = "https://callback.example"

		c := NewConfigHandler(
			nil, fakeBox{user: user, file: file},
			crypto.NewJwtManager(&config.CryptoConfig{}), crypto.NewHasher(&config.CryptoConfig{}),
			formats, &config.ServerConfig{}, onlyoffice, log.NewEmptyLogger(),
		)

		return c.processConfig(context.Background(), response.UserResponse{AccessToken: "token"}, request.BoxState{
			UserID: user.ID, FileID: file.ID, ForceEdit: forceEdit,
		})
	}

	file := func(name, ext string, canUpload bool, owner string) response.BoxFileResponse {
		return response.BoxFileResponse{
			ID: "42", Name: name, Extension: ext, Size: 10, ModifiedAt: "2026-01-01T00:00:00Z",
			Permissions: response.BoxPermissions{CanUpload: canUpload, CanDownload: true},
			CreatedBy:   response.BoxUserResponse{ID: owner},
		}
	}

	t.Run("an uploadable docx opens for editing", func(t *testing.T) {
		cfg, err := build(t, file("a.docx", "docx", true, "2002"), false)
		require.NoError(t, err)
		assert.Equal(t, "edit", cfg.EditorConfig.Mode)
		assert.Equal(t, "word", cfg.DocumentType)
		assert.Contains(t, cfg.EditorConfig.CallbackURL, "https://callback.example/callback?state=")
		assert.NotEmpty(t, cfg.Token, "Docs requires a signed config")
	})

	t.Run("the same file version keeps the same document key", func(t *testing.T) {
		first, err := build(t, file("a.docx", "docx", true, "2002"), false)
		require.NoError(t, err)
		second, err := build(t, file("a.docx", "docx", true, "2002"), false)
		require.NoError(t, err)
		assert.Equal(t, first.Document.Key, second.Document.Key, "co-editors must share a key")
	})

	t.Run("a docx without upload rights opens for viewing", func(t *testing.T) {
		cfg, err := build(t, file("a.docx", "docx", false, "2002"), false)
		require.NoError(t, err)
		assert.Equal(t, "view", cfg.EditorConfig.Mode)
	})

	t.Run("the owner may edit", func(t *testing.T) {
		cfg, err := build(t, file("a.xlsx", "xlsx", false, user.ID), false)
		require.NoError(t, err)
		assert.Equal(t, "edit", cfg.EditorConfig.Mode)
		assert.True(t, cfg.Owner)
	})

	t.Run("a view-only format opens for viewing", func(t *testing.T) {
		cfg, err := build(t, file("a.djvu", "djvu", true, "2002"), false)
		require.NoError(t, err)
		assert.Equal(t, "view", cfg.EditorConfig.Mode)
	})

	t.Run("an unknown format is refused", func(t *testing.T) {
		_, err := build(t, file("a.exe", "exe", true, "2002"), false)
		assert.ErrorIs(t, err, errFormatNotSupported)
	})

	t.Run("an empty Google doc opens as a blank docx", func(t *testing.T) {
		f := file("a.gdoc", "gdoc", true, "2002")
		f.Size = 0
		c := fakeBoxNoURL{fakeBox{user: user, file: f}}
		onlyoffice := &shared.OnlyofficeConfig{}
		onlyoffice.Onlyoffice.Builder.DocumentServerSecret = "smoke-docs-secret"
		h := NewConfigHandler(
			nil, c, crypto.NewJwtManager(&config.CryptoConfig{}), crypto.NewHasher(&config.CryptoConfig{}),
			formats, &config.ServerConfig{}, onlyoffice, log.NewEmptyLogger(),
		)
		cfg, err := h.processConfig(context.Background(), response.UserResponse{AccessToken: "token"}, request.BoxState{UserID: user.ID, FileID: f.ID})
		if err == errFormatNotSupported {
			t.Skip("gdoc is not in the document-formats list")
		}
		require.NoError(t, err)
		assert.Equal(t, "docx", cfg.Document.FileType)
		assert.Contains(t, cfg.Document.URL, "data:application/vnd.openxmlformats-officedocument.wordprocessingml.document;base64,")
	})
}

type fakeBoxNoURL struct{ fakeBox }

func (fakeBoxNoURL) GetFilePublicUrl(context.Context, string, string) (string, error) {
	return "", shared.ErrCouldNotCreatePublicURL
}
