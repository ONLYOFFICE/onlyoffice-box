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

package service

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/ONLYOFFICE/onlyoffice-box/services/auth/web/core/domain"
	"github.com/ONLYOFFICE/onlyoffice-box/services/auth/web/core/port"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	plog "github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"go-micro.dev/v4/cache"
	"golang.org/x/oauth2"
)

var errOperationTimeout = errors.New("operation timeout")

type userService struct {
	adapter     port.UserAccessServiceAdapter
	encryptor   crypto.Encryptor
	cache       cache.Cache
	credentials *oauth2.Config
	logger      plog.Logger
}

func NewUserService(
	adapter port.UserAccessServiceAdapter,
	encryptor crypto.Encryptor,
	cache cache.Cache,
	credentials *oauth2.Config,
	logger plog.Logger,
) port.UserAccessService {
	return userService{
		adapter:     adapter,
		encryptor:   encryptor,
		cache:       cache,
		credentials: credentials,
		logger:      logger,
	}
}

func (s userService) CreateUser(ctx context.Context, user domain.UserAccess) error {
	s.logger.Debugf("validating user %s to perform a persist action", user.ID)
	if err := user.Validate(); err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	errChan := make(chan error, 2)
	atokenChan := make(chan string, 1)
	rtokenChan := make(chan string, 1)

	go func() {
		defer wg.Done()
		aToken, err := s.encryptor.Encrypt(user.AccessToken, []byte(s.credentials.ClientSecret))
		if err != nil {
			errChan <- err
			return
		}
		atokenChan <- aToken
	}()

	go func() {
		defer wg.Done()
		rToken, err := s.encryptor.Encrypt(user.RefreshToken, []byte(s.credentials.ClientSecret))
		if err != nil {
			errChan <- err
			return
		}
		rtokenChan <- rToken
	}()

	wg.Wait()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return errOperationTimeout
	default:
	}

	s.logger.Debugf("user %s is valid. Persisting to database: %s", user.ID, user.AccessToken)
	if err := s.adapter.InsertUser(ctx, domain.UserAccess{
		ID:           user.ID,
		AccessToken:  <-atokenChan,
		RefreshToken: <-rtokenChan,
		TokenType:    user.TokenType,
		ExpiresAt:    user.ExpiresAt,
	}); err != nil {
		return err
	}

	return nil
}

func (s userService) GetUser(ctx context.Context, uid string) (domain.UserAccess, error) {
	s.logger.Debugf("trying to select user with id: %s", uid)
	id := strings.TrimSpace(uid)

	if id == "" {
		return domain.UserAccess{}, &InvalidServiceParameterError{
			Name:   "UID",
			Reason: "Should not be blank",
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	errChan := make(chan error, 2)
	atokenChan := make(chan string, 1)
	rtokenChan := make(chan string, 1)

	user, err := s.adapter.SelectUserByID(ctx, id)
	if err != nil {
		return user, err
	}

	s.logger.Debugf("found a user: %v", user)

	go func() {
		defer wg.Done()
		aToken, err := s.encryptor.Decrypt(user.AccessToken, []byte(s.credentials.ClientSecret))
		if err != nil {
			errChan <- err
			return
		}
		atokenChan <- aToken
	}()

	go func() {
		defer wg.Done()
		rToken, err := s.encryptor.Decrypt(user.RefreshToken, []byte(s.credentials.ClientSecret))
		if err != nil {
			errChan <- err
			return
		}
		rtokenChan <- rToken
	}()

	wg.Wait()

	select {
	case err := <-errChan:
		return domain.UserAccess{}, err
	case <-ctx.Done():
		return domain.UserAccess{}, errOperationTimeout
	default:
		u := domain.UserAccess{
			ID:           user.ID,
			AccessToken:  <-atokenChan,
			RefreshToken: <-rtokenChan,
			TokenType:    user.TokenType,
			ExpiresAt:    user.ExpiresAt,
		}
		return u, u.Validate()
	}
}

func (s userService) UpdateUser(ctx context.Context, user domain.UserAccess) (domain.UserAccess, error) {
	s.logger.Debugf("validating user %s to perform an update action", user.ID)
	if err := user.Validate(); err != nil {
		return domain.UserAccess{}, err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	errChan := make(chan error, 2)
	atokenChan := make(chan string, 1)
	rtokenChan := make(chan string, 1)

	go func() {
		defer wg.Done()
		aToken, err := s.encryptor.Encrypt(user.AccessToken, []byte(s.credentials.ClientSecret))
		if err != nil {
			errChan <- err
			return
		}
		atokenChan <- aToken
	}()

	go func() {
		defer wg.Done()
		rToken, err := s.encryptor.Encrypt(user.RefreshToken, []byte(s.credentials.ClientSecret))
		if err != nil {
			errChan <- err
			return
		}
		rtokenChan <- rToken
	}()

	select {
	case err := <-errChan:
		return user, err
	case <-ctx.Done():
		return user, errOperationTimeout
	default:
	}

	euser := domain.UserAccess{
		ID:           user.ID,
		AccessToken:  <-atokenChan,
		RefreshToken: <-rtokenChan,
		TokenType:    user.TokenType,
		ExpiresAt:    user.ExpiresAt,
	}

	s.logger.Debugf("user %s is valid to perform an update action", user.ID)
	if _, err := s.adapter.UpsertUser(ctx, euser); err != nil {
		return user, err
	}

	return user, nil
}

func (s userService) DeleteUser(ctx context.Context, uid string) error {
	id := strings.TrimSpace(uid)
	s.logger.Debugf("validating uid %s to perform a delete action", id)

	if id == "" {
		return &InvalidServiceParameterError{
			Name:   "UID",
			Reason: "Should not be blank",
		}
	}

	s.logger.Debugf("uid %s is valid to perform a delete action", id)
	return s.adapter.DeleteUserByID(ctx, uid)
}
