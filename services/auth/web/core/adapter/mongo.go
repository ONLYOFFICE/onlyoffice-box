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

package adapter

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-box/services/auth/web/core/domain"
	"github.com/ONLYOFFICE/onlyoffice-box/services/auth/web/core/port"
	"github.com/kamva/mgm/v3"
	"github.com/kamva/mgm/v3/operator"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var errInvalidUserId error = errors.New("invalid uid format")

type userAccessCollection struct {
	mgm.DefaultModel `bson:",inline"`
	UID              string `json:"uid" bson:"uid"`
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresAt        int64  `json:"expires_at"`
}

type mongoUserAdapter struct {
}

func NewMongoUserAdapter(url string) port.UserAccessServiceAdapter {
	if err := mgm.SetDefaultConfig(
		&mgm.Config{CtxTimeout: 3 * time.Second}, "box",
		options.Client().ApplyURI(url),
	); err != nil {
		log.Fatalf("mongo initialization error: %s", err.Error())
	}

	return &mongoUserAdapter{}
}

func (m *mongoUserAdapter) save(ctx context.Context, user domain.UserAccess) error {
	return mgm.TransactionWithCtx(ctx, func(session mongo.Session, sc mongo.SessionContext) error {
		u := &userAccessCollection{}
		collection := mgm.Coll(&userAccessCollection{})

		if err := collection.FirstWithCtx(ctx, bson.M{"uid": user.ID}, u); err != nil {
			if cerr := collection.CreateWithCtx(ctx, &userAccessCollection{
				UID:          user.ID,
				AccessToken:  user.AccessToken,
				RefreshToken: user.RefreshToken,
				TokenType:    user.TokenType,
				ExpiresAt:    user.ExpiresAt,
			}); cerr != nil {
				return cerr
			}

			return session.CommitTransaction(sc)
		}

		u.AccessToken = user.AccessToken
		u.RefreshToken = user.RefreshToken
		u.TokenType = user.TokenType
		u.ExpiresAt = user.ExpiresAt
		u.UpdatedAt = time.Now()

		if err := collection.UpdateWithCtx(ctx, u); err != nil {
			return err
		}

		return session.CommitTransaction(sc)
	})
}

func (m *mongoUserAdapter) InsertUser(ctx context.Context, user domain.UserAccess) error {
	if err := user.Validate(); err != nil {
		return err
	}

	return m.save(ctx, user)
}

func (m *mongoUserAdapter) SelectUserByID(ctx context.Context, uid string) (domain.UserAccess, error) {
	uid = strings.TrimSpace(uid)

	if uid == "" {
		return domain.UserAccess{}, errInvalidUserId
	}

	user := &userAccessCollection{}
	collection := mgm.Coll(user)
	return domain.UserAccess{
		ID:           user.UID,
		AccessToken:  user.AccessToken,
		RefreshToken: user.RefreshToken,
		TokenType:    user.TokenType,
		ExpiresAt:    user.ExpiresAt,
	}, collection.FirstWithCtx(ctx, bson.M{"uid": uid}, user)
}

func (m *mongoUserAdapter) UpsertUser(ctx context.Context, user domain.UserAccess) (domain.UserAccess, error) {
	if err := user.Validate(); err != nil {
		return user, err
	}

	return user, m.save(ctx, user)
}

func (m *mongoUserAdapter) DeleteUserByID(ctx context.Context, uid string) error {
	return mgm.TransactionWithCtx(ctx, func(session mongo.Session, sc mongo.SessionContext) error {
		uid = strings.TrimSpace(uid)

		if uid == "" {
			return errInvalidUserId
		}

		if _, err := mgm.Coll(&userAccessCollection{}).DeleteMany(ctx, bson.M{"uid": bson.M{operator.Eq: uid}}); err != nil {
			return err
		}

		return session.CommitTransaction(sc)
	})
}
