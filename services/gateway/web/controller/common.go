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
	"errors"
	"net/http"

	"github.com/ONLYOFFICE/onlyoffice-box/services/gateway/web/middleware"
	"golang.org/x/sync/singleflight"
)

var (
	group singleflight.Group
)

var (
	ErrSemaphoreNotAllowed = errors.New("could not acquire semaphore")
	errForeignUser         = errors.New("the request names a user other than the signed-in one")
)

// actsAsSessionUser tells whether the user id a request names (in an editor
// state or a convert body) is the one its session signed in. The session
// middleware checks only the `user` query parameter, and the user id named
// here picks whose Box token the editor and the conversion use.
func actsAsSessionUser(r *http.Request, userID string) bool {
	sessionUser, _ := r.Context().Value(middleware.UserIDKey).(string)
	return sessionUser != "" && userID == sessionUser
}
