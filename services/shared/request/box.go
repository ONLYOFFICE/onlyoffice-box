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

package request

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
)

type BoxUser struct {
	ID           string `json:"id"`
	AccessToken  string `json:"access_token" mapstructure:"access_token"`
	RefreshToken string `json:"refresh_token" mapstructure:"refresh_token"`
	TokenType    string `json:"token_type" mapstructure:"token_type"`
	ExpiresIn    int64  `json:"expires_in" mapstructure:"expires_in"`
}

func (u BoxUser) ToJSON() []byte {
	buf, _ := json.Marshal(u)
	return buf
}

type BoxState struct {
	jwt.RegisteredClaims
	UserID    string `json:"user_id" mapstructure:"user_id"`
	FileID    string `json:"file_id" mapstructure:"file_id"`
	UserAgent string `json:"user_agent" mapstructure:"user_agent"`
	ForceEdit bool   `json:"force_edit,omitempty"`
}

func (u BoxState) ToJSON() []byte {
	buf, _ := json.Marshal(u)
	return buf
}

type BoxCollaborationItem struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type BoxCollaborationAccess struct {
	Type  string `json:"type"`
	Login string `json:"login"`
}

type BoxCreateCollaboration struct {
	Item   BoxCollaborationItem   `json:"item"`
	Access BoxCollaborationAccess `json:"accessible_by"`
	Role   string                 `json:"role"`
}

func (u BoxCreateCollaboration) ToJSON() []byte {
	buf, _ := json.Marshal(u)
	return buf
}
