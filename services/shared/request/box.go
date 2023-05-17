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
	ForceEdit bool   `json:"force_edit,omitmepty"`
}

func (u BoxState) ToJSON() []byte {
	buf, _ := json.Marshal(u)
	return buf
}
