package request

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
)

type ConvertRequestBody struct {
	Action    string `json:"action"`
	UserID    string `json:"user_id"`
	FileID    string `json:"file_id"`
	ForceEdit bool   `json:"force_edit"`
}

func (r ConvertRequestBody) ToJSON() []byte {
	buf, _ := json.Marshal(r)
	return buf
}

type ConvertAPIRequest struct {
	jwt.RegisteredClaims
	Async      bool   `json:"async"`
	Key        string `json:"key"`
	Filetype   string `json:"filetype"`
	Outputtype string `json:"outputtype"`
	URL        string `json:"url"`
	Token      string `json:"token,omitempty"`
}

func (r ConvertAPIRequest) ToJSON() []byte {
	buf, _ := json.Marshal(r)
	return buf
}
