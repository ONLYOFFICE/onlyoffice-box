package response

import "encoding/json"

type BoxUser struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Language string `json:"language"`
}

func (u BoxUser) ToJSON() []byte {
	buf, _ := json.Marshal(u)
	return buf
}

type BoxCredentials struct {
	AccessToken  string `json:"access_token" mapstructure:"access_token"`
	RefreshToken string `json:"refresh_token" mapstructure:"refresh_token"`
	TokenType    string `json:"token_type" mapstructure:"token_type"`
	ExpiresIn    int64  `json:"expires_in" mapstructure:"expires_in"`
}

func (c BoxCredentials) ToJSON() []byte {
	buf, _ := json.Marshal(c)
	return buf
}

type BoxFile struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Description   string     `json:"description"`
	Extension     string     `json:"extension"`
	ModifiedAt    string     `json:"modified_at"`
	FileVersion   BoxVersion `json:"file_version"`
	VersionNumber string     `json:"version_number"`
}

func (f BoxFile) ToJSON() []byte {
	buf, _ := json.Marshal(f)
	return buf
}

type BoxVersion struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

func (v BoxVersion) ToJSON() []byte {
	buf, _ := json.Marshal(v)
	return buf
}
