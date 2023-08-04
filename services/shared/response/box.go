package response

import "encoding/json"

type BoxUserResponse struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Language string `json:"language"`
}

func (u BoxUserResponse) ToJSON() []byte {
	buf, _ := json.Marshal(u)
	return buf
}

type BoxCredentialsResponse struct {
	AccessToken  string `json:"access_token" mapstructure:"access_token"`
	RefreshToken string `json:"refresh_token" mapstructure:"refresh_token"`
	TokenType    string `json:"token_type" mapstructure:"token_type"`
	ExpiresIn    int64  `json:"expires_in" mapstructure:"expires_in"`
}

func (c BoxCredentialsResponse) ToJSON() []byte {
	buf, _ := json.Marshal(c)
	return buf
}

type BoxFileResponse struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	Extension     string          `json:"extension"`
	ModifiedAt    string          `json:"modified_at"`
	FileVersion   BoxVersion      `json:"file_version"`
	VersionNumber string          `json:"version_number"`
	Parent        BoxParent       `json:"parent"`
	Permissions   BoxPermissions  `json:"permissions"`
	CreatedBy     BoxUserResponse `json:"created_by"`
}

func (f BoxFileResponse) ToJSON() []byte {
	buf, _ := json.Marshal(f)
	return buf
}

type Entries struct {
	ID string `json:"id"`
}

type BoxCreateFileResponse struct {
	Entries []Entries `json:"entries"`
}

type BoxVersion struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

func (v BoxVersion) ToJSON() []byte {
	buf, _ := json.Marshal(v)
	return buf
}

type BoxParent struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (v BoxParent) ToJSON() []byte {
	buf, _ := json.Marshal(v)
	return buf
}

type BoxPermissions struct {
	CanAnnotate            bool `json:"can_annotate"`
	CanComment             bool `json:"can_comment"`
	CanDelete              bool `json:"can_delete"`
	CanDownload            bool `json:"can_download"`
	CanInviteCollaborator  bool `json:"can_invite_collaborator"`
	CanPreview             bool `json:"can_preview"`
	CanRename              bool `json:"can_rename"`
	CanSetShareAccess      bool `json:"can_set_share_access"`
	CanShare               bool `json:"can_share"`
	CanUpload              bool `json:"can_upload"`
	CanViewAnnotationsAll  bool `json:"can_view_annotations_all"`
	CanViewAnnotationsSelf bool `json:"can_view_annotations_self"`
}

func (v BoxPermissions) ToJSON() []byte {
	buf, _ := json.Marshal(v)
	return buf
}
