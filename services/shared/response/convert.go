package response

import "encoding/json"

type ConvertResponse struct {
	FileURL  string `json:"fileUrl"`
	FileType string `json:"fileType"`
}

func (r ConvertResponse) ToJSON() []byte {
	buf, _ := json.Marshal(r)
	return buf
}
