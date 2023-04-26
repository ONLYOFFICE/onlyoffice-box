package onlyoffice

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	ErrOnlyofficeExtensionNotSupported = errors.New("file extension is not supported")
	ErrInvalidContentLength            = errors.New("could not perform api actions due to exceeding content-length")
)

const (
	_OnlyofficeWordType  string = "word"
	_OnlyofficeCellType  string = "cell"
	_OnlyofficeSlideType string = "slide"
)

var OnlyofficeEditableExtensions map[string]string = map[string]string{
	"xlsx": _OnlyofficeCellType,
	"pptx": _OnlyofficeSlideType,
	"docx": _OnlyofficeWordType,
}

var OnlyofficeFileExtensions map[string]string = map[string]string{
	"xls":  _OnlyofficeCellType,
	"xlsx": _OnlyofficeCellType,
	"xlsm": _OnlyofficeCellType,
	"xlt":  _OnlyofficeCellType,
	"xltx": _OnlyofficeCellType,
	"xltm": _OnlyofficeCellType,
	"ods":  _OnlyofficeCellType,
	"fods": _OnlyofficeCellType,
	"ots":  _OnlyofficeCellType,
	"csv":  _OnlyofficeCellType,
	"pps":  _OnlyofficeSlideType,
	"ppsx": _OnlyofficeSlideType,
	"ppsm": _OnlyofficeSlideType,
	"ppt":  _OnlyofficeSlideType,
	"pptx": _OnlyofficeSlideType,
	"pptm": _OnlyofficeSlideType,
	"pot":  _OnlyofficeSlideType,
	"potx": _OnlyofficeSlideType,
	"potm": _OnlyofficeSlideType,
	"odp":  _OnlyofficeSlideType,
	"fodp": _OnlyofficeSlideType,
	"otp":  _OnlyofficeSlideType,
	"doc":  _OnlyofficeWordType,
	"docx": _OnlyofficeWordType,
	"docm": _OnlyofficeWordType,
	"dot":  _OnlyofficeWordType,
	"dotx": _OnlyofficeWordType,
	"dotm": _OnlyofficeWordType,
	"odt":  _OnlyofficeWordType,
	"fodt": _OnlyofficeWordType,
	"ott":  _OnlyofficeWordType,
	"rtf":  _OnlyofficeWordType,
	"txt":  _OnlyofficeWordType,
	"html": _OnlyofficeWordType,
	"htm":  _OnlyofficeWordType,
	"mht":  _OnlyofficeWordType,
	"pdf":  _OnlyofficeWordType,
	"djvu": _OnlyofficeWordType,
	"fb2":  _OnlyofficeWordType,
	"epub": _OnlyofficeWordType,
	"xps":  _OnlyofficeWordType,
}

type OnlyofficeFileUtility interface {
	ValidateFileSize(ctx context.Context, limit int64, url string) error
	EscapeFilename(filename string) string
	IsExtensionSupported(fileExt string) bool
	IsExtensionEditable(fileExt string) bool
	GetFileType(fileExt string) (string, error)
	GetFileExt(filename string) string
}

func NewOnlyofficeFileUtility() OnlyofficeFileUtility {
	return fileUtility{}
}

type fileUtility struct{}

func (u fileUtility) ValidateFileSize(ctx context.Context, limit int64, url string) error {
	resp, err := http.Head(url)

	if err != nil {
		return err
	}

	if val, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 0); val > limit || err != nil {
		return ErrInvalidContentLength
	}

	return nil
}

func (u fileUtility) EscapeFilename(filename string) string {
	f := strings.ReplaceAll(filename, "\\", ":")
	f = strings.ReplaceAll(f, "/", ":")
	return f
}

func (u fileUtility) IsExtensionSupported(fileExt string) bool {
	_, exists := OnlyofficeFileExtensions[strings.ToLower(fileExt)]
	if exists {
		return true
	}
	return false
}

func (u fileUtility) IsExtensionEditable(fileExt string) bool {
	_, exists := OnlyofficeEditableExtensions[strings.ToLower(fileExt)]
	if exists {
		return true
	}
	return false
}

func (u fileUtility) GetFileType(fileExt string) (string, error) {
	fileType, exists := OnlyofficeFileExtensions[strings.ToLower(fileExt)]
	if !exists {
		return "", ErrOnlyofficeExtensionNotSupported
	}
	return fileType, nil
}

func (u fileUtility) GetFileExt(filename string) string {
	return strings.ReplaceAll(filepath.Ext(filename), ".", "")
}
