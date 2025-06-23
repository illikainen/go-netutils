package transport

import (
	"net/url"

	"github.com/illikainen/go-netutils/src/transport/http"
	"github.com/illikainen/go-netutils/src/transport/localfs"
	"github.com/illikainen/go-netutils/src/transport/sftp"
	"github.com/illikainen/go-netutils/src/transport/types"

	"github.com/pkg/errors"
)

var (
	ErrUnsupportedScheme = types.ErrUnsupportedScheme
	ErrNotExist          = types.ErrNotExist
	ErrUnknown           = types.ErrUnknown
)

type Transport = types.Transport

func New(uri *url.URL) (Transport, error) {
	switch uri.Scheme {
	case "file":
		return localfs.New(uri)
	case "sftp":
		return sftp.New(uri)
	case "http", "https":
		return http.New(uri)
	}

	return nil, errors.Wrap(ErrUnsupportedScheme, uri.String())
}
