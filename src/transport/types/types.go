package types

import (
	"io"

	"github.com/pkg/errors"
)

type Transport interface {
	Exists(string) (bool, error)
	Open(string) (io.ReadCloser, error)
	Download(string, string) error
	Upload(string, string) error
	Close() error
	String() string
}

var ErrUnsupportedScheme = errors.New("unsupported url scheme")
