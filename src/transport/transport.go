package transport

import (
	"net/url"

	"github.com/illikainen/go-netutils/src/transport/http"
	"github.com/illikainen/go-netutils/src/transport/localfs"
	"github.com/illikainen/go-netutils/src/transport/sftp"
	"github.com/illikainen/go-netutils/src/transport/types"

	"github.com/illikainen/go-utils/src/flag"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	"github.com/spf13/pflag"
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

	return nil, errors.Wrap(types.ErrUnsupportedScheme, uri.Scheme)
}

type DownloadOptions struct {
	Output  string
	Extract string
}

type DownloadConfig struct {
	Prefix  string
	Sort    bool
	Options *DownloadOptions
}

func DownloadFlags(config DownloadConfig) *pflag.FlagSet {
	flags := pflag.NewFlagSet("download", pflag.ContinueOnError)
	flags.SortFlags = config.Sort

	flag.PathVarP(
		flags,
		&config.Options.Output,
		config.Prefix+"output",
		lo.Ternary(config.Prefix == "", "o", ""),
		flag.Path{
			State: flag.MustNotExist,
		},
		"Output file for the downloaded content",
	)

	flag.PathVarP(
		flags,
		&config.Options.Extract,
		config.Prefix+"extract",
		lo.Ternary(config.Prefix == "", "e", ""),
		flag.Path{
			State: flag.MustNotExist,
		},
		"Extract the downloaded and verified content to this directory",
	)

	return flags
}

type UploadOptions struct {
	Input string
}

type UploadConfig struct {
	Prefix  string
	Sort    bool
	Options *UploadOptions
}

func UploadFlags(config UploadConfig) *pflag.FlagSet {
	flags := pflag.NewFlagSet("upload", pflag.ContinueOnError)
	flags.SortFlags = config.Sort

	flag.PathVarP(
		flags,
		&config.Options.Input,
		config.Prefix+"input",
		lo.Ternary(config.Prefix == "", "i", ""),
		flag.Path{
			State: flag.MustExist,
		},
		"File to upload",
	)

	return flags
}
