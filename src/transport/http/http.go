package http

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/illikainen/go-netutils/src/transport/types"

	"github.com/illikainen/go-utils/src/errorx"
	log "github.com/sirupsen/logrus"
)

type Transport struct {
	uri *url.URL
}

func New(uri *url.URL) (types.Transport, error) {
	return &Transport{uri: uri}, nil
}

func (t *Transport) Close() error {
	return nil
}

func (t *Transport) Exists(remote string) (exists bool, err error) {
	uri, err := t.uri.Parse(remote)
	if err != nil {
		return false, err
	}

	log.Tracef("http: check %s", uri)

	resp, err := http.Head(uri.String())
	if err != nil {
		return false, err
	}

	return resp.StatusCode == http.StatusOK, nil
}

func (t *Transport) Open(remote string) (io.ReadCloser, error) {
	uri, err := t.uri.Parse(remote)
	if err != nil {
		return nil, err
	}

	log.Tracef("%s: open %s", uri.Scheme, uri)

	resp, err := http.Get(uri.String())
	if err != nil {
		return nil, err
	}

	return resp.Body, nil
}

func (t *Transport) Download(remote string, local string) (err error) {
	uri, err := t.uri.Parse(remote)
	if err != nil {
		return err
	}

	log.Tracef("http: download %s", uri)

	resp, err := http.Get(uri.String())
	if err != nil {
		return err
	}
	defer errorx.Defer(resp.Body.Close, &err)

	localf, err := os.Create(local) // #nosec G304
	if err != nil {
		return err
	}
	defer errorx.Defer(localf.Close, &err)

	_, err = io.Copy(localf, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func (t *Transport) Upload(remote string, _ string) error {
	uri, err := t.uri.Parse(remote)
	if err != nil {
		return err
	}

	return fmt.Errorf("http: unable to upload %s", uri)
}

func (t *Transport) String() string {
	return t.uri.String()
}
