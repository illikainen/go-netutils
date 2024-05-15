package sftp

import (
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/illikainen/go-netutils/src/sshx"
	"github.com/illikainen/go-netutils/src/transport/types"

	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/iofs"
	"github.com/pkg/errors"
	"github.com/pkg/sftp"
	log "github.com/sirupsen/logrus"
)

type Transport struct {
	uri    *url.URL
	client *sftp.Client
}

func New(uri *url.URL) (types.Transport, error) {
	password, ok := uri.User.Password()
	if !ok {
		password = ""
	}

	conn, err := sshx.Dial("tcp", uri.Host, &sshx.ClientConfig{
		User:     uri.User.Username(),
		Password: password,
	})
	if err != nil {
		return nil, err
	}

	client, err := conn.NewSFTPClient()
	if err != nil {
		return nil, err
	}

	baseURI, err := uri.Parse("/")
	if err != nil {
		return nil, err
	}

	return &Transport{uri: baseURI, client: client}, nil
}

func (t *Transport) Close() error {
	return t.client.Close()
}

func (t *Transport) Exists(remote string) (exists bool, err error) {
	remote, err = t.expand(remote)
	if err != nil {
		return false, err
	}

	uri, err := t.uri.Parse(remote)
	if err != nil {
		return false, err
	}

	log.Tracef("%s: check %s", uri.Scheme, uri)

	_, err = t.client.Stat(remote)
	if err == nil {
		return true, nil
	}

	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}

	return false, err
}

func (t *Transport) Open(remote string) (io.ReadCloser, error) {
	remote, err := t.expand(remote)
	if err != nil {
		return nil, err
	}

	uri, err := t.uri.Parse(remote)
	if err != nil {
		return nil, err
	}

	log.Infof("%s: open %s", uri.Scheme, uri)

	f, err := t.client.Open(remote)
	if err != nil {
		return nil, err
	}
	return f, err
}

func (t *Transport) Download(remote string, local string) (err error) {
	remote, err = t.expand(remote)
	if err != nil {
		return err
	}

	uri, err := t.uri.Parse(remote)
	if err != nil {
		return err
	}

	log.Infof("%s: download %s", uri.Scheme, uri)

	remotef, err := t.client.Open(remote)
	if err != nil {
		return err
	}
	defer errorx.Defer(remotef.Close, &err)

	localf, err := os.Create(local) // #nosec G304
	if err != nil {
		return err
	}
	defer errorx.Defer(localf.Close, &err)

	_, err = io.Copy(localf, remotef)
	if err != nil {
		return err
	}

	return nil
}

func (t *Transport) Upload(remote string, local string) (err error) {
	remote, err = t.expand(remote)
	if err != nil {
		return err
	}

	uri, err := t.uri.Parse(remote)
	if err != nil {
		return err
	}

	log.Infof("%s: upload %s", uri.Scheme, uri)

	f, err := t.client.Create(remote)
	if err != nil {
		return err
	}
	defer errorx.Defer(f.Close, &err)

	return iofs.Copy(f, local)
}

func (t *Transport) String() string {
	return t.uri.String()
}

func (t *Transport) expand(path string) (string, error) {
	if strings.HasPrefix(path, "/~/") {
		cwd, err := t.client.Getwd()
		if err != nil {
			return "", err
		}

		return filepath.Join(cwd, path[2:]), nil
	}

	return path, nil
}
