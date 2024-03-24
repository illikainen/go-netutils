package localfs

import (
	"io"
	"net/url"
	"os"

	"github.com/illikainen/go-netutils/src/transport/types"

	"github.com/illikainen/go-utils/src/iofs"
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

func (t *Transport) Exists(remote string) (bool, error) {
	log.Tracef("%s: check %s", t.uri.Scheme, remote)

	return iofs.Exists(remote)
}

func (t *Transport) Open(remote string) (io.ReadCloser, error) {
	log.Infof("%s: open %s", t.uri.Scheme, remote)

	return os.Open(remote) // #nosec G304
}

func (t *Transport) Download(remote string, local string) error {
	log.Infof("%s: download %s", t.uri.Scheme, remote)

	return iofs.Copy(local, remote)
}

func (t *Transport) Upload(remote string, local string) error {
	log.Infof("%s: upload %s", t.uri.Scheme, remote)

	return iofs.Copy(remote, local)
}

func (t *Transport) String() string {
	return t.uri.String()
}
