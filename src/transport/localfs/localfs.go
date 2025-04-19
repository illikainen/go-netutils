package localfs

import (
	"io"
	"net/url"
	"os"

	"github.com/illikainen/go-netutils/src/transport/types"

	"github.com/illikainen/go-utils/src/iofs"
	"github.com/illikainen/go-utils/src/sandbox"
	"github.com/pkg/errors"
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

	stat, err := os.Stat(remote)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}

	// Checking the file size is an ugly workaround to deal with the
	// bubblewrap sandbox.  Files must exist before they can be mounted in
	// a sandboxed subprocess.  When Exists() is invoked in a sandbox, the
	// `remote` will have been created by the parent process, so we can't
	// rely solely on ENOENT.
	if sandbox.IsSandboxed() {
		return stat.Size() != 0, nil
	}
	return true, nil
}

func (t *Transport) Open(remote string) (io.ReadCloser, error) {
	log.Tracef("%s: open %s", t.uri.Scheme, remote)

	f, err := os.Open(remote) // #nosec G304
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.Wrap(types.ErrNotExist, remote)
		}
		return nil, err
	}

	return f, nil
}

func (t *Transport) Download(remote string, local string) error {
	log.Tracef("%s: download %s", t.uri.Scheme, remote)

	err := iofs.Copy(local, remote)
	if errors.Is(err, os.ErrNotExist) {
		return errors.Wrap(types.ErrNotExist, remote)
	}
	return err
}

func (t *Transport) Upload(remote string, local string) error {
	log.Tracef("%s: upload %s", t.uri.Scheme, remote)

	return iofs.Copy(remote, local)
}

func (t *Transport) String() string {
	return t.uri.String()
}
