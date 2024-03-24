package sftp

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/illikainen/go-netutils/src/transport/types"

	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/iofs"
	"github.com/kevinburke/ssh_config"
	"github.com/pkg/errors"
	"github.com/pkg/sftp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

type Transport struct {
	uri    *url.URL
	client *sftp.Client
}

func New(uri *url.URL) (types.Transport, error) {
	username, err := getUsername(uri)
	if err != nil {
		return nil, err
	}

	auth, err := getAuthMethods(uri)
	if err != nil {
		return nil, err
	}

	hostKeyCallback, err := getHostKeyCallback()
	if err != nil {
		return nil, err
	}

	hostKeyAlgorithms, err := getHostKeyAlgorithms(uri)
	if err != nil {
		return nil, err
	}

	host, err := getHost(uri)
	if err != nil {
		return nil, err
	}

	baseURI, err := uri.Parse("/")
	if err != nil {
		return nil, err
	}

	config := ssh.ClientConfig{
		User:              username,
		Auth:              auth,
		HostKeyAlgorithms: hostKeyAlgorithms,
		HostKeyCallback:   hostKeyCallback,
		Config: ssh.Config{
			Ciphers: []string{"aes256-gcm@openssh.com"},
			// AFAICT configuring MACs is pointless with AES256-GCM, cf.
			// "1.6 transport: AES-GCM"
			// https://github.com/openssh/openssh-portable/blob/V_9_2/PROTOCOL
			MACs: []string{"hmac-sha2-512"},
		},
	}

	log.Debugf("%s: connecting to %s", uri.Scheme, baseURI)
	log.Tracef("%s: HostKeyAlgorithms: %s", uri.Scheme, strings.Join(config.HostKeyAlgorithms, ", "))
	log.Tracef("%s: Ciphers: %s", uri.Scheme, strings.Join(config.Config.Ciphers, ", "))
	log.Tracef("%s: MACs: %s", uri.Scheme, strings.Join(config.Config.MACs, ", "))

	conn, err := ssh.Dial("tcp", host, &config)
	if err != nil {
		return nil, err
	}

	client, err := sftp.NewClient(conn)
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

func getHost(uri *url.URL) (string, error) {
	port := uri.Port()
	if port == "" {
		p, err := ssh_config.GetStrict(uri.Hostname(), "Port")
		if err != nil {
			return "", err
		}
		port = p
	}

	host, err := ssh_config.GetStrict(uri.Hostname(), "Hostname")
	if err != nil {
		return "", err
	}
	if host == "" {
		host = uri.Hostname()
	}

	return fmt.Sprintf("%s:%s", host, port), nil
}

func getUsername(uri *url.URL) (string, error) {
	username := uri.User.Username()
	if username == "" {
		u, err := ssh_config.GetStrict(uri.Hostname(), "User")
		if err != nil {
			return "", err
		}

		username = u
		if username == "" {
			usr, err := user.Current()
			if err != nil {
				return "", err
			}
			if usr.Username == "" {
				return "", fmt.Errorf("missing username")
			}

			username = usr.Username
		}
	}

	return username, nil
}

func getAuthMethods(uri *url.URL) ([]ssh.AuthMethod, error) {
	password, ok := uri.User.Password()
	if ok {
		log.Debug("using password authentication")
		return []ssh.AuthMethod{ssh.Password(password)}, nil
	}

	identityMethods := []ssh.AuthMethod{}
	identityFiles, err := ssh_config.GetAllStrict(uri.Hostname(), "IdentityFile")
	if err != nil {
		return nil, err
	}
	identityFiles = append(
		identityFiles,
		filepath.Join("~", ".ssh", "id_ed25519"),
		filepath.Join("~", ".ssh", "id_rsa"),
	)

	for _, identityFile := range identityFiles {
		identityFile, err = iofs.Expand(identityFile)
		if err != nil {
			return nil, err
		}

		exists, err := iofs.Exists(identityFile)
		if err != nil {
			return nil, err
		}
		if exists {
			log.Debugf("using pubkey authentication with %s", identityFile)

			key, err := iofs.ReadFile(identityFile)
			if err != nil {
				return nil, err
			}

			signer, err := ssh.ParsePrivateKey(key)
			if err != nil {
				return nil, err
			}
			identityMethods = append(identityMethods, ssh.PublicKeys(signer))
		}
	}

	if len(identityMethods) > 0 {
		return identityMethods, nil
	}

	log.Debug("using interactive password authentication")
	_, err = fmt.Print("Password: ")
	if err != nil {
		return nil, err
	}

	pass, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return nil, err
	}

	return []ssh.AuthMethod{ssh.Password(string(pass))}, nil
}

func getHostKeyCallback() (ssh.HostKeyCallback, error) {
	files, err := ssh_config.GetStrict("", "UserKnownHostsFile")
	if err != nil {
		return nil, err
	}

	usableFiles := []string{}
	for _, file := range strings.Split(files, " ") {
		file, err = iofs.Expand(file)
		if err != nil {
			return nil, err
		}

		exists, err := iofs.Exists(file)
		if err != nil {
			return nil, err
		}
		if exists {
			usableFiles = append(usableFiles, file)
		}
	}

	if len(usableFiles) <= 0 {
		return nil, fmt.Errorf("cannot find known_hosts")
	}

	log.Debugf("known hosts: %s", strings.Join(usableFiles, ", "))
	return knownhosts.New(usableFiles...)
}

func getHostKeyAlgorithms(uri *url.URL) ([]string, error) {
	algoLine, err := ssh_config.GetStrict(uri.Hostname(), "HostKeyAlgorithms")
	if err != nil {
		return nil, err
	}

	algos := []string{}
	for _, algo := range strings.Split(algoLine, ",") {
		algo = strings.Trim(algo, " \t\r")
		if algo != "" {
			algos = append(algos, algo)
		}
	}

	return algos, nil
}
