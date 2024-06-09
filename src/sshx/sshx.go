package sshx

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/iofs"
	"github.com/illikainen/go-utils/src/process"
	"github.com/kevinburke/ssh_config"
	"github.com/pkg/errors"
	"github.com/pkg/sftp"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/sync/errgroup"
	"golang.org/x/term"
)

type ClientConfig struct {
	User     string
	Password string
}

type Client struct {
	*ssh.Client
	alias string
}

func Dial(network string, alias string, config *ClientConfig) (*Client, error) {
	addr, err := getAddr(alias)
	if err != nil {
		return nil, err
	}

	usr := config.User
	if usr == "" {
		usr, err = getUser(alias)
		if err != nil {
			return nil, err
		}
	}

	auth, err := getAuthMethods(alias, config.Password)
	if err != nil {
		return nil, err
	}

	hostKeyCallback, err := getHostKeyCallback(alias)
	if err != nil {
		return nil, err
	}

	hostKeyAlgorithms, err := getHostKeyAlgorithms(alias)
	if err != nil {
		return nil, err
	}

	c := ssh.ClientConfig{
		User:              usr,
		Auth:              auth,
		HostKeyCallback:   hostKeyCallback,
		HostKeyAlgorithms: hostKeyAlgorithms,
		Config: ssh.Config{
			Ciphers: []string{"aes256-gcm@openssh.com"},
			// AFAICT configuring MACs is pointless with AES256-GCM, cf.
			// "1.6 transport: AES-GCM"
			// https://github.com/openssh/openssh-portable/blob/V_9_2/PROTOCOL
			MACs: []string{"hmac-sha2-512"},
		},
	}

	log.Infof("%s: connecting to %s with ssh", alias, addr)
	log.Tracef("%s: HostKeyAlgorithms: %s", alias, strings.Join(c.HostKeyAlgorithms, ", "))
	log.Tracef("%s: Ciphers: %s", alias, strings.Join(c.Config.Ciphers, ", "))
	log.Tracef("%s: MACs: %s", alias, strings.Join(c.Config.MACs, ", "))

	client, err := ssh.Dial(network, addr, &c)
	if err != nil {
		return nil, err
	}

	return &Client{
		Client: client,
		alias:  alias,
	}, nil
}

func getAddr(alias string) (string, error) {
	host, port, err := net.SplitHostPort(alias)
	if host != "" && port != "" && err == nil {
		return alias, nil
	}

	port, err = ssh_config.GetStrict(alias, "Port")
	if err != nil {
		return "", err
	}

	host, err = ssh_config.GetStrict(alias, "Hostname")
	if err != nil {
		return "", err
	}
	if host == "" {
		host = alias
	}

	return fmt.Sprintf("%s:%s", host, port), nil
}

func getUser(alias string) (string, error) {
	usr, err := ssh_config.GetStrict(alias, "User")
	if err != nil {
		return "", err
	}

	if usr == "" {
		cur, err := user.Current()
		if err != nil {
			return "", err
		}
		usr = cur.Username
	}

	if usr == "" {
		return "", errors.Errorf("unable to determine username")
	}

	return usr, nil
}

func getAuthMethods(alias string, password string) ([]ssh.AuthMethod, error) {
	if password != "" {
		log.Debug("using password authentication")
		return []ssh.AuthMethod{ssh.Password(password)}, nil
	}

	authSock := os.Getenv("SSH_AUTH_SOCK")
	if authSock != "" {
		log.Debugf("using pubkey authentication with ssh-agent (%s)", authSock)

		conn, err := net.Dial("unix", authSock)
		if err != nil {
			return nil, err
		}

		client := agent.NewClient(conn)
		return []ssh.AuthMethod{ssh.PublicKeysCallback(client.Signers)}, nil
	}

	identityMethods := []ssh.AuthMethod{}
	identityFiles, err := ssh_config.GetAllStrict(alias, "IdentityFile")
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

	pass, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}

	return []ssh.AuthMethod{ssh.Password(string(pass))}, nil
}

func getHostKeyCallback(alias string) (ssh.HostKeyCallback, error) {
	files, err := ssh_config.GetStrict(alias, "UserKnownHostsFile")
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

func getHostKeyAlgorithms(alias string) ([]string, error) {
	algoLine, err := ssh_config.GetStrict(alias, "HostKeyAlgorithms")
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

type ExecOptions struct {
	Command string
	Become  string
	Stdin   io.Reader
	Stdout  process.OutputFunc
	Stderr  process.OutputFunc
}

type ExecOutput struct {
	Stdout []byte
	Stderr []byte
}

// NOTE: preventing command injections is the responsibility of the caller.
func (c *Client) Exec(opts *ExecOptions) (out *ExecOutput, err error) {
	session, err := c.NewSession()
	if err != nil {
		return nil, err
	}
	session.Stdin = opts.Stdin

	out = &ExecOutput{}
	group := errgroup.Group{}

	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		return nil, err
	}

	stdoutFunc := opts.Stdout
	if stdoutFunc == nil {
		stdoutFunc = process.CaptureOutput
	}

	group.Go(func() error {
		out.Stdout, err = stdoutFunc(stdoutPipe, process.Stdout)
		return err
	})

	stderrPipe, err := session.StderrPipe()
	if err != nil {
		return nil, err
	}

	stderrFunc := opts.Stderr
	if stderrFunc == nil {
		stderrFunc = process.CaptureOutput
	}

	group.Go(func() error {
		out.Stderr, err = stderrFunc(stderrPipe, process.Stderr)
		return err
	})

	cmd := opts.Command
	if opts.Become != "" {
		esc, err := c.become(opts.Become)
		if err != nil {
			return nil, err
		}

		cmd = fmt.Sprintf("%s %s", esc, cmd)
	}
	log.Tracef("%s: exec: %s", c.alias, cmd)

	err = session.Start(opts.Command)
	if err != nil {
		// XXX: what to do with the goroutine errgroup here?
		return nil, err
	}

	err = group.Wait()
	if err != nil {
		return nil, errorx.Join(err, session.Wait())
	}

	err = session.Wait()
	if err != nil {
		if len(out.Stderr) > 0 {
			return nil, errors.Errorf("%s", out.Stderr)
		}
		return nil, err
	}

	return out, nil
}

func (c *Client) become(username string) (cmd string, err error) {
	session, err := c.NewSession()
	if err != nil {
		return "", err
	}

	err = session.Run("command -v sudo")
	if err == nil {
		return fmt.Sprintf("sudo -u '%s'", username), nil
	}

	err = session.Run("command -v doas")
	if err == nil {
		return fmt.Sprintf("doas -u '%s'", username), nil
	}

	return "", errors.Errorf("unable to find a suitable program to change privileges")
}

func (c *Client) NewSFTPClient() (*sftp.Client, error) {
	return sftp.NewClient(c.Client)
}

func (c *Client) Close() error {
	return c.Client.Close()
}

func SandboxPaths() (ro []string, rw []string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, err
	}

	ro = append(
		ro,
		filepath.Join(home, ".ssh", "config"),
		filepath.Join(string(os.PathSeparator), "etc", "ssh", "ssh_config"),
		os.Getenv("SSH_AUTH_SOCK"),
	)

	userHostValue, err := ssh_config.GetStrict("", "UserKnownHostsFile")
	if err != nil {
		return nil, nil, err
	}
	ro = append(ro, strings.Split(userHostValue, " ")...)

	globalHostValue, err := ssh_config.GetStrict("", "GlobalKnownHostsFile")
	if err != nil {
		return nil, nil, err
	}
	ro = append(ro, strings.Split(globalHostValue, " ")...)

	return lo.Filter(ro, func(path string, _ int) bool {
		return path != ""
	}), nil, nil
}
