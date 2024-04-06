package sshx

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/kevinburke/ssh_config"
	"github.com/samber/lo"
)

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
