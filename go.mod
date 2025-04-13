module github.com/illikainen/go-netutils

go 1.19

require (
	github.com/illikainen/go-utils v0.0.0
	github.com/kevinburke/ssh_config v1.2.0
	github.com/pkg/errors v0.9.1
	github.com/pkg/sftp v1.13.5
	github.com/samber/lo v1.37.0
	github.com/sirupsen/logrus v1.9.0
	golang.org/x/crypto v0.17.0
	golang.org/x/sync v0.5.0
	golang.org/x/term v0.15.0
)

require (
	github.com/fatih/color v1.15.0 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	golang.org/x/exp v0.0.0-20230905200255-921286631fa9 // indirect
	golang.org/x/sys v0.15.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/illikainen/go-utils => ../go-utils
