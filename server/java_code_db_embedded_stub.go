//go:build !javacodedb

package server

import "errors"

func taskJavaCodeDBMaterializedPath() (string, error) {
	return "", errors.New("JavaCodeDB is not embedded in this build")
}
