//go:build javacodedb

package server

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// The release builder compresses the JavaCodeDB JAR before embedding it. This
// fallback lets a new ARTEX binary migrate from older self-updaters that only
// replaced the executable and did not know about the JavaCodeDB sidecar.
//
//go:embed java_code_db_embedded.jar.gz
var taskJavaCodeDBEmbeddedGZIP []byte

var (
	taskJavaCodeDBEmbeddedOnce sync.Once
	taskJavaCodeDBEmbeddedPath string
	taskJavaCodeDBEmbeddedErr  error
)

// taskJavaCodeDBEmbeddedDirectory is a private per-user directory that survives
// restarts, so the JAR is unpacked once per content hash instead of once per run.
// Falling back to a fresh temp directory keeps working where no cache dir exists.
func taskJavaCodeDBEmbeddedDirectory() (string, error) {
	if cache, err := os.UserCacheDir(); err == nil {
		directory := filepath.Join(cache, "artex", "javacodedb")
		if err := os.MkdirAll(directory, 0o700); err == nil {
			if err := os.Chmod(directory, 0o700); err == nil {
				return directory, nil
			}
		}
	}
	directory, err := os.MkdirTemp("", "artex-javacodedb-")
	if err != nil {
		return "", err
	}
	return directory, os.Chmod(directory, 0o700)
}

func taskJavaCodeDBMaterializedPath() (string, error) {
	taskJavaCodeDBEmbeddedOnce.Do(func() {
		if len(taskJavaCodeDBEmbeddedGZIP) == 0 {
			taskJavaCodeDBEmbeddedErr = errors.New("embedded JavaCodeDB JAR is empty")
			return
		}
		directory, err := taskJavaCodeDBEmbeddedDirectory()
		if err != nil {
			taskJavaCodeDBEmbeddedErr = err
			return
		}
		reader, err := gzip.NewReader(bytes.NewReader(taskJavaCodeDBEmbeddedGZIP))
		if err != nil {
			taskJavaCodeDBEmbeddedErr = err
			return
		}
		output, err := os.CreateTemp(directory, ".java-code-db-*.tmp")
		if err != nil {
			_ = reader.Close()
			taskJavaCodeDBEmbeddedErr = err
			return
		}
		temporary := output.Name()
		defer os.Remove(temporary)
		hash := sha256.New()
		_, copyErr := io.Copy(io.MultiWriter(output, hash), reader)
		readerErr := reader.Close()
		chmodErr := output.Chmod(0o600)
		syncErr := output.Sync()
		outputErr := output.Close()
		if err := errors.Join(copyErr, readerErr, chmodErr, syncErr, outputErr); err != nil {
			taskJavaCodeDBEmbeddedErr = err
			return
		}
		name := "java-code-db-" + hex.EncodeToString(hash.Sum(nil))[:16] + ".jar"
		filename := filepath.Join(directory, name)
		// The name carries the content hash, so restarts overwrite the same file
		// (atomically) instead of piling up a new temp copy each time.
		if err := os.Rename(temporary, filename); err != nil {
			taskJavaCodeDBEmbeddedErr = err
			return
		}
		// Drop JARs unpacked by other versions of ARTEX.
		if entries, err := os.ReadDir(directory); err == nil {
			for _, entry := range entries {
				if entry.Name() != name && strings.HasPrefix(entry.Name(), "java-code-db-") && strings.HasSuffix(entry.Name(), ".jar") {
					_ = os.Remove(filepath.Join(directory, entry.Name()))
				}
			}
		}
		taskJavaCodeDBEmbeddedPath = filename
	})
	return taskJavaCodeDBEmbeddedPath, taskJavaCodeDBEmbeddedErr
}
