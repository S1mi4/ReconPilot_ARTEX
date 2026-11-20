package server

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

const taskJavaCodeDBManifestName = ".artex-javacodedb.json"

type taskJavaCodeDBWorkspaceManifest struct {
	Identity string `json:"identity"`
	SHA256   string `json:"sha256"`
}

func (s *Server) prepareTaskJavaCodeDBWorkspace(codebase *taskCodeAuditCodebase, serviceID int64, version taskCodebaseVersion) (string, error) {
	if codebase == nil || s == nil || s.m == nil {
		return "", errors.New("JavaCodeDB workspace is unavailable")
	}
	versionRoot := filepath.Join(s.m.taskCodebaseRoot(strconv.FormatInt(codebase.TaskID, 10)), version.ID)
	if err := ensureTaskCodebaseDirectories(versionRoot, false); err != nil {
		return "", errors.New("codebase version storage is unavailable")
	}
	parent := filepath.Join(versionRoot, "javacodedb")
	if err := ensureTaskCodebaseDirectories(parent, true); err != nil {
		return "", err
	}
	digest, err := taskJavaCodeDBSourceDigest(codebase)
	if err != nil {
		return "", err
	}
	identityInput := strings.Join([]string{
		fmt.Sprint(codebase.TaskID), version.ID, version.CodebaseID, fmt.Sprint(serviceID),
		codebase.ArchivePrefix, codebase.ScopePath, codebase.ArtifactName, digest,
	}, "\x00")
	identityHash := sha256.Sum256([]byte(identityInput))
	identity := hex.EncodeToString(identityHash[:])
	workspace := filepath.Join(parent, identity)
	if _, err := os.Lstat(workspace); err == nil {
		if err := ensureTaskCodebaseDirectories(workspace, false); err != nil {
			return "", errors.New("existing JavaCodeDB workspace is unsafe")
		}
		manifest, err := taskJavaCodeDBReadManifest(workspace)
		if err != nil || manifest.Identity != identity || manifest.SHA256 != digest {
			return "", errors.New("existing JavaCodeDB workspace does not match this immutable codebase version")
		}
		codebase.JavaCodeDBWorkspace = workspace
		codebase.ArtifactSHA256 = digest
		return workspace, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	temporary, err := os.MkdirTemp(parent, ".building-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(temporary)
	if err := buildTaskJavaCodeDBWorkspace(codebase, temporary); err != nil {
		return "", err
	}
	manifestBytes, err := json.Marshal(taskJavaCodeDBWorkspaceManifest{Identity: identity, SHA256: digest})
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(temporary, taskJavaCodeDBManifestName), manifestBytes, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, workspace); err != nil {
		if _, statErr := os.Lstat(workspace); statErr != nil {
			return "", err
		}
		manifest, readErr := taskJavaCodeDBReadManifest(workspace)
		if readErr != nil || manifest.Identity != identity || manifest.SHA256 != digest {
			return "", err
		}
	}
	codebase.JavaCodeDBWorkspace = workspace
	codebase.ArtifactSHA256 = digest
	return workspace, nil
}

func taskJavaCodeDBReadManifest(workspace string) (taskJavaCodeDBWorkspaceManifest, error) {
	var manifest taskJavaCodeDBWorkspaceManifest
	filename := filepath.Join(workspace, taskJavaCodeDBManifestName)
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return manifest, errors.New("JavaCodeDB workspace manifest is missing or unsafe")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return manifest, err
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func taskJavaCodeDBSourceDigest(codebase *taskCodeAuditCodebase) (string, error) {
	if codebase.ArchivePath != "" {
		return sha256File(codebase.ArchivePath)
	}
	files := make([]taskCodeAuditFile, 0, len(codebase.BinaryClassFiles))
	seen := map[string]bool{}
	for _, classFile := range codebase.BinaryClassFiles {
		inputPath := classFile
		if separator := strings.Index(inputPath, "!"); separator >= 0 {
			inputPath = inputPath[:separator]
		}
		if seen[inputPath] {
			continue
		}
		seen[inputPath] = true
		if file, ok := codebase.ByPath[inputPath]; ok && file.Disk != "" {
			files = append(files, file)
			continue
		}
		filename := filepath.Join(codebase.ServiceRoot, filepath.FromSlash(inputPath))
		info, err := os.Lstat(filename)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		files = append(files, taskCodeAuditFile{Path: inputPath, Disk: filename})
	}
	if len(files) == 0 {
		return "", errors.New("could not identify Java class inputs for hashing")
	}
	return taskCodeAuditFilesDigest(files)
}

func taskCodeAuditFilesDigest(files []taskCodeAuditFile) (string, error) {
	// Hash filenames and contents in stable order so a directory service gets a
	// reproducible identity without sharing JavaCodeDB's cross-task cache.
	files = append([]taskCodeAuditFile(nil), files...)
	sortTaskCodeAuditFiles(files)
	hash := sha256.New()
	for _, file := range files {
		if file.Disk == "" {
			continue
		}
		info, err := os.Lstat(file.Disk)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("JavaCodeDB input changed while hashing")
		}
		// Length-prefix both fields so name/content boundaries cannot be confused.
		_, _ = fmt.Fprintf(hash, "%d:%s:%d:", len(file.Path), file.Path, info.Size())
		input, err := os.Open(file.Disk)
		if err != nil {
			return "", err
		}
		_, copyErr := io.Copy(hash, input)
		closeErr := input.Close()
		if copyErr != nil || closeErr != nil {
			return "", errors.Join(copyErr, closeErr)
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func buildTaskJavaCodeDBWorkspace(codebase *taskCodeAuditCodebase, workspace string) error {
	if codebase == nil || len(codebase.BinaryClassFiles) == 0 {
		return errors.New("selected Java service has no class files")
	}
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		return err
	}
	switch codebase.ArchiveKind {
	case "zip", "jar", "war":
		if codebase.ArchivePrefix == "" {
			return taskJavaCodeDBLinkOrCopy(codebase.ArchivePath, filepath.Join(workspace, filepath.Base(codebase.ArchivePath)))
		}
		return taskJavaCodeDBExtractScopedArchive(codebase, workspace)
	case "class":
		name := filepath.Base(codebase.ArchivePath)
		return taskJavaCodeDBLinkOrCopy(codebase.ArchivePath, filepath.Join(workspace, name))
	case "directory":
		return taskJavaCodeDBLinkDirectory(codebase, workspace)
	case "tar":
		return taskJavaCodeDBExtractScopedTar(codebase, workspace)
	default:
		return fmt.Errorf("unsupported JavaCodeDB workspace format %q", codebase.ArchiveKind)
	}
}

func taskJavaCodeDBLinkDirectory(codebase *taskCodeAuditCodebase, workspace string) error {
	return filepath.WalkDir(codebase.ServiceRoot, func(source string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if source == codebase.ServiceRoot {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if excludedJavaCodeDBDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(codebase.ServiceRoot, source)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !taskJavaCodeDBWorkspaceFile(rel) {
			return nil
		}
		if _, err := safeTaskCodebasePath(rel); err != nil {
			return nil
		}
		return taskJavaCodeDBLinkOrCopy(source, filepath.Join(workspace, filepath.FromSlash(rel)))
	})
}

func excludedJavaCodeDBDirectory(name string) bool {
	switch strings.ToLower(name) {
	case ".git", ".idea", ".gradle", "target", "build", "out", "generated", "generated-sources", "node_modules", "vendor":
		return true
	default:
		return false
	}
}

func taskJavaCodeDBExtractScopedArchive(codebase *taskCodeAuditCodebase, workspace string) error {
	file, err := os.Open(codebase.ArchivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	archive, err := zip.NewReader(file, info.Size())
	if err != nil {
		return err
	}
	prefix := codebase.ArchivePrefix
	var expanded int64
	for _, entry := range archive.File {
		if !strings.HasPrefix(entry.Name, prefix) || entry.FileInfo().IsDir() || entry.Mode()&os.ModeSymlink != 0 {
			continue
		}
		rel := strings.TrimPrefix(entry.Name, prefix)
		if _, err := safeTaskCodebasePath(rel); err != nil || !taskJavaCodeDBWorkspaceFile(rel) {
			continue
		}
		if entry.UncompressedSize64 > uint64(maxTaskCodebaseExpandedSize-expanded) {
			return errors.New("selected Java service exceeds the extraction limit")
		}
		reader, err := entry.Open()
		if err != nil {
			return err
		}
		target := filepath.Join(workspace, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			reader.Close()
			return err
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
		if err != nil {
			reader.Close()
			return err
		}
		written, copyErr := io.Copy(output, io.LimitReader(reader, maxTaskCodebaseExpandedSize-expanded+1))
		closeReadErr := reader.Close()
		closeWriteErr := output.Close()
		if copyErr != nil || closeReadErr != nil || closeWriteErr != nil {
			return errors.Join(copyErr, closeReadErr, closeWriteErr)
		}
		if written > maxTaskCodebaseExpandedSize-expanded {
			return errors.New("selected Java service exceeds the extraction limit")
		}
		expanded += written
	}
	return nil
}

func taskJavaCodeDBExtractScopedTar(codebase *taskCodeAuditCodebase, workspace string) error {
	file, err := os.Open(codebase.ArchivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := tar.NewReader(file)
	prefix := codebase.ArchivePrefix
	var expanded int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if !strings.HasPrefix(header.Name, prefix) || (header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) {
			continue
		}
		rel := strings.TrimPrefix(header.Name, prefix)
		if _, err := safeTaskCodebasePath(rel); err != nil || !taskJavaCodeDBWorkspaceFile(rel) {
			continue
		}
		if header.Size < 0 || header.Size > maxTaskCodebaseExpandedSize-expanded {
			return errors.New("selected Java service exceeds the extraction limit")
		}
		target := filepath.Join(workspace, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return err
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
		if err != nil {
			return err
		}
		written, copyErr := io.Copy(output, io.LimitReader(reader, header.Size+1))
		closeErr := output.Close()
		if copyErr != nil || closeErr != nil {
			return errors.Join(copyErr, closeErr)
		}
		if written != header.Size {
			return io.ErrUnexpectedEOF
		}
		expanded += written
	}
}

func taskJavaCodeDBWorkspaceFile(rel string) bool {
	lower := strings.ToLower(rel)
	ext := path.Ext(lower)
	return ext == ".class" || ext == ".jar" || ext == ".war" || ext == ".ear" || ext == ".zip" ||
		ext == ".properties" || ext == ".yml" || ext == ".yaml" || ext == ".xml" || ext == ".jsp" || ext == ".jspx" ||
		ext == ".tag" || ext == ".tagx"
}

func taskJavaCodeDBClassEntries(filename, artifactPath string) ([]string, error) {
	archive, err := zip.OpenReader(filename)
	if err != nil {
		return nil, err
	}
	defer archive.Close()
	count := 0
	return taskJavaCodeDBScanZip(&archive.Reader, artifactPath+"!", 0, &count)
}

func taskJavaCodeDBClassEntriesFromZipEntry(entry *zip.File, artifactPath string) ([]string, error) {
	if entry == nil || entry.UncompressedSize64 > 128<<20 || entry.Mode()&os.ModeSymlink != 0 {
		return nil, nil
	}
	reader, err := entry.Open()
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(reader, (128<<20)+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if len(data) > 128<<20 {
		return nil, nil
	}
	return taskJavaCodeDBClassEntriesFromBytes(data, artifactPath)
}

func taskJavaCodeDBClassEntriesFromBytes(data []byte, artifactPath string) ([]string, error) {
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	count := 0
	return taskJavaCodeDBScanZip(archive, artifactPath+"!", 1, &count)
}

func taskJavaCodeDBScanZip(archive *zip.Reader, prefix string, depth int, count *int) ([]string, error) {
	if depth > 4 {
		return nil, nil
	}
	classes := make([]string, 0)
	for _, entry := range archive.File {
		*count = *count + 1
		if *count > maxTaskCodebaseArchiveFiles {
			return classes, errors.New("nested Java archive contains too many entries")
		}
		if entry.FileInfo().IsDir() || entry.Mode()&os.ModeSymlink != 0 {
			continue
		}
		name := strings.ReplaceAll(entry.Name, "\\", "/")
		if _, err := safeTaskCodebasePath(name); err != nil {
			continue
		}
		if strings.EqualFold(path.Ext(name), ".class") {
			classes = append(classes, prefix+name)
			continue
		}
		ext := strings.ToLower(path.Ext(name))
		if ext != ".jar" && ext != ".war" && ext != ".ear" && ext != ".zip" {
			continue
		}
		if entry.UncompressedSize64 > 128<<20 {
			continue
		}
		reader, err := entry.Open()
		if err != nil {
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(reader, (128<<20)+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || len(data) > 128<<20 {
			continue
		}
		nested, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			continue
		}
		nestedClasses, err := taskJavaCodeDBScanZip(nested, prefix+name+"!", depth+1, count)
		if err != nil {
			return classes, err
		}
		classes = append(classes, nestedClasses...)
	}
	return classes, nil
}

func taskJavaCodeDBLinkOrCopy(source, target string) error {
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("JavaCodeDB input is not a regular file")
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return err
	}
	if err := os.Link(source, target); err == nil {
		return nil
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	return errors.Join(copyErr, closeErr)
}
