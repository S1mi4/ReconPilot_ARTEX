package server

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
)

const (
	maxTaskCodebaseUpload       = 512 << 20
	maxTaskCodebaseFiles        = 20000
	maxTaskCodebaseArchiveFiles = 50000
	maxTaskCodebaseExpandedSize = int64(8 << 30)
)

const taskCodebaseManifestName = "manifest.json"

type taskCodebaseVersion struct {
	ID         string    `json:"id"`
	CodebaseID string    `json:"codebase_id"`
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	Format     string    `json:"format"`
	FileCount  int       `json:"file_count"`
	TotalSize  int64     `json:"total_size"`
	CreatedAt  time.Time `json:"created_at"`
}

type taskCodebaseUploadFile struct {
	header *multipart.FileHeader
	path   string
}

type taskCodebaseUpload struct {
	kind       string
	name       string
	format     string
	codebaseID string
	files      []taskCodebaseUploadFile
}

// GET /api/tasks/{id}/codebases
func (s *Server) taskCodebasesList(w http.ResponseWriter, r *http.Request) {
	taskID, ok := validCodebaseTaskID(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	if _, ok := s.m.Task(taskID); !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	rootPath := taskCodebaseRootPath(s.m.dir, taskID)
	if err := ensureTaskCodebaseDirectories(rootPath, false); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeJSON(w, http.StatusOK, map[string]any{"versions": []taskCodebaseVersion{}})
			return
		}
		writeErr(w, http.StatusInternalServerError, "无法读取代码库版本")
		return
	}
	entries, err := os.ReadDir(rootPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "无法读取代码库版本")
		return
	}
	versions := make([]taskCodebaseVersion, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !validCodebaseVersionID(entry.Name()) {
			continue
		}
		versionDir := filepath.Join(rootPath, entry.Name())
		info, err := os.Lstat(versionDir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		manifestPath := filepath.Join(versionDir, taskCodebaseManifestName)
		manifestInfo, err := os.Lstat(manifestPath)
		if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Mode()&os.ModeSymlink != 0 {
			continue
		}
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "无法读取代码库版本")
			return
		}
		var version taskCodebaseVersion
		if err := json.Unmarshal(data, &version); err != nil || version.ID != entry.Name() {
			writeErr(w, http.StatusInternalServerError, "代码库版本记录损坏")
			return
		}
		if version.CodebaseID == "" {
			version.CodebaseID = taskCodebaseIdentityID(taskID, version.Kind, version.Name)
		}
		versions = append(versions, version)
	}
	sort.Slice(versions, func(i, j int) bool {
		if versions[i].CreatedAt.Equal(versions[j].CreatedAt) {
			return versions[i].ID > versions[j].ID
		}
		return versions[i].CreatedAt.After(versions[j].CreatedAt)
	})
	writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
}

// POST /api/tasks/{id}/codebases — multipart form fields "kind", repeated
// "file", and a matching repeated "relative_path" field. Directory paths come
// from the browser's webkitRelativePath and are validated before they reach disk.
func (s *Server) taskCodebasesUpload(w http.ResponseWriter, r *http.Request) {
	taskID, ok := validCodebaseTaskID(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	if _, ok := s.m.Task(taskID); !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	if s.engine == nil || !s.engine.beginTaskOperation(taskID) {
		writeErr(w, http.StatusConflict, "任务正在删除，无法上传代码库")
		return
	}
	defer s.engine.decInflight(taskID)

	r.Body = http.MaxBytesReader(w, r.Body, maxTaskCodebaseUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeErr(w, http.StatusRequestEntityTooLarge, "代码库上传超过大小限制")
			return
		}
		writeErr(w, http.StatusBadRequest, "代码库上传格式无效或超过大小限制")
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	upload, err := validateTaskCodebaseUpload(r.MultipartForm)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	version, err := s.saveTaskCodebaseVersion(taskID, upload)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errInvalidTaskCodebase) {
			status = http.StatusBadRequest
		}
		writeErr(w, status, err.Error())
		return
	}
	discoveryStatus := s.enqueueTaskCodebaseDiscovery(taskID, version)
	writeJSON(w, http.StatusCreated, map[string]any{"version": version, "discovery_status": discoveryStatus})
}

var errInvalidTaskCodebase = errors.New("invalid task codebase")

func validCodebaseTaskID(raw string) (string, bool) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 || strconv.FormatInt(id, 10) != raw {
		return "", false
	}
	return raw, true
}

func validCodebaseVersionID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func taskCodebaseRootPath(dataDir, taskID string) string {
	return filepath.Join(dataDir, "tasks", taskID, "codebases")
}

func ensureTaskCodebaseDirectories(rootPath string, create bool) error {
	abs, err := filepath.Abs(rootPath)
	if err != nil {
		return err
	}
	volume := filepath.VolumeName(abs)
	current := volume + string(os.PathSeparator)
	rel := strings.TrimPrefix(strings.TrimPrefix(abs, volume), string(os.PathSeparator))
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, fs.ErrNotExist) && create {
			if mkdirErr := os.Mkdir(current, 0o750); mkdirErr != nil && !errors.Is(mkdirErr, fs.ErrExist) {
				return mkdirErr
			}
			info, statErr = os.Lstat(current)
		}
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fs.ErrPermission
		}
	}
	return nil
}

func validateTaskCodebaseUpload(form *multipart.Form) (taskCodebaseUpload, error) {
	var upload taskCodebaseUpload
	if form == nil {
		return upload, fmt.Errorf("%w: missing multipart form", errInvalidTaskCodebase)
	}
	kinds := form.Value["kind"]
	codebaseIDs := form.Value["codebase_id"]
	files := form.File["file"]
	paths := form.Value["relative_path"]
	if len(kinds) != 1 || (kinds[0] != "directory" && kinds[0] != "source_archive" && kinds[0] != "artifact") {
		return upload, fmt.Errorf("%w: kind must be directory, source_archive or artifact", errInvalidTaskCodebase)
	}
	if len(codebaseIDs) > 1 || (len(codebaseIDs) == 1 && codebaseIDs[0] != "" && !validCodebaseVersionID(codebaseIDs[0])) {
		return upload, fmt.Errorf("%w: codebase_id must be a 32-character hexadecimal identifier", errInvalidTaskCodebase)
	}
	if len(codebaseIDs) == 1 {
		upload.codebaseID = codebaseIDs[0]
	}
	if len(files) == 0 || len(files) > maxTaskCodebaseFiles || len(paths) != len(files) {
		return upload, fmt.Errorf("%w: upload must include 1 to %d files and matching paths", errInvalidTaskCodebase, maxTaskCodebaseFiles)
	}
	if (kinds[0] == "source_archive" || kinds[0] == "artifact") && len(files) != 1 {
		return upload, fmt.Errorf("%w: upload one source archive or deployment package at a time", errInvalidTaskCodebase)
	}
	out := make([]taskCodebaseUploadFile, 0, len(files))
	seen := make(map[string]struct{}, len(files))
	var total int64
	rootName := ""
	for i, header := range files {
		rel, err := safeTaskCodebasePath(paths[i])
		if err != nil {
			return upload, fmt.Errorf("%w: invalid relative path", errInvalidTaskCodebase)
		}
		if (kinds[0] == "source_archive" || kinds[0] == "artifact") && path.Base(rel) != rel {
			return upload, fmt.Errorf("%w: archive path must be a filename", errInvalidTaskCodebase)
		}
		key := strings.ToLower(rel)
		if _, exists := seen[key]; exists {
			return upload, fmt.Errorf("%w: duplicate file path", errInvalidTaskCodebase)
		}
		for existing := range seen {
			if strings.HasPrefix(key, existing+"/") || strings.HasPrefix(existing, key+"/") {
				return upload, fmt.Errorf("%w: file path conflicts with another path", errInvalidTaskCodebase)
			}
		}
		seen[key] = struct{}{}
		if kinds[0] == "directory" {
			top := strings.SplitN(rel, "/", 2)[0]
			if rootName == "" {
				rootName = top
			} else if rootName != top {
				return upload, fmt.Errorf("%w: directory upload must contain one root folder", errInvalidTaskCodebase)
			}
		}
		if header.Size < 0 || header.Size > maxTaskCodebaseUpload-total {
			return upload, fmt.Errorf("%w: upload exceeds size limit", errInvalidTaskCodebase)
		}
		total += header.Size
		out = append(out, taskCodebaseUploadFile{header: header, path: rel})
	}
	upload.kind = kinds[0]
	upload.files = out
	if kinds[0] == "artifact" {
		format, ok := taskCodebaseArtifactFormat(out[0].path)
		if !ok {
			return taskCodebaseUpload{}, fmt.Errorf("%w: unsupported artifact format", errInvalidTaskCodebase)
		}
		upload.name = out[0].path
		upload.format = format
	} else if kinds[0] == "source_archive" {
		format, ok := taskCodebaseSourceArchiveFormat(out[0].path)
		if !ok {
			return taskCodebaseUpload{}, fmt.Errorf("%w: source archive must be ZIP, TAR, TAR.GZ or TGZ", errInvalidTaskCodebase)
		}
		upload.name = taskCodebaseSourceArchiveName(out[0].path)
		if upload.name == "" || upload.name == "." {
			return taskCodebaseUpload{}, fmt.Errorf("%w: source archive name is invalid", errInvalidTaskCodebase)
		}
		upload.format = format
	} else {
		upload.name = rootName
		upload.format = "directory"
	}
	return upload, nil
}

func safeTaskCodebasePath(raw string) (string, error) {
	if raw == "" || len(raw) > 4096 || strings.ContainsAny(raw, "\\:\x00") || path.IsAbs(raw) || !fs.ValidPath(raw) || path.Clean(raw) != raw {
		return "", errors.New("invalid path")
	}
	for _, part := range strings.Split(raw, "/") {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("invalid path")
		}
	}
	return raw, nil
}

func taskCodebaseArtifactFormat(name string) (string, bool) {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return "zip", true
	case strings.HasSuffix(lower, ".tar"):
		return "tar", true
	case strings.HasSuffix(lower, ".jar"):
		return "jar", true
	case strings.HasSuffix(lower, ".war"):
		return "war", true
	case strings.HasSuffix(lower, ".class"):
		return "class", true
	default:
		return "", false
	}
}

func taskCodebaseSourceArchiveFormat(name string) (string, bool) {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return "tar.gz", true
	case strings.HasSuffix(lower, ".zip"):
		return "zip", true
	case strings.HasSuffix(lower, ".tar"):
		return "tar", true
	default:
		return "", false
	}
}

func taskCodebaseSourceArchiveName(name string) string {
	base := path.Base(name)
	lower := strings.ToLower(base)
	for _, suffix := range []string{".tar.gz", ".tgz", ".zip", ".tar"} {
		if strings.HasSuffix(lower, suffix) {
			return base[:len(base)-len(suffix)]
		}
	}
	return base
}

func (s *Server) saveTaskCodebaseVersion(taskID string, upload taskCodebaseUpload) (taskCodebaseVersion, error) {
	var version taskCodebaseVersion
	versionID, err := newTaskCodebaseVersionID()
	if err != nil {
		return version, err
	}
	rootPath := taskCodebaseRootPath(s.m.dir, taskID)
	if err := ensureTaskCodebaseDirectories(rootPath, true); err != nil {
		return version, err
	}
	stageID := ".upload-" + versionID
	stagePath := filepath.Join(rootPath, stageID)
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		return version, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(stagePath)
		}
	}()

	totalSize := int64(0)
	sourceArchivePath := ""
	for _, item := range upload.files {
		rel := filepath.FromSlash(item.path)
		dest := filepath.Join(stagePath, "contents", rel)
		if upload.kind == "source_archive" {
			dest = filepath.Join(stagePath, ".source-archive")
			sourceArchivePath = dest
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			return version, err
		}
		src, err := item.header.Open()
		if err != nil {
			return version, err
		}
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
		if err != nil {
			_ = src.Close()
			return version, err
		}
		written, copyErr := io.Copy(out, src)
		closeOutErr := out.Close()
		closeSrcErr := src.Close()
		if copyErr != nil {
			return version, copyErr
		}
		if closeOutErr != nil {
			return version, closeOutErr
		}
		if closeSrcErr != nil {
			return version, closeSrcErr
		}
		if written != item.header.Size || written > maxTaskCodebaseUpload-totalSize {
			return version, fmt.Errorf("%w: upload size changed while saving", errInvalidTaskCodebase)
		}
		totalSize += written
	}
	fileCount := len(upload.files)
	storedKind := upload.kind
	storedFormat := upload.format
	storedName := upload.name
	if upload.kind == "source_archive" {
		extractedFiles, expandedSize, err := extractTaskCodebaseSourceArchive(sourceArchivePath, upload.format,
			filepath.Join(stagePath, "contents", filepath.FromSlash(upload.name)))
		if err != nil {
			return version, fmt.Errorf("%w: unable to extract source archive: %v", errInvalidTaskCodebase, err)
		}
		if extractedFiles == 0 {
			return version, fmt.Errorf("%w: source archive contains no files", errInvalidTaskCodebase)
		}
		if err := os.Remove(sourceArchivePath); err != nil {
			return version, err
		}
		fileCount = extractedFiles
		totalSize = expandedSize
		storedKind = "directory"
		storedFormat = "directory"
	} else if upload.kind == "artifact" {
		artifactPath := filepath.Join(stagePath, "contents", filepath.FromSlash(upload.files[0].path))
		if err := inspectTaskCodebaseArtifact(artifactPath, upload.format); err != nil {
			return version, fmt.Errorf("%w: %v", errInvalidTaskCodebase, err)
		}
	}
	version = taskCodebaseVersion{
		ID:         versionID,
		CodebaseID: upload.codebaseID,
		Name:       storedName,
		Kind:       storedKind,
		Format:     storedFormat,
		FileCount:  fileCount,
		TotalSize:  totalSize,
		CreatedAt:  time.Now().UTC(),
	}
	if version.CodebaseID == "" {
		version.CodebaseID = taskCodebaseIdentityID(taskID, version.Kind, version.Name)
	}
	manifest, err := json.MarshalIndent(version, "", "  ")
	if err != nil {
		return taskCodebaseVersion{}, err
	}
	if err := os.WriteFile(filepath.Join(stagePath, taskCodebaseManifestName), manifest, 0o640); err != nil {
		return taskCodebaseVersion{}, err
	}
	finalPath := filepath.Join(rootPath, versionID)
	if err := os.Rename(stagePath, finalPath); err != nil {
		return taskCodebaseVersion{}, err
	}
	committed = true
	return version, nil
}

func taskCodebaseIdentityID(taskID, kind, name string) string {
	key := strings.Join([]string{taskID, kind, strings.TrimSpace(name)}, "\x00")
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16])
}

func (s *Server) enqueueTaskCodebaseDiscovery(taskID string, version taskCodebaseVersion) string {
	if s.m.pg == nil || s.engine == nil || !s.engine.beginTaskOperation(taskID) {
		return "unavailable"
	}
	numericTaskID, _ := strconv.ParseInt(taskID, 10, 64)
	ref := pgdb.TaskCodebaseVersionRef{ID: version.ID, CodebaseID: version.CodebaseID, CreatedAt: version.CreatedAt}
	if err := s.m.pg.QueueTaskCodebaseDiscovery(numericTaskID, ref); err != nil {
		s.engine.decInflight(taskID)
		log.Printf("[codebase-discovery] task %s version %s queue failed: %v", taskID, version.ID, err)
		return "failed"
	}
	go func() {
		defer s.engine.decInflight(taskID)
		s.runTaskCodebaseDiscovery(numericTaskID, version)
	}()
	return "queued"
}

func newTaskCodebaseVersionID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}

func inspectTaskCodebaseArtifact(filename, format string) error {
	switch format {
	case "zip", "jar", "war":
		return inspectTaskCodebaseZip(filename)
	case "tar":
		return inspectTaskCodebaseTar(filename)
	case "class":
		f, err := os.Open(filename)
		if err != nil {
			return err
		}
		defer f.Close()
		var magic [4]byte
		if _, err := io.ReadFull(f, magic[:]); err != nil {
			return err
		}
		if !bytes.Equal(magic[:], []byte{0xca, 0xfe, 0xba, 0xbe}) {
			return errors.New("invalid Java class file")
		}
		return nil
	default:
		return errors.New("unsupported artifact format")
	}
}

func extractTaskCodebaseSourceArchive(filename, format, destination string) (int, int64, error) {
	switch format {
	case "zip":
		if err := inspectTaskCodebaseZip(filename); err != nil {
			return 0, 0, err
		}
		return extractTaskCodebaseZip(filename, destination)
	case "tar":
		if err := inspectTaskCodebaseTar(filename); err != nil {
			return 0, 0, err
		}
		return extractTaskCodebaseTar(filename, destination, false)
	case "tar.gz":
		if err := inspectTaskCodebaseTarGzip(filename); err != nil {
			return 0, 0, err
		}
		return extractTaskCodebaseTar(filename, destination, true)
	default:
		return 0, 0, errors.New("unsupported source archive format")
	}
}

func extractTaskCodebaseZip(filename, destination string) (int, int64, error) {
	f, err := os.Open(filename)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	archive, err := zip.NewReader(f, info.Size())
	if err != nil {
		return 0, 0, err
	}
	if err := ensureTaskCodebaseDirectories(destination, true); err != nil {
		return 0, 0, err
	}
	fileCount := 0
	var expandedSize int64
	for _, entry := range archive.File {
		isDir := entry.FileInfo().IsDir() || strings.HasSuffix(entry.Name, "/")
		rel, err := safeTaskCodebaseArchivePath(entry.Name, isDir)
		if err != nil {
			return 0, 0, err
		}
		target := filepath.Join(destination, filepath.FromSlash(rel))
		if isDir {
			if err := os.MkdirAll(target, 0o750); err != nil {
				return 0, 0, err
			}
			continue
		}
		if fileCount >= maxTaskCodebaseFiles {
			return 0, 0, errors.New("archive contains too many files")
		}
		if entry.UncompressedSize64 > uint64(maxTaskCodebaseExpandedSize-expandedSize) {
			return 0, 0, errors.New("archive expands beyond the extraction limit")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return 0, 0, err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
		if err != nil {
			return 0, 0, err
		}
		input, err := entry.Open()
		if err != nil {
			_ = out.Close()
			return 0, 0, err
		}
		expectedSize := int64(entry.UncompressedSize64)
		written, copyErr := io.Copy(out, &io.LimitedReader{R: input, N: expectedSize + 1})
		closeInputErr := input.Close()
		closeOutErr := out.Close()
		if copyErr != nil {
			return 0, 0, copyErr
		}
		if closeInputErr != nil {
			return 0, 0, closeInputErr
		}
		if closeOutErr != nil {
			return 0, 0, closeOutErr
		}
		if written != expectedSize {
			return 0, 0, errors.New("archive entry size does not match its header")
		}
		fileCount++
		expandedSize += written
	}
	return fileCount, expandedSize, nil
}

func extractTaskCodebaseTar(filename, destination string, compressed bool) (int, int64, error) {
	f, err := os.Open(filename)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	var source io.Reader = f
	var gz *gzip.Reader
	if compressed {
		gz, err = gzip.NewReader(f)
		if err != nil {
			return 0, 0, err
		}
		defer gz.Close()
		source = gz
	}
	if err := ensureTaskCodebaseDirectories(destination, true); err != nil {
		return 0, 0, err
	}
	reader := tar.NewReader(source)
	fileCount := 0
	var expandedSize int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			if gz != nil {
				if err := drainTaskCodebaseArchiveTail(gz, maxTaskCodebaseExpandedSize-expandedSize); err != nil {
					return 0, 0, err
				}
			}
			return fileCount, expandedSize, nil
		}
		if err != nil {
			return 0, 0, err
		}
		isDir := header.Typeflag == tar.TypeDir
		if !isDir && header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return 0, 0, errors.New("archive contains a link or special file")
		}
		rel, err := safeTaskCodebaseArchivePath(header.Name, isDir)
		if err != nil {
			return 0, 0, err
		}
		target := filepath.Join(destination, filepath.FromSlash(rel))
		if isDir {
			if err := os.MkdirAll(target, 0o750); err != nil {
				return 0, 0, err
			}
			continue
		}
		if fileCount >= maxTaskCodebaseFiles {
			return 0, 0, errors.New("archive contains too many files")
		}
		if header.Size < 0 || header.Size > maxTaskCodebaseExpandedSize-expandedSize {
			return 0, 0, errors.New("archive expands beyond the extraction limit")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return 0, 0, err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
		if err != nil {
			return 0, 0, err
		}
		written, copyErr := io.CopyN(out, reader, header.Size)
		closeErr := out.Close()
		if copyErr != nil {
			return 0, 0, copyErr
		}
		if closeErr != nil {
			return 0, 0, closeErr
		}
		if written != header.Size {
			return 0, 0, errors.New("archive entry size does not match its header")
		}
		fileCount++
		expandedSize += written
	}
}

func inspectTaskCodebaseZip(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	archive, err := zip.NewReader(f, info.Size())
	if err != nil {
		return err
	}
	if len(archive.File) > maxTaskCodebaseArchiveFiles {
		return errors.New("archive contains too many entries")
	}
	seen := make(map[string]bool, len(archive.File))
	var expanded int64
	for _, entry := range archive.File {
		isDir := entry.FileInfo().IsDir() || strings.HasSuffix(entry.Name, "/")
		rel, err := safeTaskCodebaseArchivePath(entry.Name, isDir)
		if err != nil {
			return err
		}
		mode := entry.Mode()
		if mode&os.ModeSymlink != 0 || (mode.Type() != 0 && !mode.IsDir()) {
			return errors.New("archive contains a link or special file")
		}
		key := strings.ToLower(rel)
		if previousDir, ok := seen[key]; ok {
			if !previousDir || !isDir {
				return errors.New("archive contains duplicate paths")
			}
			continue
		}
		seen[key] = isDir
		if entry.UncompressedSize64 > uint64(maxTaskCodebaseExpandedSize-expanded) {
			return errors.New("archive expands beyond the inspection limit")
		}
		expanded += int64(entry.UncompressedSize64)
	}
	return nil
}

func inspectTaskCodebaseTar(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return inspectTaskCodebaseTarReader(tar.NewReader(f), nil)
}

func inspectTaskCodebaseTarGzip(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	return inspectTaskCodebaseTarReader(tar.NewReader(gz), gz)
}

func inspectTaskCodebaseTarReader(tr *tar.Reader, tail io.Reader) error {
	seen := make(map[string]bool)
	var expanded int64
	for count := 0; ; count++ {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			if tail != nil {
				return drainTaskCodebaseArchiveTail(tail, maxTaskCodebaseExpandedSize-expanded)
			}
			return nil
		}
		if err != nil {
			return err
		}
		if count >= maxTaskCodebaseArchiveFiles {
			return errors.New("archive contains too many entries")
		}
		isDir := header.Typeflag == tar.TypeDir
		if !isDir && header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return errors.New("archive contains a link or special file")
		}
		rel, err := safeTaskCodebaseArchivePath(header.Name, isDir)
		if err != nil {
			return err
		}
		key := strings.ToLower(rel)
		if previousDir, ok := seen[key]; ok {
			if !previousDir || !isDir {
				return errors.New("archive contains duplicate paths")
			}
			continue
		}
		seen[key] = isDir
		if header.Size < 0 || header.Size > maxTaskCodebaseExpandedSize-expanded {
			return errors.New("archive expands beyond the inspection limit")
		}
		expanded += header.Size
		if !isDir && header.Size > 0 {
			if _, err := io.CopyN(io.Discard, tr, header.Size); err != nil {
				return err
			}
		}
	}
}

func drainTaskCodebaseArchiveTail(reader io.Reader, remaining int64) error {
	if remaining < 0 {
		return errors.New("archive expands beyond the inspection limit")
	}
	written, err := io.Copy(io.Discard, io.LimitReader(reader, remaining+1))
	if err != nil {
		return err
	}
	if written > remaining {
		return errors.New("archive expands beyond the inspection limit")
	}
	return nil
}

func safeTaskCodebaseArchivePath(raw string, isDir bool) (string, error) {
	if isDir {
		raw = strings.TrimSuffix(raw, "/")
		for strings.HasPrefix(raw, "./") {
			raw = strings.TrimPrefix(raw, "./")
		}
		if raw == "." || raw == "" {
			return "", nil
		}
	} else {
		for strings.HasPrefix(raw, "./") {
			raw = strings.TrimPrefix(raw, "./")
		}
	}
	return safeTaskCodebasePath(raw)
}
