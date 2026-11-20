package server

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

type codebaseTestFile struct {
	path string
	data []byte
}

func taskCodebaseFixture(t *testing.T) (*Server, *http.ServeMux, string) {
	t.Helper()
	base := t.TempDir()
	m := &Manager{dir: base, tasks: map[string]*Task{"313": {ID: "313", ProjectID: 1}}}
	s := &Server{m: m, engine: NewEngine(m)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/tasks/{id}/codebases", s.taskCodebasesList)
	mux.HandleFunc("POST /api/tasks/{id}/codebases", s.taskCodebasesUpload)
	mux.HandleFunc("POST /api/workspace/write", s.wsWrite)
	mux.HandleFunc("POST /api/workspace/mkdir", s.wsMkdir)
	mux.HandleFunc("DELETE /api/workspace/delete", s.wsDelete)
	mux.HandleFunc("POST /api/workspace/upload", s.wsUpload)
	return s, mux, base
}

func taskCodebasePost(t *testing.T, mux *http.ServeMux, taskID, kind string, files []codebaseTestFile, codebaseID ...string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	if err := form.WriteField("kind", kind); err != nil {
		t.Fatal(err)
	}
	if len(codebaseID) > 0 {
		if err := form.WriteField("codebase_id", codebaseID[0]); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range files {
		part, err := form.CreateFormFile("file", filepath.Base(file.path))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(file.data); err != nil {
			t.Fatal(err)
		}
		if err := form.WriteField("relative_path", file.path); err != nil {
			t.Fatal(err)
		}
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	req := newReqWithProject(http.MethodPost, "/api/tasks/"+taskID+"/codebases", &body)
	req.Header.Set(projectIDHeader, "1")
	req.Header.Set("Content-Type", form.FormDataContentType())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func readTaskCodebaseVersion(t *testing.T, body io.Reader) taskCodebaseVersion {
	t.Helper()
	var payload struct {
		Version taskCodebaseVersion `json:"version"`
	}
	if err := json.NewDecoder(body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	return payload.Version
}

func TestTaskCodebaseDirectoryUploadsCreateIndependentVersions(t *testing.T) {
	_, mux, base := taskCodebaseFixture(t)
	files := []codebaseTestFile{
		{path: "A Service/src/Main.java", data: []byte("class Main {}")},
		{path: "A Service/src/util/Helper.java", data: []byte("class Helper {}")},
	}
	firstResponse := taskCodebasePost(t, mux, "313", "directory", files)
	if firstResponse.Code != http.StatusCreated {
		t.Fatalf("upload status %d: %s", firstResponse.Code, firstResponse.Body.String())
	}
	first := readTaskCodebaseVersion(t, firstResponse.Body)
	if first.Kind != "directory" || first.Format != "directory" || first.Name != "A Service" || first.FileCount != 2 {
		t.Fatalf("unexpected directory version: %+v", first)
	}
	stored := filepath.Join(base, "tasks", "313", "codebases", first.ID, "contents", filepath.FromSlash(files[0].path))
	data, err := os.ReadFile(stored)
	if err != nil || string(data) != string(files[0].data) {
		t.Fatalf("uploaded relative path not preserved: data=%q err=%v", data, err)
	}

	files[0].data = []byte("class Main { int version = 2; }")
	secondResponse := taskCodebasePost(t, mux, "313", "directory", files)
	if secondResponse.Code != http.StatusCreated {
		t.Fatalf("second upload status %d: %s", secondResponse.Code, secondResponse.Body.String())
	}
	second := readTaskCodebaseVersion(t, secondResponse.Body)
	if second.ID == first.ID {
		t.Fatal("uploads must receive distinct version IDs")
	}
	data, err = os.ReadFile(stored)
	if err != nil || string(data) != "class Main {}" {
		t.Fatalf("new upload modified the earlier snapshot: data=%q err=%v", data, err)
	}

	listReq := newReqWithProject(http.MethodGet, "/api/tasks/313/codebases", nil)
	listReq.Header.Set(projectIDHeader, "1")
	listRec := httptest.NewRecorder()
	mux.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status %d: %s", listRec.Code, listRec.Body.String())
	}
	var listed struct {
		Versions []taskCodebaseVersion `json:"versions"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Versions) != 2 {
		t.Fatalf("want both snapshots in version list, got %+v", listed.Versions)
	}
}

func TestTaskCodebaseUploadCanContinueNamedCodebaseAcrossDifferentArtifactNames(t *testing.T) {
	_, mux, _ := taskCodebaseFixture(t)
	firstResponse := taskCodebasePost(t, mux, "313", "directory", []codebaseTestFile{{
		path: "checkout-a/src/main/App.java", data: []byte("class App {}"),
	}})
	if firstResponse.Code != http.StatusCreated {
		t.Fatalf("first upload status %d: %s", firstResponse.Code, firstResponse.Body.String())
	}
	first := readTaskCodebaseVersion(t, firstResponse.Body)
	secondResponse := taskCodebasePost(t, mux, "313", "directory", []codebaseTestFile{{
		path: "checkout-b/src/main/App.java", data: []byte("class App { int v = 2; }"),
	}}, first.CodebaseID)
	if secondResponse.Code != http.StatusCreated {
		t.Fatalf("second upload status %d: %s", secondResponse.Code, secondResponse.Body.String())
	}
	second := readTaskCodebaseVersion(t, secondResponse.Body)
	if first.ID == second.ID || first.CodebaseID != second.CodebaseID {
		t.Fatalf("uploads should create distinct versions under the selected codebase identity: first=%+v second=%+v", first, second)
	}
}

func makeCodebaseZip(t *testing.T, entries map[string]struct {
	data []byte
	mode os.FileMode
}) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for name, item := range entries {
		header := &zip.FileHeader{Name: name}
		header.SetMode(item.mode)
		file, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(item.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestTaskCodebaseArtifactInspectionRejectsUnsafeArchives(t *testing.T) {
	_, mux, base := taskCodebaseFixture(t)
	valid := makeCodebaseZip(t, map[string]struct {
		data []byte
		mode os.FileMode
	}{"WEB-INF/classes/App.class": {data: []byte{0xca, 0xfe, 0xba, 0xbe}, mode: 0o644}})
	response := taskCodebasePost(t, mux, "313", "artifact", []codebaseTestFile{{path: "app.war", data: valid}})
	if response.Code != http.StatusCreated {
		t.Fatalf("valid WAR rejected: %d %s", response.Code, response.Body.String())
	}
	version := readTaskCodebaseVersion(t, response.Body)
	if version.Kind != "artifact" || version.Format != "war" || version.Name != "app.war" {
		t.Fatalf("artifact declaration was not preserved: %+v", version)
	}

	unsafe := makeCodebaseZip(t, map[string]struct {
		data []byte
		mode os.FileMode
	}{"../escape.java": {data: []byte("bad"), mode: 0o644}})
	response = taskCodebasePost(t, mux, "313", "artifact", []codebaseTestFile{{path: "bad.zip", data: unsafe}})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("traversal archive status %d: %s", response.Code, response.Body.String())
	}

	linked := makeCodebaseZip(t, map[string]struct {
		data []byte
		mode os.FileMode
	}{"link": {data: []byte("../outside"), mode: os.ModeSymlink | 0o777}})
	response = taskCodebasePost(t, mux, "313", "artifact", []codebaseTestFile{{path: "linked.jar", data: linked}})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("symlink archive status %d: %s", response.Code, response.Body.String())
	}

	versions, err := os.ReadDir(filepath.Join(base, "tasks", "313", "codebases"))
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 {
		t.Fatalf("rejected archives must not leave versions behind: %d", len(versions))
	}
}

func makeCodebaseTar(t *testing.T, name string, typeflag byte, data []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	header := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: typeflag}
	if typeflag == tar.TypeSymlink {
		header.Linkname = "../outside"
		header.Size = 0
	}
	if err := writer.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	if len(data) > 0 {
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func makeCodebaseTarGzip(t *testing.T, files []codebaseTestFile) []byte {
	t.Helper()
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	writer := tar.NewWriter(gz)
	if err := writer.WriteHeader(&tar.Header{Name: "./", Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		header := &tar.Header{Name: "./" + file.path, Mode: 0o644, Size: int64(len(file.data)), Typeflag: tar.TypeReg}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(file.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestTaskCodebaseSourceArchivesAreExtractedForDiscovery(t *testing.T) {
	s, mux, base := taskCodebaseFixture(t)
	files := []codebaseTestFile{
		{path: "orderdesk/pom.xml", data: []byte("<project><artifactId>orderdesk</artifactId></project>")},
		{path: "orderdesk/A Service/src/main/App.java", data: []byte("class AService {}")},
		{path: "orderdesk/team/B Service/src/worker.py", data: []byte("print('fixture')")},
		{path: "orderdesk/build/output.jar", data: []byte("archive placeholder")},
		{path: "orderdesk/misc/main.c", data: []byte("int main(void) { return 0; }")},
		{path: "orderdesk/misc/src", data: []byte("a file named src is not a directory")},
	}
	zipEntries := map[string]struct {
		data []byte
		mode os.FileMode
	}{}
	for _, file := range files {
		zipEntries[file.path] = struct {
			data []byte
			mode os.FileMode
		}{data: file.data, mode: 0o644}
	}
	archives := []struct {
		name string
		data []byte
	}{
		{name: "source.zip", data: makeCodebaseZip(t, zipEntries)},
		{name: "source.tar.gz", data: makeCodebaseTarGzip(t, files)},
	}
	for _, archive := range archives {
		response := taskCodebasePost(t, mux, "313", "source_archive", []codebaseTestFile{{path: archive.name, data: archive.data}})
		if response.Code != http.StatusCreated {
			t.Fatalf("%s upload status %d: %s", archive.name, response.Code, response.Body.String())
		}
		version := readTaskCodebaseVersion(t, response.Body)
		if version.Kind != "directory" || version.Format != "directory" || version.Name != "source" ||
			version.FileCount != len(files) || version.TotalSize <= 0 {
			t.Fatalf("%s did not become an extracted source snapshot: %+v", archive.name, version)
		}
		contentRoot := filepath.Join(base, "tasks", "313", "codebases", version.ID, "contents", version.Name)
		for _, file := range files {
			stored := filepath.Join(contentRoot, filepath.FromSlash(file.path))
			data, err := os.ReadFile(stored)
			if err != nil || !bytes.Equal(data, file.data) {
				t.Fatalf("%s extracted %s as %q, err=%v", archive.name, file.path, data, err)
			}
		}
		if _, err := os.Stat(filepath.Join(base, "tasks", "313", "codebases", version.ID, "contents", archive.name)); !os.IsNotExist(err) {
			t.Fatalf("original %s was left as the codebase input instead of extracting it: err=%v", archive.name, err)
		}
		candidates, note, err := s.discoverCodebaseServices(t.Context(), 313, version)
		if err != nil {
			t.Fatalf("scan extracted %s: %v", archive.name, err)
		}
		if len(candidates) != 2 || note != "" {
			t.Fatalf("%s candidates=%+v note=%q", archive.name, candidates, note)
		}
		wantPaths := []string{"orderdesk/A Service", "orderdesk/team/B Service"}
		wantNames := []string{"A Service", "B Service"}
		wantLanguages := [][]string{{"java"}, {"python"}}
		for i, item := range candidates {
			if item.RelativePath != wantPaths[i] || item.Name != wantNames[i] ||
				!reflect.DeepEqual(item.Languages, wantLanguages[i]) ||
				item.Decision != "service" || item.Source != "discovery" || !item.SourceDirectory {
				t.Fatalf("%s candidate %d = %+v", archive.name, i, item)
			}
		}
	}
	unsafe := makeCodebaseZip(t, map[string]struct {
		data []byte
		mode os.FileMode
	}{"../escape.java": {data: []byte("unsafe"), mode: 0o644}})
	response := taskCodebasePost(t, mux, "313", "source_archive", []codebaseTestFile{{path: "unsafe.zip", data: unsafe}})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("source archive traversal accepted: %d %s", response.Code, response.Body.String())
	}
	versions, err := os.ReadDir(filepath.Join(base, "tasks", "313", "codebases"))
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != len(archives) {
		t.Fatalf("rejected source archive left a partial snapshot: got %d versions", len(versions))
	}
}

func TestTaskCodebaseSourceArchiveDecodesGBKEntryNames(t *testing.T) {
	_, mux, base := taskCodebaseFixture(t)
	gbkName, err := simplifiedchinese.GBK.NewEncoder().String("config/源码归档链接.txt")
	if err != nil {
		t.Fatal(err)
	}
	zipData := makeCodebaseZip(t, map[string]struct {
		data []byte
		mode os.FileMode
	}{gbkName: {data: []byte("gbk"), mode: 0o644}})
	response := taskCodebasePost(t, mux, "313", "source_archive", []codebaseTestFile{{path: "source.zip", data: zipData}})
	if response.Code != http.StatusCreated {
		t.Fatalf("GBK-named source archive rejected: %d %s", response.Code, response.Body.String())
	}
	version := readTaskCodebaseVersion(t, response.Body)
	stored := filepath.Join(base, "tasks", "313", "codebases", version.ID, "contents", version.Name,
		"config", "源码归档链接.txt")
	if data, err := os.ReadFile(stored); err != nil || string(data) != "gbk" {
		t.Fatalf("GBK entry was not decoded to UTF-8: data=%q err=%v", data, err)
	}

	corrupt := makeCodebaseZip(t, map[string]struct {
		data []byte
		mode os.FileMode
	}{"bad\xff.txt": {data: []byte("bad"), mode: 0o644}})
	response = taskCodebasePost(t, mux, "313", "source_archive", []codebaseTestFile{{path: "corrupt.zip", data: corrupt}})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("corrupt entry name accepted: %d %s", response.Code, response.Body.String())
	}
}

func TestTaskCodebaseTarInspectionRejectsTraversalAndLinks(t *testing.T) {
	_, mux, _ := taskCodebaseFixture(t)
	valid := makeCodebaseTar(t, "project/src/Main.java", tar.TypeReg, []byte("class Main {}"))
	response := taskCodebasePost(t, mux, "313", "artifact", []codebaseTestFile{{path: "source.tar", data: valid}})
	if response.Code != http.StatusCreated {
		t.Fatalf("valid TAR rejected: %d %s", response.Code, response.Body.String())
	}
	version := readTaskCodebaseVersion(t, response.Body)
	if version.Kind != "artifact" || version.Format != "tar" {
		t.Fatalf("TAR declaration was not preserved: %+v", version)
	}

	for _, archive := range [][]byte{
		makeCodebaseTar(t, "../escape.java", tar.TypeReg, []byte("bad")),
		makeCodebaseTar(t, "project/link", tar.TypeSymlink, nil),
	} {
		response = taskCodebasePost(t, mux, "313", "artifact", []codebaseTestFile{{path: "unsafe.tar", data: archive}})
		if response.Code != http.StatusBadRequest {
			t.Fatalf("unsafe TAR accepted: %d %s", response.Code, response.Body.String())
		}
	}
}

func TestTaskCodebaseUploadsRejectBadIDsPathsAndInvalidClasses(t *testing.T) {
	_, mux, _ := taskCodebaseFixture(t)
	for _, id := range []string{"0", "0313", "999"} {
		response := taskCodebasePost(t, mux, id, "directory", []codebaseTestFile{{path: "project/Main.java", data: []byte("class Main {}")}})
		if response.Code != http.StatusNotFound {
			t.Errorf("task ID %q returned status %d", id, response.Code)
		}
	}
	for _, unsafePath := range []string{"../escape.java", "project/../../escape.java", `project\\Main.java`, "C:/Main.java", "project/./Main.java", "project\x00/Main.java"} {
		response := taskCodebasePost(t, mux, "313", "directory", []codebaseTestFile{{path: unsafePath, data: []byte("x")}})
		if response.Code != http.StatusBadRequest {
			t.Errorf("path %q returned status %d: %s", unsafePath, response.Code, response.Body.String())
		}
	}
	response := taskCodebasePost(t, mux, "313", "artifact", []codebaseTestFile{{path: "broken.class", data: []byte("nope")}})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid class accepted: %d %s", response.Code, response.Body.String())
	}
	response = taskCodebasePost(t, mux, "313", "directory", []codebaseTestFile{
		{path: "project/Main.java", data: []byte("one")},
		{path: "project/Main.java", data: []byte("two")},
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("duplicate path accepted: %d %s", response.Code, response.Body.String())
	}
}

func TestTaskCodebaseSnapshotsAreProtectedFromWorkspaceMutations(t *testing.T) {
	_, mux, base := taskCodebaseFixture(t)
	response := taskCodebasePost(t, mux, "313", "directory", []codebaseTestFile{{path: "project/src/Main.java", data: []byte("class Main {}")}})
	if response.Code != http.StatusCreated {
		t.Fatalf("upload status %d: %s", response.Code, response.Body.String())
	}
	version := readTaskCodebaseVersion(t, response.Body)
	filePath := filepath.ToSlash(filepath.Join("tasks", "313", "codebases", version.ID, "contents", "project", "src", "Main.java"))

	writeBody, _ := json.Marshal(map[string]string{"path": filePath, "content": "changed"})
	writeRec := httptest.NewRecorder()
	mux.ServeHTTP(writeRec, newReqWithProject(http.MethodPost, "/api/workspace/write", bytes.NewReader(writeBody)))
	if writeRec.Code != http.StatusForbidden {
		t.Fatalf("workspace write status %d: %s", writeRec.Code, writeRec.Body.String())
	}

	mkdirBody, _ := json.Marshal(map[string]string{"path": filepath.ToSlash(filepath.Join("tasks", "313", "codebases", version.ID, "contents", "new"))})
	mkdirRec := httptest.NewRecorder()
	mux.ServeHTTP(mkdirRec, newReqWithProject(http.MethodPost, "/api/workspace/mkdir", bytes.NewReader(mkdirBody)))
	if mkdirRec.Code != http.StatusForbidden {
		t.Fatalf("workspace mkdir status %d: %s", mkdirRec.Code, mkdirRec.Body.String())
	}

	for _, target := range []string{"tasks/313/codebases", "tasks/313", "tasks"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, newReqWithProject(http.MethodDelete, "/api/workspace/delete?path="+url.QueryEscape(target), nil))
		if rec.Code != http.StatusForbidden {
			t.Errorf("delete %q status %d: %s", target, rec.Code, rec.Body.String())
		}
	}

	var uploadBody bytes.Buffer
	form := multipart.NewWriter(&uploadBody)
	part, err := form.CreateFormFile("file", "replacement.java")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("changed")); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	uploadPath := filepath.ToSlash(filepath.Join("tasks", "313", "codebases", version.ID, "contents", "project", "src"))
	uploadReq := newReqWithProject(http.MethodPost, "/api/workspace/upload?path="+url.QueryEscape(uploadPath), &uploadBody)
	uploadReq.Header.Set("Content-Type", form.FormDataContentType())
	uploadRec := httptest.NewRecorder()
	mux.ServeHTTP(uploadRec, uploadReq)
	if uploadRec.Code != http.StatusForbidden {
		t.Fatalf("workspace upload status %d: %s", uploadRec.Code, uploadRec.Body.String())
	}

	stored := filepath.Join(base, filepath.FromSlash(filePath))
	data, err := os.ReadFile(stored)
	if err != nil || string(data) != "class Main {}" {
		t.Fatalf("workspace mutation changed snapshot: %q, %v", data, err)
	}
}
