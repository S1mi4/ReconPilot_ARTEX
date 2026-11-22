package server

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	pgdb "github.com/Autumn-27/artex/db"
)

const (
	maxProfileInspectFiles = 20000
	maxProfileConfigBytes  = int64(256 << 10)
	maxProfileSourceBytes  = int64(512 << 10)
	maxProfileSnippetRunes = 180
)

type extractedModule struct {
	Name               string
	RelPath            string
	EntityType         string // service | shared_library | module
	Languages          []string
	Deployability      string
	Signals            []string
	EvidencePath       string
	SourceCount        int
	NeedsDeployUnknown bool
}

type extractedEntity struct {
	EntityType string
	Name       string
	CodebaseID string
	VersionID  string
	Attributes map[string]any
	Gap        bool
	GapReason  string
}

type extractedClaim struct {
	Subject            string
	Relation           string
	ObjectValue        string
	SourceType         string
	EvidenceKind       pgdb.EvidenceRefKind
	EvidenceRef        string
	EvidencePayload    map[string]any
	ValidCodeVersion   string
	Environment        string
	ValidConfig        string
	ConfirmationStatus string
	ConflictNote       string
}

type deploymentHint struct {
	ServiceName   string
	BuildContext  string
	Image         string
	ContainerPort string
	HostPort      string
	UpstreamName  string
	ProxyPass     string
	Location      string
	ConfigPath    string
	Line          int
}

type codebaseExtractionResult struct {
	Modules     []extractedModule
	Entities    []extractedEntity
	Claims      []extractedClaim
	DeployHints []deploymentHint
	Languages   []string
}

type codebaseFileEntry struct {
	Rel      string
	DiskPath string
	Read     func(int64) ([]byte, bool, error)
}

func extractCodebaseProfile(versionDir string, version taskCodebaseVersion) codebaseExtractionResult {
	var res codebaseExtractionResult
	contentsDir := filepath.Join(versionDir, "contents")
	info, err := os.Lstat(contentsDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		res.Entities = append(res.Entities, extractedEntity{
			EntityType: "module",
			Name:       version.Name,
			CodebaseID: version.CodebaseID,
			VersionID:  version.ID,
			Gap:        true,
			GapReason:  "代码库内容目录缺失或不可读取",
		})
		return res
	}

	files, walkGaps := collectProfileFiles(contentsDir, version)
	res.Entities = append(res.Entities, walkGaps...)

	commonPrefix := detectSingleRootPrefix(files)
	modules := discoverProfileModules(files, commonPrefix, version)
	res.Modules = modules

	langSet := map[string]bool{}
	for _, m := range modules {
		for _, l := range m.Languages {
			if l != "" && l != "unknown" {
				langSet[l] = true
			}
		}
	}

	for _, f := range files {
		logicalRel := trimPrefixPath(f.Rel, commonPrefix)
		mod := matchModuleForPath(modules, logicalRel, version.Name)
		modSubject := moduleSubject(mod)

		if isProfileConfigOrDeployFile(logicalRel) {
			data, oversized, rerr := f.Read(maxProfileConfigBytes)
			if rerr != nil || oversized || !utf8.Valid(data) {
				reason := fmt.Sprintf("配置文件 %s 不可读取或超出体积上限", f.Rel)
				if rerr != nil {
					reason = fmt.Sprintf("配置文件 %s 读取失败: %v", f.Rel, rerr)
				}
				res.Entities = append(res.Entities, extractedEntity{
					EntityType: "config",
					Name:       f.Rel,
					CodebaseID: version.CodebaseID,
					VersionID:  version.ID,
					Gap:        true,
					GapReason:  reason,
				})
				continue
			}
			extractConfigFileFacts(&res, f.Rel, logicalRel, modSubject, string(data), version)
			continue
		}

		lang := detectSourceLanguage(logicalRel)
		if lang == "" {
			continue
		}
		langSet[lang] = true
		data, oversized, rerr := f.Read(maxProfileSourceBytes)
		if rerr != nil || oversized || !isValidTextCodeContent(logicalRel, data) {
			reason := fmt.Sprintf("源码文件 %s 不可读取或非有效文本源码", f.Rel)
			if rerr != nil {
				reason = fmt.Sprintf("源码文件 %s 读取失败: %v", f.Rel, rerr)
			}
			res.Entities = append(res.Entities, extractedEntity{
				EntityType: "module",
				Name:       f.Rel,
				CodebaseID: version.CodebaseID,
				VersionID:  version.ID,
				Gap:        true,
				GapReason:  reason,
			})
			continue
		}

		switch lang {
		case "java":
			extractJavaSourceFacts(&res, f.Rel, modSubject, string(data), version)
		case "python":
			extractPythonSourceFacts(&res, f.Rel, modSubject, string(data), version)
		case "c":
			extractCSourceFacts(&res, f.Rel, modSubject, string(data), version)
		}
	}

	for l := range langSet {
		res.Languages = append(res.Languages, l)
	}
	sort.Strings(res.Languages)
	return res
}

func collectProfileFiles(contentsDir string, version taskCodebaseVersion) ([]codebaseFileEntry, []extractedEntity) {
	var files []codebaseFileEntry
	var gaps []extractedEntity
	visited := 0

	err := filepath.WalkDir(contentsDir, func(p string, d fs.DirEntry, wErr error) error {
		if wErr != nil {
			gaps = append(gaps, extractedEntity{
				EntityType: "module", Name: p, CodebaseID: version.CodebaseID, VersionID: version.ID,
				Gap: true, GapReason: fmt.Sprintf("遍历路径失败: %v", wErr),
			})
			return nil
		}
		if p == contentsDir {
			return nil
		}
		relFS, err := filepath.Rel(contentsDir, p)
		if err != nil {
			gaps = append(gaps, extractedEntity{
				EntityType: "module", Name: p, CodebaseID: version.CodebaseID, VersionID: version.ID,
				Gap: true, GapReason: fmt.Sprintf("相对路径解析失败: %v", err),
			})
			return nil
		}
		rel := filepath.ToSlash(relFS)
		lInfo, err := os.Lstat(p)
		if err != nil {
			gaps = append(gaps, extractedEntity{
				EntityType: "module", Name: rel, CodebaseID: version.CodebaseID, VersionID: version.ID,
				Gap: true, GapReason: fmt.Sprintf("读取文件状态失败: %v", err),
			})
			return nil
		}
		if lInfo.Mode()&os.ModeSymlink != 0 {
			gaps = append(gaps, extractedEntity{
				EntityType: "module", Name: rel, CodebaseID: version.CodebaseID, VersionID: version.ID,
				Gap: true, GapReason: "符号链接未纳入自动读取，形成清单缺口",
			})
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if taskCodeAuditMixedSharedPrune(".", rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if !lInfo.Mode().IsRegular() {
			return nil
		}
		visited++
		if visited > maxProfileInspectFiles {
			return nil
		}

		lower := strings.ToLower(rel)
		if archFmt, ok := detectMaterialArchiveFormat(lower); ok && (archFmt == "zip" || archFmt == "tar" || archFmt == "tar.gz") {
			archFiles, archGaps := collectArchiveProfileFiles(p, rel, archFmt, version)
			files = append(files, archFiles...)
			gaps = append(gaps, archGaps...)
			return nil
		}
		diskPath := p
		files = append(files, codebaseFileEntry{
			Rel:      rel,
			DiskPath: diskPath,
			Read: func(limit int64) ([]byte, bool, error) {
				return readBoundedRegularFile(diskPath, limit)
			},
		})
		return nil
	})
	if err != nil {
		gaps = append(gaps, extractedEntity{
			EntityType: "module", Name: version.Name, CodebaseID: version.CodebaseID, VersionID: version.ID,
			Gap: true, GapReason: fmt.Sprintf("遍历代码库失败: %v", err),
		})
	}
	return files, gaps
}

func collectArchiveProfileFiles(archivePath, archiveRel, format string, version taskCodebaseVersion) ([]codebaseFileEntry, []extractedEntity) {
	var files []codebaseFileEntry
	var gaps []extractedEntity

	switch format {
	case "zip":
		zr, err := zip.OpenReader(archivePath)
		if err != nil {
			gaps = append(gaps, extractedEntity{
				EntityType: "module", Name: archiveRel, CodebaseID: version.CodebaseID, VersionID: version.ID,
				Gap: true, GapReason: fmt.Sprintf("ZIP 归档不可读取: %v", err),
			})
			return files, gaps
		}
		defer zr.Close()
		for i, zf := range zr.File {
			if i >= maxProfileInspectFiles {
				break
			}
			if zf.FileInfo().IsDir() {
				continue
			}
			cleanName, perr := safeTaskCodebaseArchivePath(zf.Name, false)
			if perr != nil {
				gaps = append(gaps, extractedEntity{
					EntityType: "module", Name: path.Join(archiveRel, zf.Name), CodebaseID: version.CodebaseID, VersionID: version.ID,
					Gap: true, GapReason: "归档包含非法路径条目",
				})
				continue
			}
			if taskCodeAuditMixedSharedPrune(".", cleanName) {
				continue
			}
			if !isProfileInterestingFile(cleanName) {
				continue
			}
			if zf.UncompressedSize64 > uint64(maxProfileSourceBytes) {
				gaps = append(gaps, extractedEntity{
					EntityType: "module", Name: path.Join(archiveRel, cleanName), CodebaseID: version.CodebaseID, VersionID: version.ID,
					Gap: true, GapReason: "归档内文件超出提取体积上限",
				})
				continue
			}
			rc, oerr := zf.Open()
			if oerr != nil {
				gaps = append(gaps, extractedEntity{
					EntityType: "module", Name: path.Join(archiveRel, cleanName), CodebaseID: version.CodebaseID, VersionID: version.ID,
					Gap: true, GapReason: fmt.Sprintf("读取归档条目失败: %v", oerr),
				})
				continue
			}
			data, rerr := io.ReadAll(io.LimitReader(rc, maxProfileSourceBytes+1))
			_ = rc.Close()
			if rerr != nil || int64(len(data)) > maxProfileSourceBytes {
				gaps = append(gaps, extractedEntity{
					EntityType: "module", Name: path.Join(archiveRel, cleanName), CodebaseID: version.CodebaseID, VersionID: version.ID,
					Gap: true, GapReason: "读取归档条目内容失败或超限",
				})
				continue
			}
			captured := data
			files = append(files, codebaseFileEntry{
				Rel: path.Join(archiveRel, cleanName),
				Read: func(limit int64) ([]byte, bool, error) {
					if int64(len(captured)) > limit {
						return nil, true, nil
					}
					return captured, false, nil
				},
			})
		}
	case "tar", "tar.gz":
		f, err := os.Open(archivePath)
		if err != nil {
			gaps = append(gaps, extractedEntity{
				EntityType: "module", Name: archiveRel, CodebaseID: version.CodebaseID, VersionID: version.ID,
				Gap: true, GapReason: fmt.Sprintf("TAR 归档不可读取: %v", err),
			})
			return files, gaps
		}
		defer f.Close()
		var tr *tar.Reader
		if format == "tar.gz" {
			gz, gerr := gzip.NewReader(f)
			if gerr != nil {
				gaps = append(gaps, extractedEntity{
					EntityType: "module", Name: archiveRel, CodebaseID: version.CodebaseID, VersionID: version.ID,
					Gap: true, GapReason: fmt.Sprintf("GZIP 解压失败: %v", gerr),
				})
				return files, gaps
			}
			defer gz.Close()
			tr = tar.NewReader(gz)
		} else {
			tr = tar.NewReader(f)
		}
		for count := 0; count < maxProfileInspectFiles; count++ {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				gaps = append(gaps, extractedEntity{
					EntityType: "module", Name: archiveRel, CodebaseID: version.CodebaseID, VersionID: version.ID,
					Gap: true, GapReason: fmt.Sprintf("TAR 归档解析失败: %v", err),
				})
				break
			}
			if hdr.Typeflag == tar.TypeDir {
				continue
			}
			if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
				gaps = append(gaps, extractedEntity{
					EntityType: "module", Name: path.Join(archiveRel, hdr.Name), CodebaseID: version.CodebaseID, VersionID: version.ID,
					Gap: true, GapReason: "归档包含链接或特殊文件",
				})
				continue
			}
			cleanName, perr := safeTaskCodebaseArchivePath(hdr.Name, false)
			if perr != nil || taskCodeAuditMixedSharedPrune(".", cleanName) || !isProfileInterestingFile(cleanName) {
				continue
			}
			if hdr.Size > maxProfileSourceBytes {
				gaps = append(gaps, extractedEntity{
					EntityType: "module", Name: path.Join(archiveRel, cleanName), CodebaseID: version.CodebaseID, VersionID: version.ID,
					Gap: true, GapReason: "归档内文件超出提取体积上限",
				})
				continue
			}
			data, rerr := io.ReadAll(io.LimitReader(tr, maxProfileSourceBytes+1))
			if rerr != nil || int64(len(data)) > maxProfileSourceBytes {
				gaps = append(gaps, extractedEntity{
					EntityType: "module", Name: path.Join(archiveRel, cleanName), CodebaseID: version.CodebaseID, VersionID: version.ID,
					Gap: true, GapReason: "读取 TAR 条目内容失败",
				})
				continue
			}
			captured := data
			files = append(files, codebaseFileEntry{
				Rel: path.Join(archiveRel, cleanName),
				Read: func(limit int64) ([]byte, bool, error) {
					if int64(len(captured)) > limit {
						return nil, true, nil
					}
					return captured, false, nil
				},
			})
		}
	}
	return files, gaps
}

func isProfileInterestingFile(rel string) bool {
	return isProfileConfigOrDeployFile(rel) || detectSourceLanguage(rel) != ""
}

func detectSingleRootPrefix(files []codebaseFileEntry) string {
	root := ""
	for _, f := range files {
		parts := strings.SplitN(f.Rel, "/", 2)
		if len(parts) < 2 {
			return ""
		}
		if root == "" {
			root = parts[0]
		} else if root != parts[0] {
			return ""
		}
	}
	if root == "" {
		return ""
	}
	return root + "/"
}

func trimPrefixPath(rel, prefix string) string {
	if prefix != "" && strings.HasPrefix(rel, prefix) {
		return strings.TrimPrefix(rel, prefix)
	}
	return rel
}

func detectSourceLanguage(rel string) string {
	for _, adapter := range taskCodeAuditLanguages() {
		kind, ok := adapter.ClassifyFile(".", rel)
		if ok && (kind == "source" || kind == "java" || kind == "template") {
			return adapter.Language()
		}
	}
	return ""
}

func isBuildRootManifest(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	switch base {
	case "pom.xml", "build.gradle", "build.gradle.kts", "pyproject.toml", "setup.py", "setup.cfg",
		"cmakelists.txt", "meson.build", "makefile", "gnumakefile":
		return true
	default:
		return strings.HasPrefix(base, "requirements") && (strings.HasSuffix(base, ".txt") || strings.HasSuffix(base, ".in"))
	}
}

func discoverProfileModules(files []codebaseFileEntry, commonPrefix string, version taskCodebaseVersion) []extractedModule {
	buildDirs := map[string][]string{}
	buildBodies := map[string]string{}
	for _, f := range files {
		logical := trimPrefixPath(f.Rel, commonPrefix)
		if isBuildRootManifest(logical) {
			dir := path.Dir(logical)
			buildDirs[dir] = append(buildDirs[dir], f.Rel)
			if data, oversized, err := f.Read(maxProfileConfigBytes); err == nil && !oversized && utf8.Valid(data) {
				buildBodies[dir] += "\n" + string(data)
			}
		}
	}

	// Drop root "." aggregator if it has child build modules and declares <packaging>pom</packaging> or no direct source.
	if _, hasRoot := buildDirs["."]; hasRoot && len(buildDirs) > 1 {
		rootBody := strings.ToLower(buildBodies["."])
		hasDirectCode := false
		for _, f := range files {
			logical := trimPrefixPath(f.Rel, commonPrefix)
			if detectSourceLanguage(logical) != "" {
				inChild := false
				for dir := range buildDirs {
					if dir != "." && strings.HasPrefix(logical, dir+"/") {
						inChild = true
						break
					}
				}
				if !inChild {
					hasDirectCode = true
					break
				}
			}
		}
		if strings.Contains(rootBody, "<packaging>pom</packaging>") || !hasDirectCode {
			delete(buildDirs, ".")
		}
	}

	if len(buildDirs) == 0 {
		// Fallback: create a single module representing the uploaded codebase.
		langSet := map[string]bool{}
		srcCount := 0
		for _, f := range files {
			logical := trimPrefixPath(f.Rel, commonPrefix)
			if lang := detectSourceLanguage(logical); lang != "" {
				langSet[lang] = true
				srcCount++
			}
		}
		var langs []string
		for l := range langSet {
			langs = append(langs, l)
		}
		sort.Strings(langs)
		if len(langs) == 0 {
			return nil
		}
		etype := "shared_library"
		deploy := "auditable_library"
		return []extractedModule{{
			Name: version.Name, RelPath: ".", EntityType: etype, Languages: langs,
			Deployability: deploy, Signals: []string{"no_build_manifest_source_tree"},
			EvidencePath: version.Name, SourceCount: srcCount, NeedsDeployUnknown: true,
		}}
	}

	dirs := make([]string, 0, len(buildDirs))
	for d := range buildDirs {
		dirs = append(dirs, d)
	}
	// Sort longest path first so each file is attributed to its tightest enclosing module.
	sort.Slice(dirs, func(i, j int) bool {
		if len(dirs[i]) != len(dirs[j]) {
			return len(dirs[i]) > len(dirs[j])
		}
		return dirs[i] < dirs[j]
	})

	type modAgg struct {
		dir         string
		langs       map[string]bool
		sources     int
		webSignals  bool
		libSignals  bool
		signals     []string
		libTarget   string
		execTarget  string
		dockerfile  bool
		buildFiles  []string
		sourceTexts []string
	}
	aggs := map[string]*modAgg{}
	for _, d := range dirs {
		aggs[d] = &modAgg{dir: d, langs: map[string]bool{}, buildFiles: buildDirs[d]}
	}

	for _, f := range files {
		logical := trimPrefixPath(f.Rel, commonPrefix)
		owner := ""
		for _, d := range dirs {
			if d == "." || logical == d || strings.HasPrefix(logical, d+"/") {
				owner = d
				break
			}
		}
		if owner == "" {
			continue
		}
		agg := aggs[owner]
		base := strings.ToLower(path.Base(logical))
		if strings.HasPrefix(base, "dockerfile") {
			agg.dockerfile = true
			agg.signals = append(agg.signals, "dockerfile")
		}
		if lang := detectSourceLanguage(logical); lang != "" {
			agg.langs[lang] = true
			agg.sources++
			if data, oversized, err := f.Read(maxProfileSourceBytes); err == nil && !oversized {
				body := string(data)
				if hasWebOrServerEntrySignal(lang, body) {
					agg.webSignals = true
				}
			}
		}
	}

	var out []extractedModule
	sort.Strings(dirs)
	for _, d := range dirs {
		agg := aggs[d]
		body := buildBodies[d]
		lowerBody := strings.ToLower(body)
		for _, m := range cAuditCMakeTargetPattern.FindAllStringSubmatch(body, 16) {
			if strings.EqualFold(m[1], "library") {
				agg.libTarget = strings.TrimSpace(m[2])
				agg.libSignals = true
				agg.signals = append(agg.signals, "cmake_add_library:"+agg.libTarget)
			} else {
				agg.execTarget = strings.TrimSpace(m[2])
				agg.signals = append(agg.signals, "cmake_add_executable:"+agg.execTarget)
			}
		}
		for _, m := range cAuditMesonTargetPattern.FindAllStringSubmatch(body, 16) {
			if strings.Contains(strings.ToLower(m[1]), "library") {
				agg.libTarget = strings.TrimSpace(m[2])
				agg.libSignals = true
				agg.signals = append(agg.signals, "meson_library:"+agg.libTarget)
			} else {
				agg.execTarget = strings.TrimSpace(m[2])
				agg.signals = append(agg.signals, "meson_executable:"+agg.execTarget)
			}
		}
		if strings.Contains(lowerBody, "spring-boot-maven-plugin") ||
			strings.Contains(lowerBody, "org.springframework.boot") ||
			strings.Contains(lowerBody, "<packaging>war</packaging>") ||
			strings.Contains(lowerBody, "application-plugin") {
			agg.webSignals = true
			agg.signals = append(agg.signals, "java_service_build_plugin")
		}
		if strings.Contains(lowerBody, "fastapi") || strings.Contains(lowerBody, "flask") ||
			strings.Contains(lowerBody, "django") || strings.Contains(lowerBody, "uvicorn") ||
			strings.Contains(lowerBody, "gunicorn") || strings.Contains(lowerBody, "aiohttp") ||
			strings.Contains(lowerBody, "tornado") {
			agg.webSignals = true
			agg.signals = append(agg.signals, "python_web_framework_dep")
		}
		if strings.Contains(lowerBody, "<packaging>jar</packaging>") && !agg.webSignals {
			agg.libSignals = true
			agg.signals = append(agg.signals, "maven_jar_without_boot")
		}

		name := path.Base(d)
		if d == "." {
			name = version.Name
		}
		lowerName := strings.ToLower(name)
		if strings.HasPrefix(lowerName, "common") || strings.HasPrefix(lowerName, "shared") ||
			strings.HasPrefix(lowerName, "lib") || strings.HasSuffix(lowerName, "-sdk") ||
			strings.HasSuffix(lowerName, "-api") {
			if !agg.webSignals {
				agg.libSignals = true
				agg.signals = append(agg.signals, "shared_library_naming")
			}
		}

		var langs []string
		for l := range agg.langs {
			langs = append(langs, l)
		}
		sort.Strings(langs)
		if len(langs) == 0 {
			for _, bf := range agg.buildFiles {
				for _, adapter := range taskCodeAuditLanguages() {
					if adapter.DiscoveryFile(bf, nil).Build {
						langs = append(langs, adapter.Language())
					}
				}
			}
			langs = uniqueSorted(langs)
		}

		etype := "module"
		deployability := "auditable_library"
		needsUnknown := false
		switch {
		case agg.webSignals || agg.dockerfile || agg.execTarget != "":
			etype = "service"
			deployability = "deployable"
			if agg.execTarget != "" && name == "." {
				name = agg.execTarget
			}
		case agg.libSignals:
			etype = "shared_library"
			deployability = "auditable_library"
			if agg.libTarget != "" {
				name = agg.libTarget
			}
		default:
			etype = "module"
			deployability = "auditable_library"
			needsUnknown = true
		}
		evPath := d
		if len(agg.buildFiles) > 0 {
			evPath = agg.buildFiles[0]
		}
		out = append(out, extractedModule{
			Name:               name,
			RelPath:            d,
			EntityType:         etype,
			Languages:          langs,
			Deployability:      deployability,
			Signals:            uniqueSorted(agg.signals),
			EvidencePath:       evPath,
			SourceCount:        agg.sources,
			NeedsDeployUnknown: needsUnknown,
		})
	}
	return out
}

func hasWebOrServerEntrySignal(lang, body string) bool {
	switch lang {
	case "java":
		return strings.Contains(body, "@SpringBootApplication") ||
			strings.Contains(body, "@RestController") ||
			strings.Contains(body, "@Controller") ||
			strings.Contains(body, "@WebServlet") ||
			strings.Contains(body, "@Path(")
	case "python":
		return strings.Contains(body, "FastAPI(") ||
			strings.Contains(body, "Flask(") ||
			strings.Contains(body, "APIRouter(") ||
			strings.Contains(body, "@app.route") ||
			strings.Contains(body, "@app.get") ||
			strings.Contains(body, "@app.post") ||
			strings.Contains(body, "urlpatterns")
	case "c":
		return strings.Contains(body, "listen(") || strings.Contains(body, "mg_http_") || strings.Contains(body, "evhttp_")
	default:
		return false
	}
}

func matchModuleForPath(modules []extractedModule, logicalRel, fallbackName string) extractedModule {
	bestLen := -1
	var best extractedModule
	for _, m := range modules {
		if m.RelPath == "." {
			if bestLen < 0 {
				bestLen = 0
				best = m
			}
			continue
		}
		if logicalRel == m.RelPath || strings.HasPrefix(logicalRel, m.RelPath+"/") {
			if len(m.RelPath) > bestLen {
				bestLen = len(m.RelPath)
				best = m
			}
		}
	}
	if bestLen >= 0 {
		return best
	}
	return extractedModule{Name: fallbackName, RelPath: ".", EntityType: "module"}
}

func moduleSubject(m extractedModule) string {
	switch m.EntityType {
	case "service":
		return "service:" + m.Name
	case "shared_library":
		return "shared_library:" + m.Name
	default:
		return "module:" + m.Name
	}
}

func isProfileConfigOrDeployFile(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	if strings.HasPrefix(base, "dockerfile") || strings.HasPrefix(base, "docker-compose") {
		return true
	}
	if strings.HasPrefix(base, "nginx") && strings.HasSuffix(base, ".conf") {
		return true
	}
	if strings.HasPrefix(base, "application") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".properties")) {
		return true
	}
	if strings.HasPrefix(base, "bootstrap") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".properties")) {
		return true
	}
	if base == "web.xml" || base == "struts-config.xml" || base == "mybatis-config.xml" ||
		base == "settings.py" || base == "alembic.ini" || base == "pyproject.toml" ||
		base == "pom.xml" || base == "build.gradle" || base == "build.gradle.kts" ||
		base == "cmakelists.txt" || base == "makefile" || base == "meson.build" {
		return true
	}
	if strings.HasSuffix(base, ".proto") ||
		((strings.Contains(base, "openapi") || strings.Contains(base, "swagger")) &&
			(strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".json"))) {
		return true
	}
	if (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")) &&
		(strings.Contains(strings.ToLower(rel), "/k8s/") || strings.Contains(strings.ToLower(rel), "/deploy/") || strings.HasPrefix(base, "k8s")) {
		return true
	}
	return false
}

var (
	secretKeyNamePattern       = regexp.MustCompile(`(?i)(^|[._-])(password|passwd|secret|token|private_key|api_key|apikey|access_key|secret_key|jwt_secret|client_secret)$`)
	profileJWTPattern          = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	profilePEMPattern          = regexp.MustCompile(`(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
	profileBearerPattern       = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}\b`)
	profileSecretAssignPattern = regexp.MustCompile(`(?i)\b(password|passwd|secret|api_key|apikey|access_key|private_key|client_secret|jwt_secret)\b\s*[:=]\s*["']?([^\s"',;}{]{4,})["']?`)
	nginxLocationPattern       = regexp.MustCompile(`(?i)^\s*location\s+([^\s{]+)`)
	nginxProxyPassPat          = regexp.MustCompile(`(?i)^\s*proxy_pass\s+([^;\s]+)`)
	nginxListenPattern         = regexp.MustCompile(`(?i)^\s*listen\s+([^;\s]+)`)
	nginxSSLPattern            = regexp.MustCompile(`(?i)\bssl_certificate\b|listen\s+\d+\s+ssl`)
	pythonDebugPattern         = regexp.MustCompile(`(?m)^\s*DEBUG\s*=\s*(True|False)\b`)
)

func redactConfigSnippet(line string) string {
	trimmed := strings.TrimSpace(line)
	if len([]rune(trimmed)) > maxProfileSnippetRunes {
		trimmed = string([]rune(trimmed)[:maxProfileSnippetRunes]) + "…"
	}
	trimmed = profileJWTPattern.ReplaceAllString(trimmed, "<REDACTED_JWT>")
	trimmed = profilePEMPattern.ReplaceAllString(trimmed, "<REDACTED_PEM>")
	trimmed = profileBearerPattern.ReplaceAllString(trimmed, "Bearer <REDACTED>")
	trimmed = profileSecretAssignPattern.ReplaceAllString(trimmed, "$1=<REDACTED>")
	return trimmed
}

func extractConfigFileFacts(res *codebaseExtractionResult, rawRel, logicalRel, modSubject, body string, version taskCodebaseVersion) {
	base := strings.ToLower(path.Base(logicalRel))
	etype := "config"
	if strings.HasSuffix(base, ".proto") || strings.Contains(base, "openapi") || strings.Contains(base, "swagger") {
		etype = "protocol"
	}
	res.Entities = append(res.Entities, extractedEntity{
		EntityType: etype,
		Name:       logicalRel,
		CodebaseID: version.CodebaseID,
		VersionID:  version.ID,
		Attributes: map[string]any{"path": rawRel, "module": modSubject},
	})
	res.Claims = append(res.Claims, extractedClaim{
		Subject:          modSubject,
		Relation:         "has_config",
		ObjectValue:      logicalRel,
		SourceType:       pgdb.ClaimSourceStaticExtraction,
		EvidenceKind:     pgdb.EvidenceConfig,
		EvidenceRef:      rawRel,
		EvidencePayload:  map[string]any{"path": rawRel},
		ValidCodeVersion: version.ID,
		ValidConfig:      logicalRel,
	})

	switch {
	case strings.HasPrefix(base, "nginx") && strings.HasSuffix(base, ".conf"):
		extractNginxConfigFacts(res, rawRel, logicalRel, modSubject, body, version)
	case strings.HasPrefix(base, "docker-compose"):
		extractDockerComposeFacts(res, rawRel, logicalRel, modSubject, body, version)
	case strings.HasSuffix(base, ".properties"):
		extractPropertiesConfigFacts(res, rawRel, logicalRel, modSubject, body, version)
	case strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml"):
		extractYAMLConfigFacts(res, rawRel, logicalRel, modSubject, body, version)
	case base == "settings.py":
		for i, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
			if m := pythonDebugPattern.FindStringSubmatch(line); len(m) == 2 {
				val := strings.ToLower(m[1])
				res.Claims = append(res.Claims, extractedClaim{
					Subject:          modSubject,
					Relation:         "debug_mode",
					ObjectValue:      val,
					SourceType:       pgdb.ClaimSourceStaticExtraction,
					EvidenceKind:     pgdb.EvidenceConfig,
					EvidenceRef:      fmt.Sprintf("%s:%d", rawRel, i+1),
					EvidencePayload:  map[string]any{"line": i + 1, "snippet": redactConfigSnippet(line)},
					ValidCodeVersion: version.ID,
					ValidConfig:      logicalRel,
				})
			}
		}
	}
}

func emitNormalizedConfigKV(res *codebaseExtractionResult, rawRel, logicalRel, modSubject, fullKey, rawVal string, lineNo int, rawLine string, version taskCodebaseVersion) {
	keyLower := strings.ToLower(strings.TrimSpace(fullKey))
	val := strings.Trim(strings.TrimSpace(rawVal), `"'`)
	if keyLower == "" {
		return
	}
	if secretKeyNamePattern.MatchString(keyLower) {
		res.Claims = append(res.Claims, extractedClaim{
			Subject:          modSubject,
			Relation:         "references_secret_config",
			ObjectValue:      fullKey,
			SourceType:       pgdb.ClaimSourceStaticExtraction,
			EvidenceKind:     pgdb.EvidenceConfig,
			EvidenceRef:      fmt.Sprintf("%s:%d", rawRel, lineNo),
			EvidencePayload:  map[string]any{"line": lineNo, "key": fullKey, "snippet": fullKey + "=<REDACTED>"},
			ValidCodeVersion: version.ID,
			ValidConfig:      logicalRel,
		})
		return
	}
	if val == "" {
		return
	}
	evRef := fmt.Sprintf("%s:%d", rawRel, lineNo)
	evPayload := map[string]any{"line": lineNo, "key": fullKey, "snippet": redactConfigSnippet(rawLine)}

	emit := func(relation, objectVal string) {
		res.Claims = append(res.Claims, extractedClaim{
			Subject:          modSubject,
			Relation:         relation,
			ObjectValue:      objectVal,
			SourceType:       pgdb.ClaimSourceStaticExtraction,
			EvidenceKind:     pgdb.EvidenceConfig,
			EvidenceRef:      evRef,
			EvidencePayload:  evPayload,
			ValidCodeVersion: version.ID,
			ValidConfig:      logicalRel,
		})
	}

	switch {
	case keyLower == "server.port" || keyLower == "management.server.port":
		if keyLower == "server.port" {
			emit("server_port", val)
		}
	case keyLower == "server.servlet.context-path" || keyLower == "server.context-path":
		emit("context_path", val)
	case keyLower == "spring.application.name":
		emit("service_name", val)
	case strings.Contains(keyLower, "csrf") && (strings.HasSuffix(keyLower, ".enabled") || keyLower == "csrf"):
		if strings.EqualFold(val, "true") || strings.EqualFold(val, "enabled") {
			emit("csrf_protection", "enabled")
		} else if strings.EqualFold(val, "false") || strings.EqualFold(val, "disabled") {
			emit("csrf_protection", "disabled")
		}
	case keyLower == "server.ssl.enabled" || keyLower == "security.require-ssl":
		emit("tls_enabled", strings.ToLower(val))
	case keyLower == "debug" || keyLower == "app.debug" || keyLower == "flask.debug":
		emit("debug_mode", strings.ToLower(val))
	case strings.Contains(keyLower, "datasource.url") || strings.Contains(keyLower, "database.url"):
		lowerVal := strings.ToLower(val)
		switch {
		case strings.Contains(lowerVal, "postgresql") || strings.Contains(lowerVal, "postgres"):
			emit("database_engine", "postgresql")
		case strings.Contains(lowerVal, "mysql"):
			emit("database_engine", "mysql")
		case strings.Contains(lowerVal, "sqlite"):
			emit("database_engine", "sqlite")
		case strings.Contains(lowerVal, "oracle"):
			emit("database_engine", "oracle")
		case strings.Contains(lowerVal, "sqlserver"):
			emit("database_engine", "sqlserver")
		}
	case strings.HasPrefix(keyLower, "spring.data.redis.") || strings.HasPrefix(keyLower, "spring.redis."):
		if strings.HasSuffix(keyLower, ".host") {
			emit("cache_engine", "redis")
		}
	case strings.HasPrefix(keyLower, "spring.kafka."):
		if strings.HasSuffix(keyLower, "bootstrap-servers") {
			emit("mq_engine", "kafka")
		}
	case strings.HasPrefix(keyLower, "spring.rabbitmq."):
		if strings.HasSuffix(keyLower, ".host") || strings.HasSuffix(keyLower, ".addresses") {
			emit("mq_engine", "rabbitmq")
		}
	case strings.Contains(keyLower, "jwt.issuer") || strings.Contains(keyLower, "oauth2.resourceserver"):
		emit("auth_mechanism", "jwt")
	}
}

func extractPropertiesConfigFacts(res *codebaseExtractionResult, rawRel, logicalRel, modSubject, body string, version taskCodebaseVersion) {
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!") {
			continue
		}
		idx := strings.IndexAny(trimmed, "=:")
		if idx <= 0 {
			continue
		}
		k := strings.TrimSpace(trimmed[:idx])
		v := strings.TrimSpace(trimmed[idx+1:])
		emitNormalizedConfigKV(res, rawRel, logicalRel, modSubject, k, v, i+1, line, version)
	}
}

type yamlIndentFrame struct {
	indent int
	key    string
}

func extractYAMLConfigFacts(res *codebaseExtractionResult, rawRel, logicalRel, modSubject, body string, version taskCodebaseVersion) {
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	var stack []yamlIndentFrame
	for i, rawLine := range lines {
		noTab := strings.ReplaceAll(rawLine, "\t", "  ")
		trimmed := strings.TrimSpace(noTab)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || trimmed == "---" || strings.HasPrefix(trimmed, "- ") {
			continue
		}
		indent := len(noTab) - len(strings.TrimLeft(noTab, " "))
		colon := strings.IndexByte(trimmed, ':')
		if colon <= 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:colon])
		rest := strings.TrimSpace(trimmed[colon+1:])
		if hashIdx := strings.Index(rest, " #"); hashIdx >= 0 {
			rest = strings.TrimSpace(rest[:hashIdx])
		}
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		stack = append(stack, yamlIndentFrame{indent: indent, key: key})

		if rest == "" || rest == "|" || rest == ">" {
			continue
		}
		parts := make([]string, len(stack))
		for idx, fr := range stack {
			parts[idx] = fr.key
		}
		fullKey := strings.Join(parts, ".")
		emitNormalizedConfigKV(res, rawRel, logicalRel, modSubject, fullKey, rest, i+1, rawLine, version)
	}
}

func extractDockerComposeFacts(res *codebaseExtractionResult, rawRel, logicalRel, modSubject, body string, version taskCodebaseVersion) {
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	inServices := false
	servicesIndent := -1
	currentSvc := ""
	svcIndent := -1
	currentAttr := ""

	var hintsBySvc = map[string]*deploymentHint{}
	getHint := func(svc string, lineNo int) *deploymentHint {
		h, ok := hintsBySvc[svc]
		if !ok {
			h = &deploymentHint{ServiceName: svc, ConfigPath: rawRel, Line: lineNo}
			hintsBySvc[svc] = h
		}
		return h
	}

	for i, rawLine := range lines {
		noTab := strings.ReplaceAll(rawLine, "\t", "  ")
		trimmed := strings.TrimSpace(noTab)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(noTab) - len(strings.TrimLeft(noTab, " "))

		if strings.HasPrefix(trimmed, "- ") && currentSvc != "" && currentAttr == "ports" {
			portSpec := strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")), `"'`)
			h := getHint(currentSvc, i+1)
			if parts := strings.Split(portSpec, ":"); len(parts) >= 2 {
				hostPart := parts[len(parts)-2]
				if slash := strings.IndexByte(hostPart, '/'); slash >= 0 {
					hostPart = hostPart[:slash]
				}
				contPart := parts[len(parts)-1]
				if slash := strings.IndexByte(contPart, '/'); slash >= 0 {
					contPart = contPart[:slash]
				}
				h.HostPort = strings.TrimSpace(hostPart)
				h.ContainerPort = strings.TrimSpace(contPart)
			} else if portSpec != "" {
				h.ContainerPort = portSpec
			}
			continue
		}

		colon := strings.IndexByte(trimmed, ':')
		if colon <= 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:colon])
		val := strings.Trim(strings.TrimSpace(trimmed[colon+1:]), `"'`)

		if key == "services" && val == "" {
			inServices = true
			servicesIndent = indent
			currentSvc = ""
			svcIndent = -1
			continue
		}
		if !inServices {
			continue
		}
		if indent <= servicesIndent {
			inServices = false
			currentSvc = ""
			continue
		}
		if val == "" && (svcIndent < 0 || indent <= svcIndent) {
			currentSvc = key
			svcIndent = indent
			currentAttr = ""
			getHint(currentSvc, i+1)
			continue
		}
		if currentSvc == "" {
			continue
		}
		if indent > svcIndent {
			currentAttr = key
			h := getHint(currentSvc, i+1)
			switch key {
			case "build":
				if val != "" {
					h.BuildContext = val
				}
			case "context":
				if val != "" {
					h.BuildContext = val
				}
			case "image":
				h.Image = val
			}
		}
	}

	var svcNames []string
	for name := range hintsBySvc {
		svcNames = append(svcNames, name)
	}
	sort.Strings(svcNames)
	for _, name := range svcNames {
		h := hintsBySvc[name]
		res.DeployHints = append(res.DeployHints, *h)
		evRef := fmt.Sprintf("%s:%d", rawRel, h.Line)
		if h.ContainerPort != "" || h.HostPort != "" {
			port := h.ContainerPort
			if h.HostPort != "" {
				port = h.HostPort
			}
			res.Claims = append(res.Claims, extractedClaim{
				Subject:          "compose_service:" + h.ServiceName,
				Relation:         "exposed_port",
				ObjectValue:      port,
				SourceType:       pgdb.ClaimSourceStaticExtraction,
				EvidenceKind:     pgdb.EvidenceConfig,
				EvidenceRef:      evRef,
				EvidencePayload:  map[string]any{"line": h.Line, "service": h.ServiceName, "host_port": h.HostPort, "container_port": h.ContainerPort, "build": h.BuildContext},
				ValidCodeVersion: version.ID,
				ValidConfig:      logicalRel,
			})
		}
	}
	_ = modSubject
}

func extractNginxConfigFacts(res *codebaseExtractionResult, rawRel, logicalRel, modSubject, body string, version taskCodebaseVersion) {
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	curLoc := ""
	for i, line := range lines {
		if nginxSSLPattern.MatchString(line) {
			res.Claims = append(res.Claims, extractedClaim{
				Subject: modSubject, Relation: "tls_enabled", ObjectValue: "true",
				SourceType: pgdb.ClaimSourceStaticExtraction, EvidenceKind: pgdb.EvidenceConfig,
				EvidenceRef: fmt.Sprintf("%s:%d", rawRel, i+1), EvidencePayload: map[string]any{"line": i + 1, "snippet": redactConfigSnippet(line)},
				ValidCodeVersion: version.ID, ValidConfig: logicalRel,
			})
		}
		if m := nginxListenPattern.FindStringSubmatch(line); len(m) == 2 {
			res.Claims = append(res.Claims, extractedClaim{
				Subject: modSubject, Relation: "gateway_listen", ObjectValue: strings.TrimSpace(m[1]),
				SourceType: pgdb.ClaimSourceStaticExtraction, EvidenceKind: pgdb.EvidenceConfig,
				EvidenceRef: fmt.Sprintf("%s:%d", rawRel, i+1), EvidencePayload: map[string]any{"line": i + 1, "snippet": redactConfigSnippet(line)},
				ValidCodeVersion: version.ID, ValidConfig: logicalRel,
			})
		}
		if m := nginxLocationPattern.FindStringSubmatch(line); len(m) == 2 {
			curLoc = strings.TrimSpace(m[1])
		}
		if m := nginxProxyPassPat.FindStringSubmatch(line); len(m) == 2 {
			upstream := strings.TrimSpace(m[1])
			res.DeployHints = append(res.DeployHints, deploymentHint{
				UpstreamName: upstream, ProxyPass: upstream, Location: curLoc, ConfigPath: rawRel, Line: i + 1,
			})
			res.Claims = append(res.Claims, extractedClaim{
				Subject: modSubject, Relation: "upstream_target", ObjectValue: upstream,
				SourceType: pgdb.ClaimSourceStaticExtraction, EvidenceKind: pgdb.EvidenceConfig,
				EvidenceRef: fmt.Sprintf("%s:%d", rawRel, i+1), EvidencePayload: map[string]any{"line": i + 1, "location": curLoc, "proxy_pass": upstream},
				ValidCodeVersion: version.ID, ValidConfig: logicalRel,
			})
		}
	}
}

var (
	javaClassMappingPat  = regexp.MustCompile(`@(?:RequestMapping|Path)\s*\(([^)]*)\)`)
	javaMethodMappingPat = regexp.MustCompile(`@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*(?:\(([^)]*)\))?`)
	javaJaxRsMethodPat   = regexp.MustCompile(`@(GET|POST|PUT|DELETE|PATCH)\b`)
	javaPathAttrPat      = regexp.MustCompile(`(?:value|path)\s*=\s*["']([^"']+)["']|^\s*["']([^"']+)["']\s*$`)
	javaAnyQuotedPat     = regexp.MustCompile(`["']([^"']+)["']`)
	javaClassDeclPat     = regexp.MustCompile(`\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\b`)
	javaMethodDeclPat    = regexp.MustCompile(`\b(?:public|protected|private)\s+[\w<>[\].,\s]+\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)
	javaPreAuthPat       = regexp.MustCompile(`@(?:PreAuthorize|Secured|RolesAllowed)\s*\(\s*["']([^"']+)["']`)
	javaWebServletPat    = regexp.MustCompile(`@WebServlet\s*\(([^)]*)\)`)
)

func extractJavaSourceFacts(res *codebaseExtractionResult, rawRel, modSubject, body string, version taskCodebaseVersion) {
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	className := strings.TrimSuffix(path.Base(rawRel), ".java")
	classPrefix := ""
	pendingHTTPMethod := ""
	pendingPath := ""
	pendingLine := 0

	for i, line := range lines {
		lineNo := i + 1
		trimmed := strings.TrimSpace(line)
		if cm := javaClassDeclPat.FindStringSubmatch(trimmed); len(cm) == 2 {
			className = cm[1]
			if pendingPath != "" {
				classPrefix = pendingPath
				pendingPath = ""
				pendingHTTPMethod = ""
			}
		}
		if sm := javaWebServletPat.FindStringSubmatch(trimmed); len(sm) == 2 {
			p := firstQuotedOrRoot(sm[1])
			addExtractedEntry(res, rawRel, lineNo, modSubject, "HTTP *", p, className, line, version)
		}
		if mm := javaMethodMappingPat.FindStringSubmatch(trimmed); len(mm) >= 2 {
			ann := mm[1]
			args := ""
			if len(mm) > 2 {
				args = mm[2]
			}
			p := extractSpringMappingPath(args)
			method := "ANY"
			switch ann {
			case "GetMapping":
				method = "GET"
			case "PostMapping":
				method = "POST"
			case "PutMapping":
				method = "PUT"
			case "DeleteMapping":
				method = "DELETE"
			case "PatchMapping":
				method = "PATCH"
			case "RequestMapping":
				if m := regexp.MustCompile(`RequestMethod\.(GET|POST|PUT|DELETE|PATCH)`).FindStringSubmatch(args); len(m) == 2 {
					method = m[1]
				}
			}
			if !strings.Contains(trimmed, "class ") {
				pendingHTTPMethod = method
				pendingPath = p
				pendingLine = lineNo
			}
		} else if jm := javaJaxRsMethodPat.FindStringSubmatch(trimmed); len(jm) == 2 {
			pendingHTTPMethod = jm[1]
			pendingLine = lineNo
		} else if pm := javaClassMappingPat.FindStringSubmatch(trimmed); len(pm) == 2 {
			pendingPath = firstQuotedOrRoot(pm[1])
			if pendingLine == 0 {
				pendingLine = lineNo
			}
		}

		if pendingHTTPMethod != "" {
			if md := javaMethodDeclPat.FindStringSubmatch(trimmed); len(md) == 2 {
				fullPath := joinURLPaths(classPrefix, pendingPath)
				addExtractedEntry(res, rawRel, pendingLine, modSubject, "HTTP "+pendingHTTPMethod, fullPath, className+"."+md[1], trimmed, version)
				pendingHTTPMethod = ""
				pendingPath = ""
				pendingLine = 0
			}
		}

		if strings.Contains(trimmed, "@SpringBootApplication") {
			emitJavaClaim(res, modSubject, "framework", "Spring Boot", rawRel, lineNo, trimmed, version)
		}
		if strings.Contains(trimmed, "SecurityFilterChain") || strings.Contains(trimmed, "WebSecurityConfigurerAdapter") ||
			strings.Contains(trimmed, "OncePerRequestFilter") || strings.Contains(trimmed, "HandlerInterceptor") {
			emitJavaClaim(res, modSubject, "has_auth_filter", className, rawRel, lineNo, trimmed, version)
		}
		if strings.Contains(trimmed, "Jwts.parser") || strings.Contains(trimmed, "JwtDecoder") {
			emitJavaClaim(res, modSubject, "auth_mechanism", "jwt", rawRel, lineNo, trimmed, version)
		} else if strings.Contains(trimmed, "ShiroFilterFactoryBean") {
			emitJavaClaim(res, modSubject, "auth_mechanism", "apache_shiro", rawRel, lineNo, trimmed, version)
		}
		if strings.Contains(trimmed, ".csrf().disable()") || strings.Contains(trimmed, "csrf(AbstractHttpConfigurer::disable)") ||
			strings.Contains(trimmed, "csrf(c -> c.disable())") {
			emitJavaClaim(res, modSubject, "csrf_protection", "disabled", rawRel, lineNo, trimmed, version)
		}
		if strings.Contains(trimmed, "permitAll()") {
			emitJavaClaim(res, modSubject, "public_route", redactConfigSnippet(trimmed), rawRel, lineNo, trimmed, version)
		}
		if pm := javaPreAuthPat.FindStringSubmatch(trimmed); len(pm) == 2 {
			emitJavaClaim(res, modSubject, "auth_chain", pm[1], rawRel, lineNo, trimmed, version)
		}
		if strings.Contains(trimmed, "@DubboService") || strings.Contains(trimmed, "@GrpcService") {
			proto := "grpc"
			if strings.Contains(trimmed, "@DubboService") {
				proto = "dubbo"
			}
			res.Entities = append(res.Entities, extractedEntity{
				EntityType: "entry", Name: strings.ToUpper(proto) + " " + className,
				CodebaseID: version.CodebaseID, VersionID: version.ID,
				Attributes: map[string]any{"protocol": proto, "file": rawRel, "line": lineNo, "module": modSubject},
			})
			emitJavaClaim(res, modSubject, "exposes_entry", strings.ToUpper(proto)+" "+className, rawRel, lineNo, trimmed, version)
		}
		if strings.Contains(trimmed, "@KafkaListener") || strings.Contains(trimmed, "@RabbitListener") {
			mq := "rabbitmq"
			if strings.Contains(trimmed, "@KafkaListener") {
				mq = "kafka"
			}
			emitJavaClaim(res, modSubject, "mq_engine", mq, rawRel, lineNo, trimmed, version)
		}
		if strings.Contains(trimmed, "@FeignClient") {
			emitJavaClaim(res, modSubject, "depends_on", className+"(FeignClient)", rawRel, lineNo, trimmed, version)
		}
	}
}

var (
	pyRouterPrefixPat = regexp.MustCompile(`APIRouter\s*\([^)]*prefix\s*=\s*["']([^"']+)["']`)
	pyDecoratorPat    = regexp.MustCompile(`@(?:app|router|bp|blueprint)\.(get|post|put|delete|patch|route)\s*\(\s*["']([^"']*)["']`)
	pyDjangoPathPat   = regexp.MustCompile(`\b(?:path|re_path|url)\s*\(\s*r?["']([^"']*)["']\s*,\s*([A-Za-z0-9_.]+)`)
	pyDefPat          = regexp.MustCompile(`^(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)`)
)

func extractPythonSourceFacts(res *codebaseExtractionResult, rawRel, modSubject, body string, version taskCodebaseVersion) {
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	routerPrefix := ""
	pendingMethod := ""
	pendingPath := ""
	pendingLine := 0
	pendingAuth := ""

	for i, line := range lines {
		lineNo := i + 1
		trimmed := strings.TrimSpace(line)
		if rm := pyRouterPrefixPat.FindStringSubmatch(trimmed); len(rm) == 2 {
			routerPrefix = rm[1]
		}
		if strings.Contains(trimmed, "FastAPI(") {
			emitJavaClaim(res, modSubject, "framework", "FastAPI", rawRel, lineNo, trimmed, version)
		} else if strings.Contains(trimmed, "Flask(") {
			emitJavaClaim(res, modSubject, "framework", "Flask", rawRel, lineNo, trimmed, version)
		}
		if strings.Contains(trimmed, "@login_required") || strings.Contains(trimmed, "@permission_required") || strings.Contains(trimmed, "@jwt_required") {
			pendingAuth = trimmed
			emitJavaClaim(res, modSubject, "has_auth_filter", trimmed, rawRel, lineNo, trimmed, version)
		}
		if dm := pyDecoratorPat.FindStringSubmatch(trimmed); len(dm) == 3 {
			m := strings.ToUpper(dm[1])
			if m == "ROUTE" {
				m = "ANY"
			}
			pendingMethod = m
			pendingPath = dm[2]
			pendingLine = lineNo
		}
		if fm := pyDefPat.FindStringSubmatch(trimmed); len(fm) >= 2 && pendingMethod != "" {
			fullPath := joinURLPaths(routerPrefix, pendingPath)
			entryName := "HTTP " + pendingMethod + " " + fullPath
			addExtractedEntry(res, rawRel, pendingLine, modSubject, "HTTP "+pendingMethod, fullPath, fm[1], trimmed, version)
			if strings.Contains(fm[2], "Depends(") || pendingAuth != "" {
				emitJavaClaim(res, "entry:"+entryName, "auth_required", "true", rawRel, lineNo, trimmed, version)
			}
			pendingMethod = ""
			pendingPath = ""
			pendingLine = 0
			pendingAuth = ""
		}
		if dj := pyDjangoPathPat.FindStringSubmatch(trimmed); len(dj) == 3 {
			fullPath := joinURLPaths("/", dj[1])
			addExtractedEntry(res, rawRel, lineNo, modSubject, "HTTP ANY", fullPath, dj[2], trimmed, version)
		}
		if strings.Contains(trimmed, "AllowAny") {
			emitJavaClaim(res, modSubject, "public_route", redactConfigSnippet(trimmed), rawRel, lineNo, trimmed, version)
		}
		if m := pythonDebugPattern.FindStringSubmatch(line); len(m) == 2 {
			emitJavaClaim(res, modSubject, "debug_mode", strings.ToLower(m[1]), rawRel, lineNo, trimmed, version)
		}
	}
}

var (
	cMainPat      = regexp.MustCompile(`\bint\s+main\s*\(`)
	cNetSocketPat = regexp.MustCompile(`\b(listen|bind|accept|mg_http_listen|evhttp_bind_socket)\s*\(`)
	cLocalIncPat  = regexp.MustCompile(`^\s*#include\s+"([^"]+)"`)
)

func extractCSourceFacts(res *codebaseExtractionResult, rawRel, modSubject, body string, version taskCodebaseVersion) {
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	for i, line := range lines {
		lineNo := i + 1
		trimmed := strings.TrimSpace(line)
		if cMainPat.MatchString(trimmed) {
			addExtractedEntry(res, rawRel, lineNo, modSubject, "CLI main", rawRel, "main", trimmed, version)
		}
		if m := cNetSocketPat.FindStringSubmatch(trimmed); len(m) == 2 {
			emitJavaClaim(res, modSubject, "exposes_entry", "C_SOCKET "+m[1]+"@"+rawRel, rawRel, lineNo, trimmed, version)
		}
		if inc := cLocalIncPat.FindStringSubmatch(trimmed); len(inc) == 2 {
			emitJavaClaim(res, modSubject, "depends_on", inc[1], rawRel, lineNo, trimmed, version)
		}
	}
}

func addExtractedEntry(res *codebaseExtractionResult, rawRel string, lineNo int, modSubject, methodPrefix, routePath, handler, snippet string, version taskCodebaseVersion) {
	name := strings.TrimSpace(methodPrefix) + " " + routePath
	res.Entities = append(res.Entities, extractedEntity{
		EntityType: "entry",
		Name:       name,
		CodebaseID: version.CodebaseID,
		VersionID:  version.ID,
		Attributes: map[string]any{
			"file":    rawRel,
			"line":    lineNo,
			"handler": handler,
			"module":  modSubject,
			"path":    routePath,
		},
	})
	res.Claims = append(res.Claims, extractedClaim{
		Subject:          modSubject,
		Relation:         "exposes_entry",
		ObjectValue:      name,
		SourceType:       pgdb.ClaimSourceStaticExtraction,
		EvidenceKind:     pgdb.EvidenceCodeRange,
		EvidenceRef:      fmt.Sprintf("%s:%d", rawRel, lineNo),
		EvidencePayload:  map[string]any{"line": lineNo, "handler": handler, "snippet": redactConfigSnippet(snippet)},
		ValidCodeVersion: version.ID,
	})
}

func emitJavaClaim(res *codebaseExtractionResult, subject, relation, value, rawRel string, lineNo int, snippet string, version taskCodebaseVersion) {
	res.Claims = append(res.Claims, extractedClaim{
		Subject:          subject,
		Relation:         relation,
		ObjectValue:      value,
		SourceType:       pgdb.ClaimSourceStaticExtraction,
		EvidenceKind:     pgdb.EvidenceCodeRange,
		EvidenceRef:      fmt.Sprintf("%s:%d", rawRel, lineNo),
		EvidencePayload:  map[string]any{"line": lineNo, "snippet": redactConfigSnippet(snippet)},
		ValidCodeVersion: version.ID,
	})
}

func extractSpringMappingPath(args string) string {
	args = strings.TrimSpace(args)
	if args == "" {
		return "/"
	}
	if m := javaPathAttrPat.FindStringSubmatch(args); len(m) >= 2 {
		if m[1] != "" {
			return m[1]
		}
		if len(m) > 2 && m[2] != "" {
			return m[2]
		}
	}
	if m := javaAnyQuotedPat.FindStringSubmatch(args); len(m) == 2 {
		return m[1]
	}
	return "/"
}

func firstQuotedOrRoot(s string) string {
	if m := javaAnyQuotedPat.FindStringSubmatch(s); len(m) == 2 && strings.TrimSpace(m[1]) != "" {
		return strings.TrimSpace(m[1])
	}
	return "/"
}

func joinURLPaths(prefix, suffix string) string {
	p := strings.TrimSpace(prefix)
	s := strings.TrimSpace(suffix)
	if p == "" && s == "" {
		return "/"
	}
	joined := path.Join("/", p, s)
	if !strings.HasPrefix(joined, "/") {
		return "/" + joined
	}
	return joined
}
