package server

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	pgdb "github.com/Autumn-27/artex/db"
)

type javaBinaryClassSummary struct {
	ClassName         string `json:"class_name"`
	Artifact          string `json:"artifact"`
	Entry             string `json:"entry"`
	OriginalClassFile string `json:"original_class_file,omitempty"`
	Application       bool   `json:"application"`
}

type javaBinaryEndpointSummary struct {
	Method     string `json:"method"`
	Path       string `json:"path"`
	ClassName  string `json:"class_name"`
	MethodName string `json:"method_name,omitempty"`
	Artifact   string `json:"artifact"`
	Entry      string `json:"entry"`
}

type javaBinaryProfileSummary struct {
	ApplicationClasses []javaBinaryClassSummary    `json:"application_classes,omitempty"`
	WebEndpoints       []javaBinaryEndpointSummary `json:"web_endpoints,omitempty"`
	Available          bool                        `json:"available"`
	UnavailableReason  string                      `json:"unavailable_reason,omitempty"`
}

var (
	webXMLServletNamePat = regexp.MustCompile(`(?is)<servlet-name>\s*([^<\s]+)\s*</servlet-name>`)
	webXMLURLPatternPat  = regexp.MustCompile(`(?is)<url-pattern>\s*([^<\s]+)\s*</url-pattern>`)
	webXMLFilterNamePat  = regexp.MustCompile(`(?is)<filter-name>\s*([^<\s]+)\s*</filter-name>`)
)

func (s *Server) extractJavaBinaryProfile(ctx context.Context, taskID string, versionDir string, version taskCodebaseVersion) codebaseExtractionResult {
	var res codebaseExtractionResult
	res.Languages = []string{"java"}

	contentsDir := filepath.Join(versionDir, "contents")
	artifactPath := filepath.Join(contentsDir, filepath.FromSlash(version.Name))
	info, err := os.Lstat(artifactPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		res.Entities = append(res.Entities, extractedEntity{
			EntityType: "module",
			Name:       version.Name,
			CodebaseID: version.CodebaseID,
			VersionID:  version.ID,
			Gap:        true,
			GapReason:  "Java 二进制包缺失或不可读取",
		})
		return res
	}

	modName := strings.TrimSuffix(path.Base(version.Name), path.Ext(version.Name))
	if modName == "" {
		modName = version.Name
	}
	mod := extractedModule{
		Name:          modName,
		RelPath:       ".",
		EntityType:    "service",
		Languages:     []string{"java"},
		Deployability: "binary_only",
		EvidencePath:  version.Name,
	}
	modSubject := moduleSubject(mod)

	var classFiles []string
	var bundledLibs []string
	hasBootOrWebLayout := false

	switch version.Format {
	case "class":
		data, oversized, rerr := readBoundedRegularFile(artifactPath, maxMaterialClassInspectBytes)
		if rerr != nil || oversized || !isValidJavaClassBytes(data) {
			res.Entities = append(res.Entities, extractedEntity{
				EntityType: "module", Name: version.Name, CodebaseID: version.CodebaseID, VersionID: version.ID,
				Gap: true, GapReason: "Java class 字节码无效或不可读取",
			})
			return res
		}
		classFiles = append(classFiles, version.Name)
		mod.EntityType = "module"
		mod.NeedsDeployUnknown = true
	case "jar", "war", "zip":
		zr, zerr := zip.OpenReader(artifactPath)
		if zerr != nil {
			res.Entities = append(res.Entities, extractedEntity{
				EntityType: "module", Name: version.Name, CodebaseID: version.CodebaseID, VersionID: version.ID,
				Gap: true, GapReason: fmt.Sprintf("Java 部署包 %s 无法打开: %v", version.Name, zerr),
			})
			return res
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
				res.Entities = append(res.Entities, extractedEntity{
					EntityType: "module", Name: path.Join(version.Name, zf.Name), CodebaseID: version.CodebaseID, VersionID: version.ID,
					Gap: true, GapReason: "部署包包含非法路径条目",
				})
				continue
			}
			upper := strings.ToUpper(cleanName)
			lower := strings.ToLower(cleanName)
			if strings.HasPrefix(upper, "BOOT-INF/CLASSES/") || strings.HasPrefix(upper, "WEB-INF/CLASSES/") {
				hasBootOrWebLayout = true
			}
			if strings.HasSuffix(lower, ".class") {
				rc, oerr := zf.Open()
				if oerr != nil {
					res.Entities = append(res.Entities, extractedEntity{
						EntityType: "module", Name: version.Name + "!" + cleanName, CodebaseID: version.CodebaseID, VersionID: version.ID,
						Gap: true, GapReason: fmt.Sprintf("读取字节码条目失败: %v", oerr),
					})
					continue
				}
				data, rerr := io.ReadAll(io.LimitReader(rc, maxMaterialClassInspectBytes+1))
				_ = rc.Close()
				if rerr != nil || int64(len(data)) > maxMaterialClassInspectBytes || !isValidJavaClassBytes(data) {
					res.Entities = append(res.Entities, extractedEntity{
						EntityType: "module", Name: version.Name + "!" + cleanName, CodebaseID: version.CodebaseID, VersionID: version.ID,
						Gap: true, GapReason: "Java class 字节码损坏或魔数校验失败",
					})
					continue
				}
				classFiles = append(classFiles, version.Name+"!"+cleanName)
				continue
			}
			if (strings.HasPrefix(upper, "BOOT-INF/LIB/") || strings.HasPrefix(upper, "WEB-INF/LIB/")) && strings.HasSuffix(lower, ".jar") {
				libBase := path.Base(cleanName)
				bundledLibs = append(bundledLibs, libBase)
				continue
			}
			if upper == "META-INF/MANIFEST.MF" && zf.UncompressedSize64 <= uint64(maxProfileConfigBytes) {
				if data, rerr := readZipEntryBounded(zf, maxProfileConfigBytes); rerr == nil && utf8.Valid(data) {
					extractManifestFacts(&res, version.Name+"!"+cleanName, modSubject, string(data), version, &hasBootOrWebLayout)
				} else {
					res.Entities = append(res.Entities, extractedEntity{
						EntityType: "config", Name: version.Name + "!" + cleanName, CodebaseID: version.CodebaseID, VersionID: version.ID,
						Gap: true, GapReason: "MANIFEST.MF 不可读取",
					})
				}
				continue
			}
			if upper == "WEB-INF/WEB.XML" && zf.UncompressedSize64 <= uint64(maxProfileConfigBytes) {
				hasBootOrWebLayout = true
				if data, rerr := readZipEntryBounded(zf, maxProfileConfigBytes); rerr == nil && utf8.Valid(data) {
					extractWebXMLFacts(&res, version.Name+"!"+cleanName, modSubject, string(data), version)
				} else {
					res.Entities = append(res.Entities, extractedEntity{
						EntityType: "config", Name: version.Name + "!" + cleanName, CodebaseID: version.CodebaseID, VersionID: version.ID,
						Gap: true, GapReason: "WEB-INF/web.xml 不可读取",
					})
				}
				continue
			}
			normalizedRel := stripArchiveCodePrefix(cleanName)
			if isProfileConfigOrDeployFile(normalizedRel) {
				data, rerr := readZipEntryBounded(zf, maxProfileConfigBytes)
				if rerr != nil || !utf8.Valid(data) {
					res.Entities = append(res.Entities, extractedEntity{
						EntityType: "config", Name: version.Name + "!" + cleanName, CodebaseID: version.CodebaseID, VersionID: version.ID,
						Gap: true, GapReason: "部署包内配置文件不可读取或超限",
					})
					continue
				}
				extractConfigFileFacts(&res, version.Name+"!"+cleanName, normalizedRel, modSubject, string(data), version)
			}
		}
	default:
		res.Entities = append(res.Entities, extractedEntity{
			EntityType: "module", Name: version.Name, CodebaseID: version.CodebaseID, VersionID: version.ID,
			Gap: true, GapReason: fmt.Sprintf("不支持的二进制包格式 %q", version.Format),
		})
		return res
	}

	if version.Format == "jar" && !hasBootOrWebLayout {
		mod.EntityType = "shared_library"
		mod.Deployability = "auditable_library"
		modSubject = moduleSubject(mod)
	}
	mod.SourceCount = len(classFiles)
	res.Modules = append(res.Modules, mod)

	for _, lib := range uniqueSorted(bundledLibs) {
		if len(bundledLibs) > 64 {
			break
		}
		res.Claims = append(res.Claims, extractedClaim{
			Subject:          modSubject,
			Relation:         "depends_on",
			ObjectValue:      lib,
			SourceType:       pgdb.ClaimSourceStaticExtraction,
			EvidenceKind:     pgdb.EvidenceConfig,
			EvidenceRef:      version.Name + "!lib/" + lib,
			EvidencePayload:  map[string]any{"library": lib},
			ValidCodeVersion: version.ID,
		})
	}

	if len(classFiles) > 0 {
		summary, probeErr := s.queryJavaCodeDBForProfile(ctx, taskID, versionDir, version, artifactPath, classFiles)
		if probeErr != nil || summary == nil || !summary.Available {
			reason := "JavaCodeDB 未就绪，未能对 Java 二进制包完成反编译类与入口深度提取"
			if probeErr != nil {
				reason = fmt.Sprintf("JavaCodeDB 深度提取失败: %v", probeErr)
			} else if summary != nil && strings.TrimSpace(summary.UnavailableReason) != "" {
				reason = summary.UnavailableReason
			}
			res.Entities = append(res.Entities, extractedEntity{
				EntityType: "module",
				Name:       version.Name + " (JavaCodeDB)",
				CodebaseID: version.CodebaseID,
				VersionID:  version.ID,
				Gap:        true,
				GapReason:  reason,
			})
			res.Claims = append(res.Claims, extractedClaim{
				Subject:            modSubject,
				Relation:           "java_binary_deep_index",
				ObjectValue:        "unavailable",
				SourceType:         pgdb.ClaimSourceStaticExtraction,
				EvidenceKind:       pgdb.EvidenceManual,
				EvidenceRef:        version.Name,
				EvidencePayload:    map[string]any{"reason": reason},
				ValidCodeVersion:   version.ID,
				ConfirmationStatus: pgdb.ClaimStatusUnknown,
			})
		} else {
			for _, cls := range summary.ApplicationClasses {
				ref := taskJavaCodeDBSourcePath(cls.Artifact, cls.Entry)
				if ref == "" {
					ref = cls.ClassName
				}
				res.Claims = append(res.Claims, extractedClaim{
					Subject:          modSubject,
					Relation:         "has_application_class",
					ObjectValue:      cls.ClassName,
					SourceType:       pgdb.ClaimSourceStaticExtraction,
					EvidenceKind:     pgdb.EvidenceDecompiled,
					EvidenceRef:      ref,
					EvidencePayload:  map[string]any{"class_name": cls.ClassName, "artifact": cls.Artifact, "entry": cls.Entry},
					ValidCodeVersion: version.ID,
				})
			}
			for _, ep := range summary.WebEndpoints {
				method := strings.ToUpper(strings.TrimSpace(ep.Method))
				if method == "" {
					method = "ANY"
				}
				epPath := joinURLPaths("/", ep.Path)
				epName := "HTTP " + method + " " + epPath
				ref := taskJavaCodeDBSourcePath(ep.Artifact, ep.Entry)
				if ref == "" {
					ref = ep.ClassName
				}
				res.Entities = append(res.Entities, extractedEntity{
					EntityType: "entry",
					Name:       epName,
					CodebaseID: version.CodebaseID,
					VersionID:  version.ID,
					Attributes: map[string]any{
						"class_name":  ep.ClassName,
						"method_name": ep.MethodName,
						"artifact":    ep.Artifact,
						"entry":       ep.Entry,
						"module":      modSubject,
						"decompiled":  true,
					},
				})
				res.Claims = append(res.Claims, extractedClaim{
					Subject:          modSubject,
					Relation:         "exposes_entry",
					ObjectValue:      epName,
					SourceType:       pgdb.ClaimSourceStaticExtraction,
					EvidenceKind:     pgdb.EvidenceDecompiled,
					EvidenceRef:      ref,
					EvidencePayload:  map[string]any{"class_name": ep.ClassName, "method_name": ep.MethodName, "path": epPath},
					ValidCodeVersion: version.ID,
				})
			}
		}
	}

	return res
}

func (s *Server) queryJavaCodeDBForProfile(ctx context.Context, taskID, versionDir string, version taskCodebaseVersion, artifactPath string, classFiles []string) (*javaBinaryProfileSummary, error) {
	if s != nil && s.javaCodeDBProfileProbe != nil {
		return s.javaCodeDBProfileProbe(ctx, versionDir, version)
	}
	cfg := s.probeJavaCodeDB()
	if !cfg.Ready {
		return &javaBinaryProfileSummary{
			Available:         false,
			UnavailableReason: taskJavaCodeDBNotice(cfg),
		}, nil
	}
	taskNum, _ := strconv.ParseInt(taskID, 10, 64)
	codebase := &taskCodeAuditCodebase{
		TaskID:           taskNum,
		ArchivePath:      artifactPath,
		ArchiveKind:      version.Format,
		ArchiveName:      version.Name,
		ScopePath:        ".",
		BinaryClassFiles: classFiles,
		BinaryOnlyAudit:  true,
		ArtifactName:     version.Name,
		ArtifactFormat:   version.Format,
	}
	workspace, err := s.prepareTaskJavaCodeDBWorkspace(codebase, 0, version)
	if err != nil {
		return nil, err
	}
	client, err := startTaskJavaCodeDB(ctx, cfg, workspace)
	if err != nil {
		return nil, err
	}
	defer client.close()
	if _, err := client.waitForIndex(ctx); err != nil {
		return nil, err
	}

	summary := &javaBinaryProfileSummary{Available: true}
	if out, err := client.callTool(ctx, "list_classes", map[string]any{"limit": 100, "offset": 0, "scope": "application"}); err == nil {
		var page taskJavaCodeDBClassList
		if json.Unmarshal([]byte(out), &page) == nil {
			for _, c := range page.Classes {
				summary.ApplicationClasses = append(summary.ApplicationClasses, javaBinaryClassSummary{
					ClassName:   c.ClassName,
					Artifact:    c.Artifact,
					Entry:       c.Entry,
					Application: c.Application,
				})
			}
		}
	}
	if out, err := client.callTool(ctx, "list_web_endpoints", map[string]any{"limit": 100, "offset": 0}); err == nil {
		var epResp struct {
			Endpoints []struct {
				HTTPMethod string `json:"httpMethod"`
				Method     string `json:"method"`
				Path       string `json:"path"`
				ClassName  string `json:"className"`
				MethodName string `json:"methodName"`
				Artifact   string `json:"artifact"`
				Entry      string `json:"entry"`
			} `json:"endpoints"`
		}
		if json.Unmarshal([]byte(out), &epResp) == nil {
			for _, ep := range epResp.Endpoints {
				m := ep.HTTPMethod
				if m == "" {
					m = ep.Method
				}
				summary.WebEndpoints = append(summary.WebEndpoints, javaBinaryEndpointSummary{
					Method:     m,
					Path:       ep.Path,
					ClassName:  ep.ClassName,
					MethodName: ep.MethodName,
					Artifact:   ep.Artifact,
					Entry:      ep.Entry,
				})
			}
		}
	}
	return summary, nil
}

func readZipEntryBounded(zf *zip.File, limit int64) ([]byte, error) {
	if zf.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("entry exceeds limit")
	}
	rc, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("entry exceeds limit")
	}
	return data, nil
}

func extractManifestFacts(res *codebaseExtractionResult, evRef, modSubject, body string, version taskCodebaseVersion, hasBootOrWeb *bool) {
	res.Entities = append(res.Entities, extractedEntity{
		EntityType: "config", Name: evRef, CodebaseID: version.CodebaseID, VersionID: version.ID,
		Attributes: map[string]any{"kind": "manifest", "module": modSubject},
	})
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	for i, line := range lines {
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		if v == "" {
			continue
		}
		switch strings.ToLower(k) {
		case "main-class", "start-class":
			*hasBootOrWeb = true
			res.Claims = append(res.Claims, extractedClaim{
				Subject: modSubject, Relation: "entrypoint_class", ObjectValue: v,
				SourceType: pgdb.ClaimSourceStaticExtraction, EvidenceKind: pgdb.EvidenceConfig,
				EvidenceRef: fmt.Sprintf("%s:%d", evRef, i+1), EvidencePayload: map[string]any{"line": i + 1, "key": k, "value": v},
				ValidCodeVersion: version.ID, ValidConfig: "META-INF/MANIFEST.MF",
			})
		case "spring-boot-version":
			*hasBootOrWeb = true
			res.Claims = append(res.Claims, extractedClaim{
				Subject: modSubject, Relation: "framework", ObjectValue: "Spring Boot",
				SourceType: pgdb.ClaimSourceStaticExtraction, EvidenceKind: pgdb.EvidenceConfig,
				EvidenceRef: fmt.Sprintf("%s:%d", evRef, i+1), EvidencePayload: map[string]any{"line": i + 1, "spring_boot_version": v},
				ValidCodeVersion: version.ID, ValidConfig: "META-INF/MANIFEST.MF",
			})
		}
	}
}

func extractWebXMLFacts(res *codebaseExtractionResult, evRef, modSubject, body string, version taskCodebaseVersion) {
	res.Entities = append(res.Entities, extractedEntity{
		EntityType: "config", Name: evRef, CodebaseID: version.CodebaseID, VersionID: version.ID,
		Attributes: map[string]any{"kind": "web.xml", "module": modSubject},
	})
	urls := webXMLURLPatternPat.FindAllStringSubmatch(body, 64)
	names := webXMLServletNamePat.FindAllStringSubmatch(body, 64)
	filters := webXMLFilterNamePat.FindAllStringSubmatch(body, 32)
	var seen []string
	for _, m := range urls {
		if len(m) == 2 {
			seen = append(seen, strings.TrimSpace(m[1]))
		}
	}
	sort.Strings(seen)
	for _, p := range uniqueSorted(seen) {
		epName := "HTTP ANY " + joinURLPaths("/", p)
		res.Entities = append(res.Entities, extractedEntity{
			EntityType: "entry", Name: epName, CodebaseID: version.CodebaseID, VersionID: version.ID,
			Attributes: map[string]any{"source": evRef, "module": modSubject},
		})
		res.Claims = append(res.Claims, extractedClaim{
			Subject: modSubject, Relation: "exposes_entry", ObjectValue: epName,
			SourceType: pgdb.ClaimSourceStaticExtraction, EvidenceKind: pgdb.EvidenceConfig,
			EvidenceRef: evRef, EvidencePayload: map[string]any{"url_pattern": p, "servlets": len(names)},
			ValidCodeVersion: version.ID, ValidConfig: "WEB-INF/web.xml",
		})
	}
	for _, fm := range filters {
		if len(fm) == 2 {
			res.Claims = append(res.Claims, extractedClaim{
				Subject: modSubject, Relation: "has_auth_filter", ObjectValue: strings.TrimSpace(fm[1]),
				SourceType: pgdb.ClaimSourceStaticExtraction, EvidenceKind: pgdb.EvidenceConfig,
				EvidenceRef: evRef, EvidencePayload: map[string]any{"filter": strings.TrimSpace(fm[1])},
				ValidCodeVersion: version.ID, ValidConfig: "WEB-INF/web.xml",
			})
		}
	}
}
