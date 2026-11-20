package server

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

const (
	maxMaterialInspectFiles       = 20000
	maxMaterialUnclassifiedSample = 20
	maxMaterialNestedArchiveBytes = int64(64 << 20)
	maxMaterialClassInspectBytes  = int64(4 << 20)
	minJavaClassFileBytes         = 10
	minJavaClassMajorVersion      = 45
)

func (s *Server) probeJavaCodeDB() taskJavaCodeDBConfig {
	if s != nil && s.javaCodeDBProbe != nil {
		return s.javaCodeDBProbe()
	}
	return configuredTaskJavaCodeDB()
}

type materialCodebaseDiskVersion struct {
	version    taskCodebaseVersion
	versionDir string
}

// loadTaskLatestCodebases reads every version directory for taskID, flags any
// corrupt or missing manifests explicitly, and returns the latest version per
// distinct CodebaseID sorted deterministically.
func (s *Server) loadTaskLatestCodebases(taskID string) (latest []materialCodebaseDiskVersion, broken []string, err error) {
	rootPath := s.m.taskCodebaseRoot(taskID)
	if err := ensureTaskCodebaseDirectories(rootPath, false); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	entries, err := os.ReadDir(rootPath)
	if err != nil {
		return nil, nil, err
	}
	all := make([]materialCodebaseDiskVersion, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".upload-") {
			continue
		}
		if !validCodebaseVersionID(entry.Name()) {
			continue
		}
		versionDir := filepath.Join(rootPath, entry.Name())
		info, lerr := os.Lstat(versionDir)
		if lerr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			broken = append(broken, fmt.Sprintf("代码库目录不可读：%s", entry.Name()))
			continue
		}
		manifestPath := filepath.Join(versionDir, taskCodebaseManifestName)
		mInfo, merr := os.Lstat(manifestPath)
		if merr != nil || !mInfo.Mode().IsRegular() || mInfo.Mode()&os.ModeSymlink != 0 {
			broken = append(broken, fmt.Sprintf("代码库版本 %s 缺少 manifest.json", entry.Name()))
			continue
		}
		data, rerr := os.ReadFile(manifestPath)
		if rerr != nil {
			broken = append(broken, fmt.Sprintf("无法读取代码库版本 %s 清单：%v", entry.Name(), rerr))
			continue
		}
		var ver taskCodebaseVersion
		if uerr := json.Unmarshal(data, &ver); uerr != nil || ver.ID != entry.Name() {
			broken = append(broken, fmt.Sprintf("代码库版本 %s manifest.json 损坏", entry.Name()))
			continue
		}
		if ver.CodebaseID == "" {
			ver.CodebaseID = taskCodebaseIdentityID(taskID, ver.Kind, ver.Name)
		}
		all = append(all, materialCodebaseDiskVersion{version: ver, versionDir: versionDir})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].version.CreatedAt.Equal(all[j].version.CreatedAt) {
			return all[i].version.ID > all[j].version.ID
		}
		return all[i].version.CreatedAt.After(all[j].version.CreatedAt)
	})
	seen := make(map[string]bool, len(all))
	for _, item := range all {
		if seen[item.version.CodebaseID] {
			continue
		}
		seen[item.version.CodebaseID] = true
		latest = append(latest, item)
	}
	sort.Slice(latest, func(i, j int) bool {
		if latest[i].version.Name != latest[j].version.Name {
			return latest[i].version.Name < latest[j].version.Name
		}
		return latest[i].version.CodebaseID < latest[j].version.CodebaseID
	})
	return latest, broken, nil
}

func (s *Server) evaluateTaskMaterials(taskID string, t *Task) db.MaterialCheckReport {
	now := time.Now().UTC()
	lifecycle := t.lifecycleSnapshot()
	cfg := lifecycle.AssessmentConfig
	_ = db.NormalizeAndValidateAssessmentConfig(&cfg)

	execMode := cfg.ExecutionMode
	if execMode == "" {
		execMode = db.AssessmentExecDynamic
	}
	standardVersion := db.AssessmentStandardDynamic
	if execMode == db.AssessmentExecOffline {
		standardVersion = db.AssessmentStandardOffline
	}

	report := db.MaterialCheckReport{
		CheckedAt:          &now,
		ConfigDigest:       cfg.ConfigDigest(),
		ExecutionMode:      execMode,
		StandardVersion:    standardVersion,
		SourceAcknowledged: cfg.SourceAcknowledged,
	}

	addBlocker := func(kind, target, msg string) {
		report.Blockers = append(report.Blockers, msg)
		report.Gaps = append(report.Gaps, db.MaterialGap{
			Kind:     kind,
			Severity: "blocker",
			Target:   target,
			Message:  msg,
		})
	}
	addWarning := func(kind, target, msg string) {
		report.Warnings = append(report.Warnings, msg)
		report.Gaps = append(report.Gaps, db.MaterialGap{
			Kind:     kind,
			Severity: "warning",
			Target:   target,
			Message:  msg,
		})
	}

	latest, brokenVersions, listErr := s.loadTaskLatestCodebases(taskID)
	if listErr != nil {
		addBlocker("codebase", taskID, fmt.Sprintf("读取代码库目录失败: %v", listErr))
	}
	for _, msg := range brokenVersions {
		addBlocker("codebase", taskID, msg)
	}

	codebaseHash := sha256.New()
	discoveryByVersion := s.latestDiscoveryStatusMap(taskID)

	var contentFailures []string
	for _, entry := range latest {
		fmt.Fprintf(codebaseHash, "%s|%s|%d\n", entry.version.CodebaseID, entry.version.ID, entry.version.TotalSize)
		inv := inspectCodebaseMaterialVersion(entry.versionDir, entry.version)
		if st, ok := discoveryByVersion[entry.version.ID]; ok {
			inv.DiscoveryStatus = st
		}
		report.Codebases = append(report.Codebases, inv)
		if inv.NeedsJavaCodeDB {
			report.JavaCodeDBRequired = true
		}
		if inv.BlockingError != "" {
			contentFailures = append(contentFailures, fmt.Sprintf("%s: %s", inv.Name, inv.BlockingError))
			addBlocker("package", inv.Name, fmt.Sprintf("%s: %s", inv.Name, inv.BlockingError))
		}
		if len(inv.InvalidCodeFiles) > 0 && inv.BlockingError == "" {
			msg := fmt.Sprintf("%s 包含 %d 个损坏或非文本伪装源码文件（示例: %s）",
				inv.Name, len(inv.InvalidCodeFiles), strings.Join(limitSample(inv.InvalidCodeFiles, 3), ", "))
			addWarning("unreadable", inv.Name, msg)
		}
		if len(inv.UnreadableEntries) > 0 && inv.BlockingError == "" {
			msg := fmt.Sprintf("%s 存在 %d 个不可读取条目（示例: %s）",
				inv.Name, len(inv.UnreadableEntries), strings.Join(limitSample(inv.UnreadableEntries, 3), ", "))
			addWarning("unreadable", inv.Name, msg)
		}
		if inv.UnclassifiedCount > 0 && inv.BlockingError == "" {
			msg := fmt.Sprintf("%s 存在 %d 个未分类文件，将继续跟踪避免静默遗漏（示例: %s）",
				inv.Name, inv.UnclassifiedCount, strings.Join(limitSample(inv.UnclassifiedFiles, 3), ", "))
			addWarning("unclassified", inv.Name, msg)
		}
	}
	report.CodebaseDigest = hex.EncodeToString(codebaseHash.Sum(nil))

	// Item 1: codebases existence
	if len(latest) == 0 && len(brokenVersions) == 0 {
		msg := "尚未挂载任何代码库或软件包"
		addBlocker("codebase", taskID, msg)
		report.Items = append(report.Items, db.MaterialCheckItem{
			Key: "codebases", Status: "fail", Summary: msg, Blocking: true,
		})
	} else if len(latest) > 0 && len(brokenVersions) == 0 {
		report.Items = append(report.Items, db.MaterialCheckItem{
			Key:     "codebases",
			Status:  "pass",
			Summary: fmt.Sprintf("已挂载 %d 份代码/软件包版本", len(latest)),
		})
	} else {
		report.Items = append(report.Items, db.MaterialCheckItem{
			Key:      "codebases",
			Status:   "fail",
			Summary:  fmt.Sprintf("存在 %d 份损坏的代码库版本记录", len(brokenVersions)),
			Detail:   strings.Join(brokenVersions, "; "),
			Blocking: true,
		})
	}

	// Item 2: package & source contents inspect
	if len(contentFailures) > 0 {
		report.Items = append(report.Items, db.MaterialCheckItem{
			Key:      "package_contents",
			Status:   "fail",
			Summary:  "代码内容或归档包校验未通过",
			Detail:   strings.Join(contentFailures, "; "),
			Blocking: true,
		})
	} else if len(latest) > 0 {
		totalSrc, totalCls := 0, 0
		for _, c := range report.Codebases {
			totalSrc += c.ValidSourceFiles
			totalCls += c.ValidClassFiles
		}
		status := "pass"
		detail := ""
		if len(report.Gaps) > 0 {
			status = "warn"
			var parts []string
			for _, g := range report.Gaps {
				if g.Severity == "warning" {
					parts = append(parts, g.Message)
				}
			}
			detail = strings.Join(parts, "; ")
		}
		report.Items = append(report.Items, db.MaterialCheckItem{
			Key:     "package_contents",
			Status:  status,
			Summary: fmt.Sprintf("已验证 %d 个有效源码文件、%d 个有效字节码文件", totalSrc, totalCls),
			Detail:  detail,
		})
	}

	// Item 3: JavaCodeDB availability when binary-only Java packages exist
	if report.JavaCodeDBRequired {
		jcfg := s.probeJavaCodeDB()
		report.JavaCodeDBReady = jcfg.Ready
		if !jcfg.Ready {
			msg := strings.TrimSpace(jcfg.Notice)
			if msg == "" {
				msg = "存在纯字节码 Java 包且当前 JavaCodeDB 未就绪，无法反编译分析"
			}
			addBlocker("java_code_db", "JavaCodeDB", msg)
			report.Items = append(report.Items, db.MaterialCheckItem{
				Key: "java_code_db", Status: "fail", Summary: "JavaCodeDB 未就绪", Detail: msg, Blocking: true,
			})
		} else {
			report.Items = append(report.Items, db.MaterialCheckItem{
				Key:     "java_code_db",
				Status:  "pass",
				Summary: fmt.Sprintf("JavaCodeDB 已就绪（%s）", firstNonEmpty(jcfg.Version, "available")),
			})
		}
	} else {
		report.Items = append(report.Items, db.MaterialCheckItem{
			Key: "java_code_db", Status: "not_applicable", Summary: "当前材料均含源码或非纯 Java 字节码包，无需依赖 JavaCodeDB",
		})
	}

	// Item 4: environment vs explicit offline standard
	if execMode == db.AssessmentExecOffline {
		report.Items = append(report.Items, db.MaterialCheckItem{
			Key:     "environment",
			Status:  "not_applicable",
			Summary: "已显式选择离线审计模式（whitebox-offline-v1），不强制要求动态环境地址",
		})
	} else {
		gwHost := s.llmHost()
		var invalidEnvs []string
		for _, env := range cfg.Environments {
			canon, _, hostOrIP, ok := db.ParseAssessmentEnvironmentTarget(env.URL)
			if !ok {
				invalidEnvs = append(invalidEnvs, fmt.Sprintf("环境地址无效: %q", env.URL))
				continue
			}
			if gwHost != "" && strings.EqualFold(hostOrIP, gwHost) {
				invalidEnvs = append(invalidEnvs, fmt.Sprintf("环境地址 %q 与内置 LLM 网关冲突，不能作为评估目标", env.URL))
				continue
			}
			report.ValidEnvironmentURLs = append(report.ValidEnvironmentURLs, canon)
		}
		if len(cfg.Environments) == 0 {
			msg := "联调评估模式至少需要配置 1 个有效目标环境地址；若仅做离线审计，请切换 execution_mode=offline"
			addBlocker("environment", "environments", msg)
			report.Items = append(report.Items, db.MaterialCheckItem{
				Key: "environment", Status: "fail", Summary: msg, Blocking: true,
			})
		} else if len(invalidEnvs) > 0 {
			msg := strings.Join(invalidEnvs, "; ")
			addBlocker("environment", "environments", msg)
			report.Items = append(report.Items, db.MaterialCheckItem{
				Key: "environment", Status: "fail", Summary: "目标环境配置校验失败", Detail: msg, Blocking: true,
			})
		} else {
			report.Items = append(report.Items, db.MaterialCheckItem{
				Key:     "environment",
				Status:  "pass",
				Summary: fmt.Sprintf("已校验 %d 个目标环境入口", len(report.ValidEnvironmentURLs)),
				Detail:  strings.Join(report.ValidEnvironmentURLs, ", "),
			})
		}
	}

	// Item 5: LLM profile readiness (warning only, consistent with ARTeX queued/idle LLM behavior)
	report.LLMReady = s.engine != nil && s.engine.ReadyFor(t)
	if report.LLMReady {
		report.Items = append(report.Items, db.MaterialCheckItem{
			Key: "llm_profile", Status: "pass", Summary: "任务可用 LLM 模型配置已就绪",
		})
	} else {
		msg := "当前未解析到可用 LLM 模型配置，正式启动后任务将等待或进入队列直到模型可用"
		addWarning("llm", "llm_profile", msg)
		report.Items = append(report.Items, db.MaterialCheckItem{
			Key: "llm_profile", Status: "warn", Summary: msg,
		})
	}

	// Item 6: outbound source acknowledgement visibility (enforced on Start)
	if cfg.SourceAcknowledged {
		report.Items = append(report.Items, db.MaterialCheckItem{
			Key: "source_ack", Status: "pass", Summary: "已确认源码可发送至所选 LLM 进行白盒分析",
		})
	} else {
		report.Items = append(report.Items, db.MaterialCheckItem{
			Key: "source_ack", Status: "warn", Summary: "尚未确认外发源码声明（正式启动前必须确认 source_acknowledged=true）",
		})
	}

	report.Ready = len(report.Blockers) == 0
	if report.Ready {
		if len(report.Warnings) > 0 {
			report.Summary = fmt.Sprintf("材料检查通过（含 %d 条提醒），可确认外发并显式启动", len(report.Warnings))
		} else {
			report.Summary = "材料检查全部通过，可确认外发并显式启动"
		}
	} else {
		report.Summary = fmt.Sprintf("材料检查未通过，存在 %d 项阻断问题：%s", len(report.Blockers), report.Blockers[0])
	}
	return report
}

func (s *Server) latestDiscoveryStatusMap(taskID string) map[string]string {
	out := map[string]string{}
	if s.m == nil || s.m.pg == nil {
		return out
	}
	num, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil || num <= 0 {
		return out
	}
	_, runs, err := s.m.pg.ListTaskCodeServices(num)
	if err != nil {
		return out
	}
	for _, r := range runs {
		if _, exists := out[r.VersionID]; !exists {
			out[r.VersionID] = r.Status
		}
	}
	return out
}

func inspectCodebaseMaterialVersion(versionDir string, version taskCodebaseVersion) db.MaterialCodebaseInventory {
	inv := db.MaterialCodebaseInventory{
		CodebaseID: version.CodebaseID,
		VersionID:  version.ID,
		Name:       version.Name,
		Kind:       version.Kind,
	}
	contentsDir := filepath.Join(versionDir, "contents")
	cInfo, err := os.Lstat(contentsDir)
	if err != nil || !cInfo.IsDir() || cInfo.Mode()&os.ModeSymlink != 0 {
		inv.Deployability = "unreadable"
		inv.BlockingError = "代码库内容目录缺失或不可读取"
		return inv
	}

	langSeen := map[string]bool{}
	hasBuild := false
	visitedFiles := 0

	walkErr := filepath.WalkDir(contentsDir, func(p string, d fs.DirEntry, wErr error) error {
		if wErr != nil {
			inv.UnreadableEntries = append(inv.UnreadableEntries, p)
			return nil
		}
		if p == contentsDir {
			return nil
		}
		relFS, err := filepath.Rel(contentsDir, p)
		if err != nil {
			inv.UnreadableEntries = append(inv.UnreadableEntries, p)
			return nil
		}
		rel := filepath.ToSlash(relFS)
		lInfo, err := os.Lstat(p)
		if err != nil {
			inv.UnreadableEntries = append(inv.UnreadableEntries, rel)
			return nil
		}
		if lInfo.Mode()&os.ModeSymlink != 0 {
			inv.UnreadableEntries = append(inv.UnreadableEntries, rel)
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			var mixed taskCodeAuditMixedAdapter
			if mixed.PruneDirectory(".", rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if !lInfo.Mode().IsRegular() {
			inv.UnreadableEntries = append(inv.UnreadableEntries, rel)
			return nil
		}
		visitedFiles++
		if visitedFiles > maxMaterialInspectFiles {
			return nil
		}

		lower := strings.ToLower(rel)
		if archiveFmt, isArch := detectMaterialArchiveFormat(lower); isArch {
			if err := inspectArchiveFileForMaterial(p, rel, archiveFmt, &inv, langSeen, &hasBuild); err != nil {
				inv.UnreadableEntries = append(inv.UnreadableEntries, rel)
				inv.Warnings = append(inv.Warnings, fmt.Sprintf("归档 %s 不可解析: %v", rel, err))
				if version.Kind == "artifact" {
					inv.BlockingError = fmt.Sprintf("归档包无法读取或已损坏: %v", err)
				}
			}
			return nil
		}

		if strings.HasSuffix(lower, ".class") {
			data, oversized, rerr := readBoundedRegularFile(p, maxMaterialClassInspectBytes)
			if rerr != nil {
				inv.UnreadableEntries = append(inv.UnreadableEntries, rel)
				return nil
			}
			if oversized || !isValidJavaClassBytes(data) {
				inv.InvalidCodeFiles = append(inv.InvalidCodeFiles, rel)
				if version.Kind == "artifact" && inv.BlockingError == "" {
					inv.BlockingError = fmt.Sprintf("无效的 Java class 字节码文件 (%s)", rel)
				}
				return nil
			}
			inv.ValidClassFiles++
			langSeen["java"] = true
			return nil
		}

		oversized := lInfo.Size() > taskCodeAuditMaxFileBytes
		if oversized {
			// Check whether it is an eligible source/template file so huge/corrupt blobs are reported clearly.
			if matched, kind, _ := matchRegisteredAuditFile(rel, nil); len(matched) > 0 && kind != "" {
				inv.InvalidCodeFiles = append(inv.InvalidCodeFiles, rel)
			} else {
				inv.UnreadableEntries = append(inv.UnreadableEntries, rel)
			}
			return nil
		}
		data, tooBig, rerr := readBoundedRegularFile(p, taskCodeAuditMaxFileBytes)
		if rerr != nil || tooBig {
			inv.UnreadableEntries = append(inv.UnreadableEntries, rel)
			return nil
		}
		classifyInspectedFileContent(rel, data, &inv, langSeen, &hasBuild)
		return nil
	})
	if walkErr != nil && inv.BlockingError == "" {
		inv.Deployability = "unreadable"
		inv.BlockingError = fmt.Sprintf("遍历代码目录失败: %v", walkErr)
		return inv
	}

	for lang := range langSeen {
		inv.Languages = append(inv.Languages, lang)
	}
	sort.Strings(inv.Languages)

	if inv.BlockingError != "" {
		inv.Deployability = "unreadable"
		return inv
	}
	if inv.ValidSourceFiles == 0 && inv.ValidClassFiles == 0 {
		if len(inv.UnreadableEntries) > 0 && len(inv.InvalidCodeFiles) == 0 {
			inv.Deployability = "unreadable"
			inv.BlockingError = fmt.Sprintf("归档或文件不可读取（示例: %s）", strings.Join(limitSample(inv.UnreadableEntries, 3), ", "))
			return inv
		}
		inv.Deployability = "empty"
		var details []string
		if len(inv.InvalidCodeFiles) > 0 {
			details = append(details, fmt.Sprintf("%d 个无效/伪装/空源码文件 (%s)", len(inv.InvalidCodeFiles), strings.Join(limitSample(inv.InvalidCodeFiles, 3), ", ")))
		}
		if inv.UnclassifiedCount > 0 {
			details = append(details, fmt.Sprintf("%d 个未分类文件 (%s)", inv.UnclassifiedCount, strings.Join(limitSample(inv.UnclassifiedFiles, 3), ", ")))
		}
		if len(inv.UnreadableEntries) > 0 {
			details = append(details, fmt.Sprintf("%d 个不可读条目 (%s)", len(inv.UnreadableEntries), strings.Join(limitSample(inv.UnreadableEntries, 3), ", ")))
		}
		if len(details) > 0 {
			inv.BlockingError = "未发现有效可审计源码或 Java 字节码文件：" + strings.Join(details, "；")
		} else {
			inv.BlockingError = "代码库未包含任何有效可审计源码或 Java 字节码文件"
		}
		return inv
	}

	if inv.ValidSourceFiles == 0 && inv.ValidClassFiles > 0 {
		inv.Deployability = "binary_only"
		inv.NeedsJavaCodeDB = true
		return inv
	}
	if hasBuild || version.Format == "jar" || version.Format == "war" {
		inv.Deployability = "deployable"
		return inv
	}
	inv.Deployability = "auditable_library"
	return inv
}

func detectMaterialArchiveFormat(lowerName string) (string, bool) {
	switch {
	case strings.HasSuffix(lowerName, ".tar.gz"), strings.HasSuffix(lowerName, ".tgz"):
		return "tar.gz", true
	case strings.HasSuffix(lowerName, ".zip"):
		return "zip", true
	case strings.HasSuffix(lowerName, ".jar"):
		return "jar", true
	case strings.HasSuffix(lowerName, ".war"):
		return "war", true
	case strings.HasSuffix(lowerName, ".tar"):
		return "tar", true
	default:
		return "", false
	}
}

func readBoundedRegularFile(path string, maxBytes int64) ([]byte, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maxBytes {
		return nil, true, nil
	}
	return data, false, nil
}

func isValidJavaClassBytes(data []byte) bool {
	if len(data) < minJavaClassFileBytes {
		return false
	}
	if data[0] != 0xca || data[1] != 0xfe || data[2] != 0xba || data[3] != 0xbe {
		return false
	}
	major := binary.BigEndian.Uint16(data[6:8])
	return major >= minJavaClassMajorVersion
}

func inspectArchiveFileForMaterial(archivePath, archiveRel, format string, inv *db.MaterialCodebaseInventory, langSeen map[string]bool, hasBuild *bool) error {
	switch format {
	case "zip", "jar", "war":
		if format == "jar" || format == "war" {
			langSeen["java"] = true
		}
		r, err := zip.OpenReader(archivePath)
		if err != nil {
			return err
		}
		defer r.Close()
		return inspectZipEntriesForMaterial(r.File, archiveRel, format, inv, langSeen, hasBuild, 0)
	case "tar", "tar.gz":
		f, err := os.Open(archivePath)
		if err != nil {
			return err
		}
		defer f.Close()
		var tr *tar.Reader
		if format == "tar.gz" {
			gz, err := gzip.NewReader(f)
			if err != nil {
				return err
			}
			defer gz.Close()
			tr = tar.NewReader(gz)
		} else {
			tr = tar.NewReader(f)
		}
		return inspectTarEntriesForMaterial(tr, archiveRel, inv, langSeen, hasBuild)
	default:
		return fmt.Errorf("unsupported archive format %q", format)
	}
}

func inspectZipEntriesForMaterial(files []*zip.File, parentRel, parentFmt string, inv *db.MaterialCodebaseInventory, langSeen map[string]bool, hasBuild *bool, depth int) error {
	for i, f := range files {
		if i >= maxMaterialInspectFiles {
			break
		}
		if f.FileInfo().IsDir() {
			continue
		}
		cleanName, err := safeTaskCodebaseArchivePath(f.Name, false)
		if err != nil {
			inv.UnreadableEntries = append(inv.UnreadableEntries, path.Join(parentRel, f.Name))
			continue
		}
		entryPath := cleanName
		if parentRel != "" {
			entryPath = path.Join(parentRel, cleanName)
		}
		lower := strings.ToLower(cleanName)
		// Check nested jar/war inside WAR WEB-INF/lib or fat JAR BOOT-INF/lib cleanly.
		if depth == 0 && (strings.HasSuffix(lower, ".jar") || strings.HasSuffix(lower, ".war")) {
			if f.UncompressedSize64 > uint64(maxMaterialNestedArchiveBytes) {
				inv.UnreadableEntries = append(inv.UnreadableEntries, entryPath)
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return err
			}
			nestedBytes, rerr := io.ReadAll(io.LimitReader(rc, maxMaterialNestedArchiveBytes+1))
			closeErr := rc.Close()
			if rerr != nil || closeErr != nil || int64(len(nestedBytes)) > maxMaterialNestedArchiveBytes {
				inv.UnreadableEntries = append(inv.UnreadableEntries, entryPath)
				continue
			}
			nzr, zerr := zip.NewReader(bytes.NewReader(nestedBytes), int64(len(nestedBytes)))
			if zerr != nil {
				inv.UnreadableEntries = append(inv.UnreadableEntries, entryPath)
				continue
			}
			inv.NestedArchiveFiles++
			langSeen["java"] = true
			if parentFmt == "war" || parentFmt == "jar" {
				*hasBuild = true
			}
			_ = inspectZipEntriesForMaterial(nzr.File, entryPath, "jar", inv, langSeen, hasBuild, depth+1)
			continue
		}
		if strings.HasSuffix(lower, ".class") {
			if f.UncompressedSize64 > uint64(maxMaterialClassInspectBytes) {
				inv.InvalidCodeFiles = append(inv.InvalidCodeFiles, entryPath)
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return err
			}
			data, rerr := io.ReadAll(io.LimitReader(rc, maxMaterialClassInspectBytes+1))
			closeErr := rc.Close()
			if rerr != nil || closeErr != nil || int64(len(data)) > maxMaterialClassInspectBytes || !isValidJavaClassBytes(data) {
				inv.InvalidCodeFiles = append(inv.InvalidCodeFiles, entryPath)
				continue
			}
			inv.ValidClassFiles++
			langSeen["java"] = true
			continue
		}
		// Normalize nested package roots (WEB-INF/classes/..., BOOT-INF/classes/...) before language classification.
		normalizedRel := stripArchiveCodePrefix(cleanName)
		if f.UncompressedSize64 > uint64(taskCodeAuditMaxFileBytes) {
			if matched, kind, _ := matchRegisteredAuditFile(normalizedRel, nil); len(matched) > 0 && kind != "" {
				inv.InvalidCodeFiles = append(inv.InvalidCodeFiles, entryPath)
			}
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		data, rerr := io.ReadAll(io.LimitReader(rc, taskCodeAuditMaxFileBytes+1))
		closeErr := rc.Close()
		if rerr != nil || closeErr != nil || int64(len(data)) > taskCodeAuditMaxFileBytes {
			inv.UnreadableEntries = append(inv.UnreadableEntries, entryPath)
			continue
		}
		classifyInspectedFileContentWithLabel(normalizedRel, entryPath, data, inv, langSeen, hasBuild)
	}
	return nil
}

func inspectTarEntriesForMaterial(tr *tar.Reader, parentRel string, inv *db.MaterialCodebaseInventory, langSeen map[string]bool, hasBuild *bool) error {
	count := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		count++
		if count > maxMaterialInspectFiles {
			break
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink {
			inv.UnreadableEntries = append(inv.UnreadableEntries, path.Join(parentRel, hdr.Name))
			continue
		}
		cleanName, perr := safeTaskCodebaseArchivePath(hdr.Name, false)
		if perr != nil {
			inv.UnreadableEntries = append(inv.UnreadableEntries, path.Join(parentRel, hdr.Name))
			continue
		}
		entryPath := path.Join(parentRel, cleanName)
		lower := strings.ToLower(cleanName)
		if strings.HasSuffix(lower, ".class") {
			data, err := io.ReadAll(io.LimitReader(tr, maxMaterialClassInspectBytes+1))
			if err != nil || int64(len(data)) > maxMaterialClassInspectBytes || !isValidJavaClassBytes(data) {
				inv.InvalidCodeFiles = append(inv.InvalidCodeFiles, entryPath)
				continue
			}
			inv.ValidClassFiles++
			langSeen["java"] = true
			continue
		}
		if hdr.Size > taskCodeAuditMaxFileBytes {
			if matched, kind, _ := matchRegisteredAuditFile(cleanName, nil); len(matched) > 0 && kind != "" {
				inv.InvalidCodeFiles = append(inv.InvalidCodeFiles, entryPath)
			}
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, taskCodeAuditMaxFileBytes+1))
		if err != nil || int64(len(data)) > taskCodeAuditMaxFileBytes {
			inv.UnreadableEntries = append(inv.UnreadableEntries, entryPath)
			continue
		}
		classifyInspectedFileContentWithLabel(cleanName, entryPath, data, inv, langSeen, hasBuild)
	}
	return nil
}

func stripArchiveCodePrefix(rel string) string {
	for _, prefix := range []string{"WEB-INF/classes/", "BOOT-INF/classes/"} {
		if strings.HasPrefix(rel, prefix) {
			return strings.TrimPrefix(rel, prefix)
		}
	}
	return rel
}

func classifyInspectedFileContent(rel string, data []byte, inv *db.MaterialCodebaseInventory, langSeen map[string]bool, hasBuild *bool) {
	classifyInspectedFileContentWithLabel(rel, rel, data, inv, langSeen, hasBuild)
}

func classifyInspectedFileContentWithLabel(rel, displayPath string, data []byte, inv *db.MaterialCodebaseInventory, langSeen map[string]bool, hasBuild *bool) {
	matchedLangs, kind, buildLangs := matchRegisteredAuditFile(rel, data)
	if len(buildLangs) > 0 {
		*hasBuild = true
		for _, l := range buildLangs {
			langSeen[l] = true
		}
	}
	if len(matchedLangs) > 0 && (kind == "source" || kind == "template") {
		if !isValidTextCodeContent(rel, data) {
			inv.InvalidCodeFiles = append(inv.InvalidCodeFiles, displayPath)
			return
		}
		if kind == "source" {
			inv.ValidSourceFiles++
		} else {
			inv.ValidTemplateFiles++
		}
		for _, l := range matchedLangs {
			langSeen[l] = true
		}
		return
	}
	if len(buildLangs) > 0 || isKnownNonCodeRepoFile(rel) {
		return
	}
	inv.UnclassifiedCount++
	if len(inv.UnclassifiedFiles) < maxMaterialUnclassifiedSample {
		inv.UnclassifiedFiles = append(inv.UnclassifiedFiles, displayPath)
	}
}

func matchRegisteredAuditFile(rel string, body []byte) (langs []string, kind string, buildLangs []string) {
	for _, adapter := range taskCodeAuditLanguages() {
		k, ok := adapter.ClassifyFile(".", rel)
		if ok && (kind == "" || kind == "template") {
			kind = k
		}
		if ok {
			langs = append(langs, adapter.Language())
		}
		if adapter.DiscoveryFile(rel, body).Build {
			buildLangs = append(buildLangs, adapter.Language())
		}
	}
	return langs, kind, buildLangs
}

func isValidTextCodeContent(rel string, data []byte) bool {
	if bytes.IndexByte(data, 0) >= 0 {
		return false
	}
	if !utf8.Valid(data) {
		return false
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return strings.EqualFold(path.Base(rel), "__init__.py")
	}
	return true
}

func isKnownNonCodeRepoFile(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	if base == "readme" || strings.HasPrefix(base, "readme.") ||
		base == "license" || strings.HasPrefix(base, "license.") ||
		base == "changelog" || strings.HasPrefix(base, "changelog.") ||
		base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") ||
		base == ".gitignore" || strings.HasPrefix(base, ".git") ||
		base == ".editorconfig" || base == ".env.example" ||
		base == "web.xml" || base == "manifest.mf" {
		return true
	}
	switch strings.ToLower(path.Ext(base)) {
	case ".md", ".yaml", ".yml", ".json", ".xml", ".properties", ".conf", ".ini", ".toml", ".cfg", ".sql", ".css", ".scss", ".less", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf":
		return true
	default:
		return false
	}
}

func limitSample(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	return items[:n]
}

// ---------- Unified Creation, Draft Update, Check, and Start Flows ----------

func (s *Server) createTaskUnified(projectID int64, req createTaskReq, parentRef string) (*Task, int, error) {
	if projectID <= 0 {
		return nil, http.StatusBadRequest, errors.New("project_id is required")
	}
	if req.AssessmentMode {
		if err := db.NormalizeAndValidateAssessmentConfig(&req.AssessmentConfig); err != nil {
			return nil, http.StatusBadRequest, err
		}
		if strings.TrimSpace(req.Description) == "" {
			if req.AssessmentConfig.BusinessOverview != "" {
				req.Description = req.AssessmentConfig.BusinessOverview
			} else if strings.TrimSpace(req.Name) != "" {
				req.Description = strings.TrimSpace(req.Name)
			} else {
				req.Description = "未命名评估任务"
			}
		} else if req.AssessmentConfig.BusinessOverview == "" {
			req.AssessmentConfig.BusinessOverview = strings.TrimSpace(req.Description)
		}
		// Whitebox assessment tasks are ALWAYS created as persisted drafts first unless
		// created strictly for low-level internal helpers; explicit Start unlocks them.
		draftVal := true
		if req.Draft == nil {
			req.Draft = &draftVal
		}
	} else {
		if strings.TrimSpace(req.Description) == "" {
			req.Description = "未命名任务"
		}
	}

	if len(req.LLMProfileIDs) == 0 && req.LLMProfileID != nil {
		req.LLMProfileIDs = []int64{*req.LLMProfileID}
	}
	if err := s.validateTaskProfileIDs(req.LLMProfileIDs); err != nil {
		return nil, http.StatusBadRequest, err
	}
	if err := db.NormalizeNoResultOptions(&db.TaskCreateOptions{
		NoResultSeconds:     req.NoResultSeconds,
		NoResultMinFindings: req.NoResultMinFindings,
		NoResultMinSeverity: req.NoResultMinSeverity,
	}); err != nil {
		return nil, http.StatusBadRequest, err
	}
	if req.TimeoutSeconds < 0 {
		req.TimeoutSeconds = 0
	}
	if len(req.SourceTaskIDs) > db.MaxTaskSourceCount {
		return nil, http.StatusBadRequest, fmt.Errorf("关联任务最多选择 %d 个", db.MaxTaskSourceCount)
	}
	sourceIDs := make([]int64, 0, len(req.SourceTaskIDs))
	seenSources := map[int64]bool{}
	for _, raw := range req.SourceTaskIDs {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || id <= 0 || seenSources[id] {
			return nil, http.StatusBadRequest, errors.New("关联任务 id 无效或重复")
		}
		if _, ok := s.m.Task(strconv.FormatInt(id, 10)); !ok {
			return nil, http.StatusBadRequest, fmt.Errorf("关联任务 #%d 不存在", id)
		}
		seenSources[id] = true
		sourceIDs = append(sourceIDs, id)
	}
	companyIDs, err := db.NormalizeTaskCompanyIDs(req.CompanyIDs)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("关联企业无效：最多选择 %d 个有效企业", db.MaxTaskCompanyCount)
	}
	interceptRules, err := buildTaskInterceptRules(req.InterceptRules)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("任务级拦截规则无效：%v", err)
	}
	var schedule *db.TaskScheduleInput
	if req.Schedule != nil {
		input := s.scheduleInput(projectID, *req.Schedule, nil)
		input.TaskIDs = nil
		if err := db.ValidateTaskScheduleInput(input); err != nil {
			return nil, http.StatusBadRequest, err
		}
		schedule = &input
	}
	remark, err := normalizeRemark(req.Remark)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	if req.WorkerCount < 0 {
		return nil, http.StatusBadRequest, errors.New("Worker 运行数量不能为负数")
	}
	if req.WorkerCount > db.MaxTaskWorkerCount {
		return nil, http.StatusBadRequest, fmt.Errorf("Worker 运行数量最多 %d", db.MaxTaskWorkerCount)
	}

	isDraft := req.AssessmentMode && (req.Draft == nil || *req.Draft)
	phase := ""
	if req.AssessmentMode {
		phase = db.AssessmentPhaseMaterialCheck
	}

	t, err := s.m.CreateTaskWithOptions(req.Description, req.Goal, db.TaskCreateOptions{
		ProjectID: projectID,
		Schedule:  schedule,
		Name:      strings.TrimSpace(req.Name), CategoryID: req.CategoryID,
		SourceTaskIDs: sourceIDs, CompanyIDs: companyIDs, LLMProfileIDs: req.LLMProfileIDs,
		NoResultSeconds: req.NoResultSeconds, NoResultMinFindings: req.NoResultMinFindings, NoResultMinSeverity: req.NoResultMinSeverity,
		TimeoutSeconds: req.TimeoutSeconds, PlanHeartbeatSeconds: req.PlanHeartbeatSeconds,
		CoverageEnabled:   req.CoverageEnabled,
		ShareGlobalAssets: req.ShareGlobalAssets,
		Remark:            remark,
		WorkerCount:       req.WorkerCount,
		InterceptRules:    interceptRules,
		AssessmentMode:    req.AssessmentMode,
		AssessmentPhase:   phase,
		Draft:             isDraft,
		AssessmentConfig:  req.AssessmentConfig,
	})
	if err != nil {
		if errors.Is(err, db.ErrTaskCategoryInvalid) || errors.Is(err, db.ErrTaskCategoryNotFound) {
			return nil, http.StatusBadRequest, errors.New("任务分类不存在或无效")
		}
		if errors.Is(err, db.ErrTaskCompanyIDsInvalid) || errors.Is(err, db.ErrTaskCompanyNotFound) {
			return nil, http.StatusBadRequest, errors.New("关联企业不存在或无效")
		}
		if errors.Is(err, db.ErrAssessmentSecretRejected) {
			return nil, http.StatusBadRequest, err
		}
		return nil, http.StatusBadRequest, err
	}
	if parentRef != "" {
		t.ParentRef = parentRef
		if id, e := strconv.ParseInt(t.ID, 10, 64); e == nil && s.m != nil && s.m.PG() != nil {
			_ = s.m.PG().SetParentRef(id, parentRef)
		}
	}

	if !t.IsDraft() {
		log.Printf("[task] 新建任务 #%s «%s» 目标: %s", t.ID, req.Description, req.Goal)
		if schedule == nil || schedule.StartImmediately {
			s.launchTask(t, req.Description+" "+req.Goal, req.SeedFirstIntent != nil && *req.SeedFirstIntent)
		} else {
			s.engine.Pause(t.ID, agent.AbortPausedBySchedule)
		}
	} else {
		log.Printf("[task] 新建白盒评估草稿 #%s «%s»", t.ID, t.Name)
	}
	return t, http.StatusCreated, nil
}

type updateTaskDraftReq struct {
	Name                 *string              `json:"name,omitempty"`
	Remark               *string              `json:"remark,omitempty"`
	CategoryID           *int64               `json:"category_id,omitempty"`
	ClearCategory        bool                 `json:"clear_category,omitempty"`
	Description          *string              `json:"description,omitempty"`
	Goal                 *string              `json:"goal,omitempty"`
	SourceTaskIDs        *[]string            `json:"source_task_ids,omitempty"`
	CompanyIDs           *[]int64             `json:"company_ids,omitempty"`
	LLMProfileIDs        *[]int64             `json:"llm_profile_ids,omitempty"`
	TimeoutSeconds       *int                 `json:"timeout_seconds,omitempty"`
	NoResultSeconds      *int                 `json:"no_result_seconds,omitempty"`
	NoResultMinFindings  *int                 `json:"no_result_min_findings,omitempty"`
	NoResultMinSeverity  *string              `json:"no_result_min_severity,omitempty"`
	PlanHeartbeatSeconds *int                 `json:"plan_heartbeat_seconds,omitempty"`
	CoverageEnabled      *bool                `json:"coverage_enabled,omitempty"`
	ShareGlobalAssets    *bool                `json:"share_global_assets,omitempty"`
	WorkerCount          *int                 `json:"worker_count,omitempty"`
	AssessmentConfig     *db.AssessmentConfig `json:"assessment_config,omitempty"`
}

func (s *Server) updateTaskDraftUnified(taskID string, req updateTaskDraftReq) (*Task, int, error) {
	t, ok := s.m.Task(taskID)
	if !ok {
		return nil, http.StatusNotFound, errors.New("task not found")
	}
	if !t.AssessmentMode {
		return nil, http.StatusBadRequest, db.ErrTaskNotAssessmentMode
	}
	if !t.IsDraft() {
		return nil, http.StatusConflict, db.ErrTaskNotDraft
	}

	var patch db.AssessmentDraftPatch
	patch.Name = req.Name
	patch.Remark = req.Remark
	if req.ClearCategory {
		patch.SetCategory = true
		patch.CategoryID = nil
	} else if req.CategoryID != nil {
		patch.SetCategory = true
		patch.CategoryID = req.CategoryID
	}
	patch.Description = req.Description
	patch.Goal = req.Goal
	patch.TimeoutSeconds = req.TimeoutSeconds
	patch.NoResultSeconds = req.NoResultSeconds
	patch.NoResultMinFindings = req.NoResultMinFindings
	patch.NoResultMinSeverity = req.NoResultMinSeverity
	patch.PlanHeartbeatSeconds = req.PlanHeartbeatSeconds
	patch.CoverageEnabled = req.CoverageEnabled
	patch.ShareGlobalAssets = req.ShareGlobalAssets
	patch.WorkerCount = req.WorkerCount
	patch.CompanyIDs = req.CompanyIDs
	patch.Config = req.AssessmentConfig

	if req.SourceTaskIDs != nil {
		if len(*req.SourceTaskIDs) > db.MaxTaskSourceCount {
			return nil, http.StatusBadRequest, fmt.Errorf("关联任务最多选择 %d 个", db.MaxTaskSourceCount)
		}
		ids := make([]int64, 0, len(*req.SourceTaskIDs))
		seen := map[int64]bool{}
		for _, raw := range *req.SourceTaskIDs {
			id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
			if err != nil || id <= 0 || seen[id] || strconv.FormatInt(id, 10) == taskID {
				return nil, http.StatusBadRequest, errors.New("关联任务 id 无效或重复")
			}
			if _, ok := s.m.Task(strconv.FormatInt(id, 10)); !ok {
				return nil, http.StatusBadRequest, fmt.Errorf("关联任务 #%d 不存在", id)
			}
			seen[id] = true
			ids = append(ids, id)
		}
		patch.SourceTaskIDs = &ids
	}
	if req.LLMProfileIDs != nil {
		if err := s.validateTaskProfileIDs(*req.LLMProfileIDs); err != nil {
			return nil, http.StatusBadRequest, err
		}
		patch.LLMProfileIDs = req.LLMProfileIDs
	}

	updated, err := s.m.UpdateAssessmentDraft(taskID, patch)
	if err != nil {
		if errors.Is(err, db.ErrTaskNotDraft) {
			return nil, http.StatusConflict, err
		}
		return nil, http.StatusBadRequest, err
	}
	if updated == nil {
		return nil, http.StatusNotFound, errors.New("task not found")
	}
	return updated, http.StatusOK, nil
}

func (s *Server) runTaskMaterialCheck(taskID string) (*Task, db.MaterialCheckReport, int, error) {
	t, ok := s.m.Task(taskID)
	if !ok {
		return nil, db.MaterialCheckReport{}, http.StatusNotFound, errors.New("task not found")
	}
	if !t.AssessmentMode {
		return nil, db.MaterialCheckReport{}, http.StatusBadRequest, db.ErrTaskNotAssessmentMode
	}
	if !t.IsDraft() {
		return t, t.lifecycleSnapshot().MaterialCheck, http.StatusConflict, db.ErrTaskNotDraft
	}
	report := s.evaluateTaskMaterials(taskID, t)
	updated, err := s.m.SaveMaterialCheckReport(taskID, report)
	if err != nil {
		if errors.Is(err, db.ErrTaskNotDraft) {
			return nil, report, http.StatusConflict, err
		}
		return nil, report, http.StatusInternalServerError, err
	}
	if updated == nil {
		return nil, report, http.StatusNotFound, errors.New("task not found")
	}
	return updated, report, http.StatusOK, nil
}

func (s *Server) startAssessmentTaskUnified(taskID string, sourceAcknowledged bool) (*Task, *db.AssessmentRound, db.MaterialCheckReport, int, error) {
	t, ok := s.m.Task(taskID)
	if !ok {
		return nil, nil, db.MaterialCheckReport{}, http.StatusNotFound, errors.New("task not found")
	}
	if !t.AssessmentMode {
		return nil, nil, db.MaterialCheckReport{}, http.StatusBadRequest, db.ErrTaskNotAssessmentMode
	}
	if !t.IsDraft() {
		return nil, nil, db.MaterialCheckReport{}, http.StatusConflict, errors.New("任务已启动，不能重复执行草稿启动")
	}
	if s.engine.IsDeleting(taskID) {
		return nil, nil, db.MaterialCheckReport{}, http.StatusConflict, errors.New("任务正在删除，无法启动")
	}

	// Re-run material check synchronously right before start so deleted/tampered
	// files or invalidated environments can never bypass readiness gates.
	checkedTask, report, code, err := s.runTaskMaterialCheck(taskID)
	if err != nil {
		return nil, nil, report, code, err
	}
	t = checkedTask
	if !report.Ready {
		return nil, nil, report, http.StatusConflict, fmt.Errorf("%w: %s", db.ErrDraftMaterialNotReady, report.Summary)
	}
	cfg := t.lifecycleSnapshot().AssessmentConfig
	if !cfg.SourceAcknowledged && !sourceAcknowledged {
		return nil, nil, report, http.StatusBadRequest, db.ErrSourceNotAcknowledged
	}

	var entities []db.CreateTargetEntityInput
	for _, cb := range report.Codebases {
		etype := "module"
		switch cb.Deployability {
		case "deployable":
			etype = "service"
		case "auditable_library":
			etype = "shared_library"
		case "binary_only":
			etype = "service"
		}
		attrs, _ := json.Marshal(map[string]any{
			"languages":          cb.Languages,
			"deployability":      cb.Deployability,
			"valid_source_files": cb.ValidSourceFiles,
			"valid_class_files":  cb.ValidClassFiles,
			"needs_java_code_db": cb.NeedsJavaCodeDB,
		})
		entities = append(entities, db.CreateTargetEntityInput{
			EntityType: etype,
			Name:       cb.Name,
			CodebaseID: cb.CodebaseID,
			VersionID:  cb.VersionID,
			Attributes: attrs,
		})
	}
	for _, gap := range report.Gaps {
		if gap.Severity != "warning" {
			continue
		}
		if gap.Kind == "unclassified" || gap.Kind == "unreadable" {
			entities = append(entities, db.CreateTargetEntityInput{
				EntityType: "module",
				Name:       gap.Target,
				Gap:        true,
				GapReason:  gap.Message,
			})
		}
	}

	envDigest := sha256String(strings.Join(report.ValidEnvironmentURLs, ","))
	scopeDigest := sha256String(cfg.ScopeNotes + "|" + fmt.Sprintf("%v", t.lifecycleSnapshot().CompanyIDs))

	startedTask, round, err := s.m.StartAssessmentTask(taskID, db.AssessmentStartInput{
		Report:             report,
		SourceAcknowledged: true,
		CodebaseEntities:   entities,
		CodebaseVersion:    report.CodebaseDigest,
		EnvironmentVersion: envDigest,
		ScopeVersion:       scopeDigest,
		StandardVersion:    report.StandardVersion,
	})
	if err != nil {
		if errors.Is(err, db.ErrSourceNotAcknowledged) {
			return nil, nil, report, http.StatusBadRequest, err
		}
		if errors.Is(err, db.ErrTaskNotDraft) || errors.Is(err, db.ErrDraftMaterialNotReady) {
			return nil, nil, report, http.StatusConflict, err
		}
		return nil, nil, report, http.StatusInternalServerError, err
	}
	if startedTask == nil {
		return nil, nil, report, http.StatusNotFound, errors.New("task not found")
	}

	s.launchTask(startedTask, "", false)
	log.Printf("[assessment] 任务 #%s 正式启动：round=%d, mode=%s, phase=%s",
		startedTask.ID, round.RoundNo, report.StandardVersion, startedTask.lifecycleSnapshot().AssessmentPhase)
	return startedTask, round, startedTask.lifecycleSnapshot().MaterialCheck, http.StatusOK, nil
}

func sha256String(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func (s *Server) seedAssessmentEnvironmentAssets(t *Task) {
	if t == nil || t.ProjectID <= 0 {
		return
	}
	lifecycle := t.lifecycleSnapshot()
	if lifecycle.AssessmentConfig.ExecutionMode == db.AssessmentExecOffline {
		return
	}
	as := s.m.Assets(t.ProjectID)
	if as == nil {
		return
	}
	taskNum, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || taskNum <= 0 {
		return
	}
	gwHost := s.llmHost()
	for _, env := range lifecycle.AssessmentConfig.Environments {
		canon, kind, hostOrIP, ok := db.ParseAssessmentEnvironmentTarget(env.URL)
		if !ok || (gwHost != "" && strings.EqualFold(hostOrIP, gwHost)) {
			continue
		}
		var rootID int64
		if strings.HasPrefix(canon, "http://") || strings.HasPrefix(canon, "https://") {
			rootID, _ = as.UpsertHTTPService(db.UpsertHTTPServiceReq{URL: canon, TaskID: taskNum})
		} else if kind == "ip" {
			rootID, _ = as.UpsertIP(db.UpsertIPReq{IP: hostOrIP, TaskID: taskNum})
		} else {
			rootID, _ = as.UpsertRootDomain(db.UpsertRootDomainReq{Domain: hostOrIP, TaskID: taskNum})
		}
		if rootID > 0 {
			_ = as.SetTaskAssetSource(taskNum, rootID, "task", "由白盒评估目标环境配置初始化", nil)
		}
	}
}

// ---------- HTTP Handlers for Draft Update, Material Check, and Start ----------

// PATCH /api/tasks/{id}/draft
func (s *Server) updateTaskDraftHandler(w http.ResponseWriter, r *http.Request) {
	taskNum, ok := s.requireTaskInProject(w, r, r.PathValue("id"), true)
	if !ok {
		return
	}
	var req updateTaskDraftReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	taskID := strconv.FormatInt(taskNum, 10)
	updated, code, err := s.updateTaskDraftUnified(taskID, req)
	if err != nil {
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, taskDTO(updated, s.resolvedTaskStatus(updated)))
}

// POST /api/tasks/{id}/material-check
func (s *Server) materialCheckHandler(w http.ResponseWriter, r *http.Request) {
	taskNum, ok := s.requireTaskInProject(w, r, r.PathValue("id"), true)
	if !ok {
		return
	}
	taskID := strconv.FormatInt(taskNum, 10)
	updated, report, code, err := s.runTaskMaterialCheck(taskID)
	if err != nil {
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"task":   taskDTO(updated, s.resolvedTaskStatus(updated)),
		"report": report,
	})
}

// POST /api/tasks/{id}/start
func (s *Server) startAssessmentTaskHandler(w http.ResponseWriter, r *http.Request) {
	taskNum, ok := s.requireTaskInProject(w, r, r.PathValue("id"), true)
	if !ok {
		return
	}
	var req struct {
		SourceAcknowledged bool `json:"source_acknowledged"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
			return
		}
	}
	taskID := strconv.FormatInt(taskNum, 10)
	started, round, report, code, err := s.startAssessmentTaskUnified(taskID, req.SourceAcknowledged)
	if err != nil {
		if errors.Is(err, db.ErrDraftMaterialNotReady) {
			writeJSON(w, code, map[string]any{
				"error":  err.Error(),
				"report": report,
			})
			return
		}
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"task":   taskDTO(started, s.resolvedTaskStatus(started)),
		"round":  round,
		"report": report,
	})
}
