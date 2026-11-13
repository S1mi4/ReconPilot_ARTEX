package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	taskJavaDecompilerEnv      = "ARTEX_VINEFLOWER_JAR"
	taskJavaExecutableEnv      = "ARTEX_JAVA_BIN"
	taskJavaDecompilerName     = "Vineflower"
	taskJavaDecompilerTimeout  = 5 * time.Minute
	taskJavaDecompilerMaxHeap  = "-Xmx1g"
	taskJavaDecompilerLogLimit = 64 << 10
)

type taskJavaDecompilerConfig struct {
	JavaPath string
	JarPath  string
	JarHash  string
	Version  string
	Ready    bool
	Notice   string
}

type taskCodeAuditProvenanceLocation struct {
	ReconstructedFile string `json:"reconstructed_file"`
	OriginalClassFile string `json:"original_class_file"`
	Package           string `json:"package"`
	Class             string `json:"class"`
	Method            string `json:"method"`
}

type taskCodeAuditProvenance struct {
	Decompiler       string                          `json:"decompiler"`
	DecompilerSHA256 string                          `json:"decompiler_sha256"`
	ArtifactName     string                          `json:"artifact_name"`
	ArtifactFormat   string                          `json:"artifact_format"`
	ArtifactSHA256   string                          `json:"artifact_sha256"`
	Source           taskCodeAuditProvenanceLocation `json:"source"`
	Sink             taskCodeAuditProvenanceLocation `json:"sink"`
}

type taskCodeAuditClassOrigin struct {
	Entry string
	Inner bool
}

var javaVersionPattern = regexp.MustCompile(`(?im)^\s*(?:openjdk|java)\s+(?:version\s*)?["']?(\d+)(?:\.(\d+))?`)
var javaPackagePattern = regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*;`)

func configuredTaskJavaDecompiler() taskJavaDecompilerConfig {
	jarPath := strings.TrimSpace(os.Getenv(taskJavaDecompilerEnv))
	if jarPath == "" {
		return taskJavaDecompilerConfig{Notice: "二进制审计未配置反编译器；请设置 ARTEX_VINEFLOWER_JAR 并提供 Java 17 或更高版本。"}
	}
	if !filepath.IsAbs(jarPath) {
		return taskJavaDecompilerConfig{Notice: "ARTEX_VINEFLOWER_JAR 必须是 Vineflower JAR 的绝对路径。"}
	}
	jarInfo, err := os.Stat(jarPath)
	if err != nil || !jarInfo.Mode().IsRegular() {
		return taskJavaDecompilerConfig{Notice: "ARTEX_VINEFLOWER_JAR 必须指向可读的普通文件。"}
	}
	jar, err := os.Open(jarPath)
	if err != nil {
		return taskJavaDecompilerConfig{Notice: "无法读取已配置的 Vineflower JAR。"}
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, jar); err != nil {
		_ = jar.Close()
		return taskJavaDecompilerConfig{Notice: "无法校验已配置的 Vineflower JAR。"}
	}
	if err := jar.Close(); err != nil {
		return taskJavaDecompilerConfig{Notice: "无法关闭已配置的 Vineflower JAR。"}
	}

	javaPath := strings.TrimSpace(os.Getenv(taskJavaExecutableEnv))
	if javaPath == "" {
		javaPath = "java"
	}
	resolvedJava, err := exec.LookPath(javaPath)
	if err != nil {
		return taskJavaDecompilerConfig{JarPath: jarPath, Notice: "找不到 Java 运行时；请设置 ARTEX_JAVA_BIN 或将 Java 17+ 加入 PATH。"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, resolvedJava, "-version")
	cmd.Env = restrictedTaskDecompilerEnvironment(os.TempDir())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return taskJavaDecompilerConfig{JavaPath: resolvedJava, JarPath: jarPath, Notice: "无法读取 Java 运行时版本；二进制审计已停用。"}
	}
	version, major, ok := parseTaskJavaVersion(string(output))
	if !ok || major < 17 {
		return taskJavaDecompilerConfig{JavaPath: resolvedJava, JarPath: jarPath, Notice: "Vineflower 需要 Java 17 或更高版本；当前运行时不满足要求。"}
	}
	return taskJavaDecompilerConfig{
		JavaPath: resolvedJava,
		JarPath:  jarPath,
		JarHash:  hex.EncodeToString(hash.Sum(nil)),
		Version:  version,
		Ready:    true,
	}
}

func parseTaskJavaVersion(output string) (string, int, bool) {
	match := javaVersionPattern.FindStringSubmatch(strings.TrimSpace(output))
	if len(match) < 3 {
		return "", 0, false
	}
	major, err := strconv.Atoi(match[1])
	if err != nil {
		return "", 0, false
	}
	if major == 1 {
		major, err = strconv.Atoi(match[2])
		if err != nil {
			return "", 0, false
		}
	}
	version := match[1]
	if match[2] != "" {
		version += "." + match[2]
	}
	return version, major, true
}

func (c *taskCodeAuditCodebase) decompileBinary(ctx context.Context, config taskJavaDecompilerConfig) error {
	if len(c.BinaryClassFiles) == 0 {
		return errors.New("代码包中没有可反编译的 Java class 文件")
	}
	if !config.Ready {
		if config.Notice != "" {
			return errors.New(config.Notice)
		}
		return errors.New("Vineflower 未配置")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	workDir, err := os.MkdirTemp("", "artex-java-audit-")
	if err != nil {
		return fmt.Errorf("create decompiler workspace: %w", err)
	}
	c.TempDir = workDir
	outputDir := filepath.Join(workDir, "decompiled")
	if err := os.Mkdir(outputDir, 0o750); err != nil {
		return fmt.Errorf("create decompiler output: %w", err)
	}
	inputInfo, err := os.Lstat(c.ArchivePath)
	if err != nil || !inputInfo.Mode().IsRegular() || inputInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("binary artifact is not a regular file")
	}
	inputHash, err := sha256File(c.ArchivePath)
	if err != nil {
		return fmt.Errorf("hash binary artifact: %w", err)
	}
	c.ArtifactSHA256 = inputHash
	c.DecompilerName = taskJavaDecompilerName
	c.DecompilerSHA256 = config.JarHash

	ctx, cancel := context.WithTimeout(ctx, taskJavaDecompilerTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, config.JavaPath, taskJavaDecompilerMaxHeap, "-jar", config.JarPath,
		"--folder", "--skip-extra-files=1", c.ArchivePath, outputDir)
	cmd.Env = restrictedTaskDecompilerEnvironment(workDir)
	var output limitedTaskDecompilerOutput
	output.limit = taskJavaDecompilerLogLimit
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("Vineflower decompilation stopped: %w", ctx.Err())
		}
		message := strings.TrimSpace(output.String())
		if message != "" {
			return fmt.Errorf("Vineflower decompilation failed: %w: %s", err, message)
		}
		return fmt.Errorf("Vineflower decompilation failed: %w", err)
	}
	return c.collectDecompiledFiles(outputDir)
}

func (c *taskCodeAuditCodebase) collectDecompiledFiles(outputDir string) error {
	origins := make(map[string]taskCodeAuditClassOrigin, len(c.BinaryClassFiles))
	directClass := c.ArchiveKind == "class" && len(c.BinaryClassFiles) == 1
	for _, entry := range c.BinaryClassFiles {
		rel := entry
		if c.ArchiveKind != "class" && c.ArchivePrefix != "" {
			rel = strings.TrimPrefix(rel, c.ArchivePrefix)
		}
		key, inner, ok := normalizedTaskClassSourcePath(rel)
		if !ok {
			continue
		}
		if current, exists := origins[key]; exists {
			if current.Inner && !inner {
				origins[key] = taskCodeAuditClassOrigin{Entry: entry}
			} else if current.Entry != entry && current.Inner == inner {
				origins[key] = taskCodeAuditClassOrigin{Entry: ""}
			}
			continue
		}
		origins[key] = taskCodeAuditClassOrigin{Entry: entry, Inner: inner}
	}

	type javaOutput struct {
		path string
		disk string
		size int64
	}
	javaFiles := make([]javaOutput, 0)
	err := filepath.WalkDir(outputDir, func(filename string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filename == outputDir {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".java") || !entry.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(outputDir, filename)
		if err != nil {
			return err
		}
		if _, err := safeTaskCodebasePath(filepath.ToSlash(rel)); err != nil {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() < 0 || info.Size() > taskCodeAuditMaxFileBytes || len(javaFiles) >= maxTaskCodebaseFiles {
			c.Skipped++
			return nil
		}
		javaFiles = append(javaFiles, javaOutput{path: filepath.ToSlash(rel), disk: filename, size: info.Size()})
		return nil
	})
	if err != nil {
		return fmt.Errorf("read Vineflower output: %w", err)
	}
	added := 0
	for _, file := range javaFiles {
		keyPath := file.path
		if c.ArchivePrefix != "" {
			keyPath = strings.TrimPrefix(keyPath, c.ArchivePrefix)
		}
		key, _, ok := normalizedTaskClassSourcePath(keyPath)
		if !ok {
			continue
		}
		origin, found := origins[key]
		if !found && directClass && len(javaFiles) == 1 {
			origin = taskCodeAuditClassOrigin{Entry: c.BinaryClassFiles[0]}
			found = true
		}
		if !found || origin.Entry == "" {
			continue
		}
		if len(c.Files) >= maxTaskCodebaseFiles {
			c.Skipped++
			continue
		}
		if _, err := safeTaskCodebasePath(file.path); err != nil {
			continue
		}
		if _, exists := c.ByPath[file.path]; exists {
			continue
		}
		fileEntry := taskCodeAuditFile{Path: file.path, Kind: "java", Size: file.size, Disk: file.disk}
		c.Files = append(c.Files, fileEntry)
		c.ByPath[file.path] = fileEntry
		c.ProvenanceByPath[file.path] = newTaskCodeAuditProvenanceLocation(file.path, origin.Entry, taskAuditJavaPackage(file.disk))
		added++
	}
	if added == 0 || countAuditProductionFiles(c.Files) == 0 {
		return errors.New("Vineflower did not produce auditable Java sources for the selected class files")
	}
	sortTaskCodeAuditFiles(c.Files)
	return nil
}

func normalizedTaskClassSourcePath(filename string) (string, bool, bool) {
	rel := filepath.ToSlash(strings.TrimSpace(filename))
	rel = strings.TrimPrefix(rel, "./")
	rel = strings.TrimPrefix(rel, "/")
	for _, prefix := range []string{"BOOT-INF/classes/", "WEB-INF/classes/"} {
		rel = strings.TrimPrefix(rel, prefix)
	}
	if strings.HasPrefix(rel, "META-INF/versions/") {
		parts := strings.SplitN(rel, "/", 4)
		if len(parts) == 4 && parts[2] != "" {
			rel = parts[3]
		}
	}
	ext := strings.ToLower(path.Ext(rel))
	if ext != ".class" && ext != ".java" {
		return "", false, false
	}
	base := path.Base(rel)
	inner := false
	if ext == ".class" {
		if index := strings.IndexByte(base, '$'); index >= 0 {
			base = base[:index] + ".java"
			inner = true
		} else {
			base = strings.TrimSuffix(base, path.Ext(base)) + ".java"
		}
	} else {
		base = strings.TrimSuffix(base, path.Ext(base)) + ".java"
	}
	dir := path.Dir(rel)
	if dir == "." {
		rel = base
	} else {
		rel = path.Join(dir, base)
	}
	clean := path.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", false, false
	}
	return clean, inner, true
}

func newTaskCodeAuditProvenanceLocation(reconstructed, original, reconstructedPackage string) taskCodeAuditProvenanceLocation {
	classPath := strings.ReplaceAll(filepath.ToSlash(reconstructed), "\\", "/")
	classPath = strings.TrimSuffix(classPath, path.Ext(classPath))
	classPath = strings.ReplaceAll(classPath, "$", ".")
	packageName := path.Dir(classPath)
	if packageName == "." {
		packageName = ""
	} else {
		packageName = strings.ReplaceAll(packageName, "/", ".")
	}
	if reconstructedPackage != "" {
		packageName = reconstructedPackage
	}
	className := path.Base(classPath)
	originalClassName := strings.TrimSuffix(path.Base(filepath.ToSlash(original)), path.Ext(original))
	if index := strings.IndexByte(originalClassName, '$'); index >= 0 {
		originalClassName = originalClassName[:index] + "." + originalClassName[index+1:]
	}
	if originalClassName == className || strings.HasPrefix(originalClassName, className+".") {
		className = originalClassName
	}
	return taskCodeAuditProvenanceLocation{
		ReconstructedFile: filepath.ToSlash(reconstructed),
		OriginalClassFile: original,
		Package:           packageName,
		Class:             className,
	}
}

func taskAuditJavaPackage(filename string) string {
	file, err := os.Open(filename)
	if err != nil {
		return ""
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, 64<<10))
	if err != nil {
		return ""
	}
	match := javaPackagePattern.FindSubmatch(content)
	if len(match) < 2 {
		return ""
	}
	return string(match[1])
}

func candidateTaskCodeAuditProvenance(candidate taskCodeAuditCandidate, codebase *taskCodeAuditCodebase) (taskCodeAuditProvenance, bool) {
	if codebase == nil || codebase.DecompilerName == "" || codebase.DecompilerSHA256 == "" || codebase.ArtifactSHA256 == "" {
		return taskCodeAuditProvenance{}, false
	}
	source, ok := codebase.ProvenanceByPath[filepath.ToSlash(candidate.Source.File)]
	if !ok {
		return taskCodeAuditProvenance{}, false
	}
	sink, ok := codebase.ProvenanceByPath[filepath.ToSlash(candidate.Sink.File)]
	if !ok {
		return taskCodeAuditProvenance{}, false
	}
	source.Method = taskCodeAuditMethodFromSymbol(candidate.Source.Symbol)
	sink.Method = taskCodeAuditMethodFromSymbol(candidate.Sink.Symbol)
	if source.Method == "" || sink.Method == "" {
		return taskCodeAuditProvenance{}, false
	}
	return taskCodeAuditProvenance{
		Decompiler:       codebase.DecompilerName,
		DecompilerSHA256: codebase.DecompilerSHA256,
		ArtifactName:     codebase.ArtifactName,
		ArtifactFormat:   codebase.ArtifactFormat,
		ArtifactSHA256:   codebase.ArtifactSHA256,
		Source:           source,
		Sink:             sink,
	}, true
}

func taskCodeAuditMethodFromSymbol(symbol string) string {
	symbol = strings.TrimSpace(symbol)
	if index := strings.IndexByte(symbol, '('); index >= 0 {
		symbol = symbol[:index]
	}
	if index := strings.LastIndexByte(symbol, '.'); index >= 0 {
		symbol = symbol[index+1:]
	}
	return strings.TrimSpace(symbol)
}

func (c *taskCodeAuditCodebase) cleanup() {
	if c != nil && c.TempDir != "" {
		_ = os.RemoveAll(c.TempDir)
		c.TempDir = ""
	}
}

func sha256File(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func restrictedTaskDecompilerEnvironment(tempDir string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + tempDir,
		"TMPDIR=" + tempDir,
		"TMP=" + tempDir,
		"TEMP=" + tempDir,
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
	}
}

type limitedTaskDecompilerOutput struct {
	bytes.Buffer
	limit int
}

func (w *limitedTaskDecompilerOutput) Write(p []byte) (int, error) {
	written := len(p)
	if remaining := w.limit - w.Len(); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = w.Buffer.Write(p)
	}
	return written, nil
}

func sortTaskCodeAuditFiles(files []taskCodeAuditFile) {
	// Kept local to the audit package so decompiled inventory order matches source inventory.
	sort.Slice(files, func(i, j int) bool {
		if files[i].Kind != files[j].Kind {
			order := map[string]int{"java": 0, "config": 1, "test": 2, "template": 3}
			return order[files[i].Kind] < order[files[j].Kind]
		}
		return files[i].Path < files[j].Path
	})
}
