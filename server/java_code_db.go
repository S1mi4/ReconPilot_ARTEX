package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/norma/llm"
)

const (
	taskJavaCodeDBJarEnv       = "ARTEX_JAVACODEDB_JAR"
	taskJavaCodeDBStartupLimit = 5 * time.Minute
	taskJavaCodeDBRequestLimit = 2 * time.Minute
	taskJavaCodeDBMaxMessage   = 16 << 20
	taskJavaCodeDBLogLimit     = 64 << 10
)

type taskJavaCodeDBConfig struct {
	JavaPath string
	JarPath  string
	JarHash  string
	Version  string
	Ready    bool
	Notice   string
}

type taskJavaCodeDBClient struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	reader    *bufio.Reader
	lines     chan taskJavaCodeDBLine // filled by one reader goroutine per process
	done      chan struct{}           // closed when the client is shut down
	doneOnce  sync.Once
	stderr    limitedTaskProcessOutput
	wait      chan error
	mu        sync.Mutex
	nextID    int64
	closed    bool
	workspace string
}

type taskJavaCodeDBLine struct {
	line []byte
	err  error
}

// readTaskJavaCodeDBLine reads one newline-terminated message but stops
// accumulating at limit bytes, so an oversized response cannot exhaust memory
// before the size check runs.
func readTaskJavaCodeDBLine(reader *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		if len(line)+len(chunk) > limit {
			return nil, errors.New("JavaCodeDB MCP response exceeds the 16 MiB limit")
		}
		line = append(line, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return line, err
	}
}

func (c *taskJavaCodeDBClient) readLoop() {
	for {
		line, err := readTaskJavaCodeDBLine(c.reader, taskJavaCodeDBMaxMessage)
		select {
		case c.lines <- taskJavaCodeDBLine{line: line, err: err}:
		case <-c.done:
			return
		}
		if err != nil {
			return
		}
	}
}

func (c *taskJavaCodeDBClient) markDone() { c.doneOnce.Do(func() { close(c.done) }) }

// interruptTaskJavaCodeDBProcess asks the JVM to stop; Windows cannot deliver an
// interrupt signal to a child process, so it is killed there.
func interruptTaskJavaCodeDBProcess(process *os.Process) error {
	if runtime.GOOS == "windows" {
		return process.Kill()
	}
	return process.Signal(os.Interrupt)
}

type taskJavaCodeDBRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type taskJavaCodeDBRPCResponse struct {
	ID     json.RawMessage         `json:"id"`
	Method string                  `json:"method"`
	Result json.RawMessage         `json:"result"`
	Error  *taskJavaCodeDBRPCError `json:"error"`
}

type taskJavaCodeDBToolResult struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	IsError bool `json:"isError"`
}

type taskJavaCodeDBClassList struct {
	Total     int64                    `json:"total"`
	Offset    int                      `json:"offset"`
	Limit     int                      `json:"limit"`
	Truncated bool                     `json:"truncated"`
	Classes   []taskJavaCodeDBClassRef `json:"classes"`
}

type taskJavaCodeDBClassSourceResponse struct {
	ClassName string `json:"className"`
	TotalHits int    `json:"totalHits"`
	Results   []struct {
		ClassName       string `json:"className"`
		Artifact        string `json:"artifact"`
		Entry           string `json:"entry"`
		Application     bool   `json:"application"`
		SHA256          string `json:"sha256"`
		SourceLineStart int    `json:"sourceLineStart"`
		SourceLineEnd   int    `json:"sourceLineEnd"`
		TotalLines      int    `json:"totalLines"`
		Source          string `json:"source"`
	} `json:"results"`
}

// taskJavaCodeDBConfigCacheTTL bounds how long a JavaCodeDB probe result is reused.
// The probe hashes the whole JAR and forks a JVM, so it must not run per request.
const taskJavaCodeDBConfigCacheTTL = time.Minute

var taskJavaCodeDBConfigCache struct {
	sync.Mutex
	key    string
	at     time.Time
	config taskJavaCodeDBConfig
}

// resolveTaskJavaCodeDBJarPath finds the JavaCodeDB JAR (env, next to the
// executable, then the embedded copy).
func resolveTaskJavaCodeDBJarPath() string {
	jarPath := strings.TrimSpace(os.Getenv(taskJavaCodeDBJarEnv))
	if jarPath == "" {
		if executable, err := os.Executable(); err == nil {
			candidate := filepath.Join(filepath.Dir(executable), "java-code-db.jar")
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
				jarPath = candidate
			}
		}
	}
	if jarPath == "" {
		if embedded, err := taskJavaCodeDBMaterializedPath(); err == nil {
			jarPath = embedded
		}
	}
	return jarPath
}

// configuredTaskJavaCodeDB returns the JavaCodeDB runtime state, cached by the
// JAR identity (path, size, mtime) and the Java selection for a short time.
func configuredTaskJavaCodeDB() taskJavaCodeDBConfig {
	jarPath := resolveTaskJavaCodeDBJarPath()
	key := jarPath + "\x00" + os.Getenv(taskJavaExecutableEnv) + "\x00" + os.Getenv("PATH")
	if info, err := os.Lstat(jarPath); err == nil {
		key += fmt.Sprintf("\x00%d\x00%d", info.Size(), info.ModTime().UnixNano())
	}
	taskJavaCodeDBConfigCache.Lock()
	defer taskJavaCodeDBConfigCache.Unlock()
	if taskJavaCodeDBConfigCache.key == key && time.Since(taskJavaCodeDBConfigCache.at) < taskJavaCodeDBConfigCacheTTL {
		return taskJavaCodeDBConfigCache.config
	}
	config := probeTaskJavaCodeDB(jarPath)
	taskJavaCodeDBConfigCache.key, taskJavaCodeDBConfigCache.at, taskJavaCodeDBConfigCache.config = key, time.Now(), config
	return config
}

func probeTaskJavaCodeDB(jarPath string) taskJavaCodeDBConfig {
	if jarPath == "" {
		return taskJavaCodeDBConfig{Notice: "二进制审计未找到 JavaCodeDB；请使用集成构建脚本重新构建或设置 ARTEX_JAVACODEDB_JAR。"}
	}
	if !filepath.IsAbs(jarPath) {
		return taskJavaCodeDBConfig{Notice: "ARTEX_JAVACODEDB_JAR 必须是绝对路径。"}
	}
	jarInfo, err := os.Lstat(jarPath)
	if err != nil || !jarInfo.Mode().IsRegular() || jarInfo.Mode()&os.ModeSymlink != 0 {
		return taskJavaCodeDBConfig{Notice: "ARTEX_JAVACODEDB_JAR 必须指向可读的普通文件。"}
	}
	jar, err := os.Open(jarPath)
	if err != nil {
		return taskJavaCodeDBConfig{Notice: "无法读取 JavaCodeDB JAR。"}
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, jar); err != nil {
		_ = jar.Close()
		return taskJavaCodeDBConfig{Notice: "无法校验 JavaCodeDB JAR。"}
	}
	if err := jar.Close(); err != nil {
		return taskJavaCodeDBConfig{Notice: "无法关闭 JavaCodeDB JAR。"}
	}
	javaPath := strings.TrimSpace(os.Getenv(taskJavaExecutableEnv))
	if javaPath == "" {
		javaPath = "java"
	}
	resolvedJava, err := exec.LookPath(javaPath)
	if err != nil {
		return taskJavaCodeDBConfig{JarPath: jarPath, Notice: "找不到 Java 运行时；请设置 ARTEX_JAVA_BIN 或将 Java 21+ 加入 PATH。"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, resolvedJava, "-version")
	cmd.Env = restrictedTaskJavaCodeDBEnvironment(os.TempDir())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return taskJavaCodeDBConfig{JavaPath: resolvedJava, JarPath: jarPath, Notice: "无法读取 Java 运行时版本；JavaCodeDB 二进制审计已停用。"}
	}
	version, major, ok := parseTaskJavaVersion(string(output))
	if !ok || major < 21 {
		return taskJavaCodeDBConfig{JavaPath: resolvedJava, JarPath: jarPath, Notice: "JavaCodeDB 需要 Java 21 或更高版本；当前运行时不满足要求。"}
	}
	return taskJavaCodeDBConfig{
		JavaPath: resolvedJava,
		JarPath:  jarPath,
		JarHash:  hex.EncodeToString(hash.Sum(nil)),
		Version:  version,
		Ready:    true,
	}
}

func taskJavaCodeDBNotice(config taskJavaCodeDBConfig) string {
	if config.Notice != "" {
		return config.Notice
	}
	return "二进制审计需要 JavaCodeDB 和 Java 21 或更高版本。"
}

func startTaskJavaCodeDB(ctx context.Context, config taskJavaCodeDBConfig, workspace string) (*taskJavaCodeDBClient, error) {
	if !config.Ready {
		return nil, errors.New(taskJavaCodeDBNotice(config))
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, config.JavaPath, "-Xmx384m", "-XX:ActiveProcessorCount=2", "-jar", config.JarPath, "--workspace", workspace)
	cmd.Dir = workspace
	cmd.Env = restrictedTaskJavaCodeDBEnvironment(workspace)
	cmd.Env = append(cmd.Env, "JAVACODEDB_INDEX_WORKERS=1", "JAVACODEDB_LUCENE_RAM_BUFFER_MB=16", "JAVACODEDB_CACHE_ENABLED=false")
	cmd.Cancel = func() error { return interruptTaskJavaCodeDBProcess(cmd.Process) }
	cmd.WaitDelay = 5 * time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("open JavaCodeDB stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("open JavaCodeDB stdout: %w", err)
	}
	client := &taskJavaCodeDBClient{cmd: cmd, stdin: stdin, reader: bufio.NewReaderSize(stdout, 64<<10),
		lines: make(chan taskJavaCodeDBLine, 4), done: make(chan struct{}), wait: make(chan error, 1), workspace: workspace}
	client.stderr.limit = taskJavaCodeDBLogLimit
	cmd.Stderr = &client.stderr
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("start JavaCodeDB: %w", err)
	}
	go func() { client.wait <- cmd.Wait() }()
	go client.readLoop()
	initCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var initialized json.RawMessage
	if err := client.request(initCtx, "initialize", map[string]any{
		"protocolVersion": "2025-03-26",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "ARTEX", "version": runtime.Version()},
	}, &initialized); err != nil {
		client.close()
		return nil, fmt.Errorf("initialize JavaCodeDB MCP: %w", err)
	}
	if _, err := client.stdin.Write([]byte("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")); err != nil {
		client.close()
		return nil, fmt.Errorf("complete JavaCodeDB MCP initialization: %w", err)
	}
	return client, nil
}

func (c *taskJavaCodeDBClient) waitForIndex(ctx context.Context) (map[string]any, error) {
	deadline := time.NewTimer(taskJavaCodeDBStartupLimit)
	defer deadline.Stop()
	for {
		callCtx, cancel := context.WithTimeout(ctx, taskJavaCodeDBRequestLimit)
		text, err := c.callTool(callCtx, "get_index_status", map[string]any{})
		cancel()
		if err != nil {
			return nil, err
		}
		var status map[string]any
		if err := json.Unmarshal([]byte(text), &status); err != nil {
			return nil, fmt.Errorf("decode JavaCodeDB index status: %w", err)
		}
		state, _ := status["state"].(string)
		switch state {
		case "ready", "completed_with_errors":
			return status, nil
		case "failed":
			return nil, fmt.Errorf("JavaCodeDB indexing failed: %v", status["recentIssues"])
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, errors.New("JavaCodeDB indexing exceeded the five-minute startup limit")
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (c *taskJavaCodeDBClient) callTool(ctx context.Context, name string, arguments map[string]any) (string, error) {
	var raw json.RawMessage
	if err := c.request(ctx, "tools/call", map[string]any{"name": name, "arguments": arguments}, &raw); err != nil {
		return "", err
	}
	var result taskJavaCodeDBToolResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("decode JavaCodeDB %s response: %w", name, err)
	}
	var text strings.Builder
	for _, content := range result.Content {
		if content.Type == "text" {
			if text.Len() > 0 {
				text.WriteByte('\n')
			}
			text.WriteString(content.Text)
		}
	}
	if result.IsError {
		return text.String(), fmt.Errorf("JavaCodeDB %s failed: %s", name, text.String())
	}
	return text.String(), nil
}

func (c *taskJavaCodeDBClient) request(ctx context.Context, method string, params any, result *json.RawMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("JavaCodeDB MCP process is closed")
	}
	c.nextID++
	id := c.nextID
	payload, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if _, err := c.stdin.Write(payload); err != nil {
		return fmt.Errorf("write JavaCodeDB MCP request: %w", err)
	}
	for {
		select {
		case <-ctx.Done():
			// Stop this MCP process so a timed-out request cannot leave a late response
			// to be mistaken for the next request's answer.
			c.closed = true
			c.markDone()
			_ = c.stdin.Close()
			_ = c.cmd.Process.Kill()
			return ctx.Err()
		case exitErr := <-c.wait:
			c.closed = true
			c.markDone()
			if exitErr == nil {
				return errors.New("JavaCodeDB MCP process exited unexpectedly")
			}
			message := strings.TrimSpace(c.stderr.String())
			if message != "" {
				return fmt.Errorf("JavaCodeDB MCP process exited: %w: %s", exitErr, message)
			}
			return fmt.Errorf("JavaCodeDB MCP process exited: %w", exitErr)
		case response := <-c.lines:
			if response.err != nil {
				// The reader goroutine stops on its first error, so the client is unusable.
				c.closed = true
				c.markDone()
				if errors.Is(response.err, io.EOF) && len(response.line) == 0 {
					return errors.New("JavaCodeDB MCP closed stdout")
				}
				return fmt.Errorf("read JavaCodeDB MCP response: %w", response.err)
			}
			var envelope taskJavaCodeDBRPCResponse
			if err := json.Unmarshal(bytes.TrimSpace(response.line), &envelope); err != nil {
				return fmt.Errorf("decode JavaCodeDB MCP message: %w", err)
			}
			if len(envelope.ID) == 0 || string(envelope.ID) != fmt.Sprint(id) {
				continue
			}
			if envelope.Error != nil {
				return fmt.Errorf("JavaCodeDB MCP %s error %d: %s", method, envelope.Error.Code, envelope.Error.Message)
			}
			if result != nil {
				*result = envelope.Result
			}
			return nil
		}
	}
}

func (c *taskJavaCodeDBClient) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.markDone()
	_, _ = c.stdin.Write([]byte("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/exit\"}\n"))
	_ = c.stdin.Close()
	_ = interruptTaskJavaCodeDBProcess(c.cmd.Process)
	c.mu.Unlock()
	select {
	case <-c.wait:
	case <-time.After(5 * time.Second):
		_ = c.cmd.Process.Kill()
		select {
		case <-c.wait:
		case <-time.After(2 * time.Second):
		}
	}
}

var taskCodeAuditBinaryTools = []llm.ToolSchema{
	{Name: "get_index_status", Description: "查看当前服务 JavaCodeDB 符号索引状态。只读。", InputSchema: map[string]any{"type": "object", "properties": map[string]any{}}},
	{Name: "search_code", Description: "在 JavaCodeDB 索引中搜索类、方法、注解和字节码反编译方法体；结果给出 className、artifact、entry。只读。", InputSchema: map[string]any{
		"type": "object", "properties": map[string]any{
			"query": map[string]any{"type": "string"}, "mode": map[string]any{"type": "string", "enum": []string{"text", "substring", "regex"}},
			"scope": map[string]any{"type": "string", "enum": []string{"all", "application", "dependency"}}, "includeBodies": map[string]any{"type": "boolean"},
			"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 50}, "offset": map[string]any{"type": "integer", "minimum": 0, "maximum": 1000},
		}, "required": []string{"query"},
	}},
	{Name: "search_config", Description: "搜索当前服务已索引的配置文件和模板。只读。", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"type": "string"}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 50}, "offset": map[string]any{"type": "integer", "minimum": 0, "maximum": 1000}}, "required": []string{"query"}}},
	{Name: "list_classes", Description: "按页列出当前服务的 Java 类，返回 className、artifact、entry 和 path。默认列出应用代码；可指定 application、dependency 或 all。只读。", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 50}, "offset": map[string]any{"type": "integer", "minimum": 0, "maximum": 50000}, "scope": map[string]any{"type": "string", "enum": []string{"application", "dependency", "all"}}}}},
	{Name: "list_web_endpoints", Description: "列出 JavaCodeDB 发现的 Spring MVC、Servlet 和 web.xml 入口。只读。", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"httpMethod": map[string]any{"type": "string"}, "pathContains": map[string]any{"type": "string"}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 50}, "offset": map[string]any{"type": "integer", "minimum": 0, "maximum": 1000}}}},
	{Name: "get_method", Description: "读取指定 Java 方法的反编译代码。类名重名时提供 artifact。只读。", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"className": map[string]any{"type": "string"}, "methodName": map[string]any{"type": "string"}, "descriptor": map[string]any{"type": "string"}, "artifact": map[string]any{"type": "string"}}, "required": []string{"className", "methodName"}}},
	{Name: "read_class", Description: "读取一个已索引 Java 类的有限反编译源码片段，返回真实源码行号和可用于 Finding 的 class 文件路径。候选与复核都必须调用它核对证据。只读。", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"class_name": map[string]any{"type": "string"}, "artifact": map[string]any{"type": "string"}, "entry": map[string]any{"type": "string"}, "start_line": map[string]any{"type": "integer", "minimum": 1}, "end_line": map[string]any{"type": "integer", "minimum": 1}}, "required": []string{"class_name"}}},
	{Name: "find_callers", Description: "查询 Java 方法的直接调用者和 CHA 推断调用者；图结果用于定位线索，必须再读源码确认实际数据流。只读。", InputSchema: taskCodeAuditGraphToolSchema()},
	{Name: "find_callees", Description: "查询 Java 方法的直接调用目标和 CHA 推断调用目标；图结果用于定位线索，必须再读源码确认实际数据流。只读。", InputSchema: taskCodeAuditGraphToolSchema()},
}

func (state *taskCodeAuditToolState) callJavaCodeDB(name string, raw json.RawMessage) (string, error) {
	var arguments map[string]any
	if err := json.Unmarshal(raw, &arguments); err != nil {
		return `{"error":"参数不是合法 JSON"}`, err
	}
	if name == "list_classes" {
		if _, ok := arguments["scope"]; !ok {
			arguments["scope"] = "application"
		}
	}
	if name == "read_class" {
		return state.readJavaCodeDBClass(arguments)
	}
	switch name {
	case "get_index_status", "search_code", "search_config", "list_classes", "list_web_endpoints", "get_method", "find_callers", "find_callees":
	default:
		return `{"error":"JavaCodeDB 工具未开放"}`, errors.New("JavaCodeDB tool not allowed")
	}
	ctx := state.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	callCtx, cancel := context.WithTimeout(ctx, taskJavaCodeDBRequestLimit)
	defer cancel()
	output, err := state.javaCodeDB.callTool(callCtx, name, arguments)
	if err != nil {
		return output, err
	}
	if name == "list_classes" {
		var result taskJavaCodeDBClassList
		if err := json.Unmarshal([]byte(output), &result); err != nil {
			return "", fmt.Errorf("decode JavaCodeDB class list: %w", err)
		}
		for index := range result.Classes {
			state.registerJavaCodeDBClass(result.Classes[index])
			result.Classes[index].Path = taskJavaCodeDBSourcePath(result.Classes[index].Artifact, result.Classes[index].Entry)
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return "", err
		}
		return string(encoded), nil
	}
	if name == "search_code" || name == "get_method" || name == "list_web_endpoints" {
		state.registerJavaCodeDBClassesFromOutput(output)
	}
	return taskJavaCodeDBBoundedOutput(output), nil
}

func (state *taskCodeAuditToolState) registerJavaCodeDBClassesFromOutput(output string) {
	var result struct {
		Results []taskJavaCodeDBClassRef `json:"results"`
	}
	if json.Unmarshal([]byte(output), &result) != nil {
		return
	}
	for _, class := range result.Results {
		if class.ClassName != "" && class.Artifact != "" && class.Entry != "" {
			state.registerJavaCodeDBClass(class)
		}
	}
}

func (state *taskCodeAuditToolState) readJavaCodeDBClass(arguments map[string]any) (string, error) {
	className := strings.TrimSpace(taskJavaCodeDBString(arguments["class_name"]))
	artifact := strings.TrimSpace(taskJavaCodeDBString(arguments["artifact"]))
	entry := strings.TrimSpace(taskJavaCodeDBString(arguments["entry"]))
	if className == "" {
		return `{"error":"class_name is required"}`, errors.New("class_name is required")
	}
	var candidates []taskJavaCodeDBClassRef
	for _, class := range state.codebase.JavaCodeDBClasses {
		if class.ClassName != className || (artifact != "" && class.Artifact != artifact) || (entry != "" && class.Entry != entry) {
			continue
		}
		candidates = append(candidates, class)
	}
	if len(candidates) == 0 {
		return `{"error":"class is not in the selected service index"}`, errors.New("class outside selected service")
	}
	if len(candidates) > 1 {
		choices, _ := json.Marshal(candidates)
		return string(choices), errors.New("class name is ambiguous; specify artifact and entry")
	}
	class := candidates[0]
	startLine := taskJavaCodeDBInt(arguments["start_line"], 1)
	endLine := taskJavaCodeDBInt(arguments["end_line"], startLine+199)
	if startLine < 1 || endLine < startLine {
		return `{"error":"invalid source line range"}`, errors.New("invalid source line range")
	}
	ctx := state.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	callCtx, cancel := context.WithTimeout(ctx, taskJavaCodeDBRequestLimit)
	defer cancel()
	text, err := state.javaCodeDB.callTool(callCtx, "get_class_source", map[string]any{
		"className": class.ClassName, "artifact": class.Artifact, "entry": class.Entry,
		"startLine": startLine, "endLine": endLine,
	})
	if err != nil {
		return text, err
	}
	var result taskJavaCodeDBClassSourceResponse
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		return "", fmt.Errorf("decode JavaCodeDB class source: %w", err)
	}
	if len(result.Results) != 1 {
		return `{"error":"JavaCodeDB did not return one exact class"}`, errors.New("JavaCodeDB class source was ambiguous")
	}
	source := result.Results[0]
	if source.ClassName != class.ClassName || source.Artifact != class.Artifact || source.Entry != class.Entry {
		return `{"error":"JavaCodeDB class identity changed"}`, errors.New("JavaCodeDB class identity mismatch")
	}
	if strings.TrimSpace(source.Source) == "" {
		return `{"error":"JavaCodeDB returned no decompiled source"}`, errors.New("empty decompiled class source")
	}
	filePath := taskJavaCodeDBSourcePath(class.Artifact, class.Entry)
	state.registerJavaCodeDBClass(class)
	file := taskCodeAuditFile{Path: filePath, Kind: "java", Size: int64(len(source.Source))}
	if _, exists := state.codebase.ByPath[filePath]; !exists {
		state.codebase.Files = append(state.codebase.Files, file)
	}
	state.codebase.ByPath[filePath] = file
	classNameParts := strings.Split(class.ClassName, ".")
	classShortName := strings.ReplaceAll(classNameParts[len(classNameParts)-1], "$", ".")
	packageName := strings.Join(classNameParts[:len(classNameParts)-1], ".")
	state.codebase.ProvenanceByPath[filePath] = taskCodeAuditProvenanceLocation{
		ReconstructedFile: filePath, OriginalClassFile: class.OriginalClassFile, Package: packageName, Class: classShortName,
	}
	state.prodFiles[filePath] = true
	state.readFiles[filePath] = true
	state.readCalls[filePath]++
	if state.visible[filePath] == nil {
		state.visible[filePath] = map[int]bool{}
	}
	lines := strings.Split(strings.ReplaceAll(source.Source, "\r\n", "\n"), "\n")
	var formatted strings.Builder
	for index, line := range lines {
		lineNumber := source.SourceLineStart + index
		if lineNumber > source.SourceLineEnd || formatted.Len()+len(line)+24 > taskCodeAuditReadMaxBytes {
			break
		}
		fmt.Fprintf(&formatted, "%d: %s\n", lineNumber, line)
		state.visible[filePath][lineNumber] = true
		state.recordLine(filePath, lineNumber, line)
	}
	return fmt.Sprintf("反编译类 %s；源码路径 %s；原始 class %s；类 SHA-256 %s；返回行 %d-%d（共 %d 行）：\n%s",
		class.ClassName, filePath, class.OriginalClassFile, source.SHA256, source.SourceLineStart, source.SourceLineEnd,
		source.TotalLines, formatted.String()), nil
}

func (state *taskCodeAuditToolState) registerJavaCodeDBClass(class taskJavaCodeDBClassRef) {
	if state.codebase == nil || state.codebase.JavaCodeDBClasses == nil {
		return
	}
	filePath := taskJavaCodeDBSourcePath(class.Artifact, class.Entry)
	if class.OriginalClassFile == "" {
		class.OriginalClassFile = taskJavaCodeDBOriginalClassFile(state.codebase, class.Artifact, class.Entry)
	}
	state.codebase.JavaCodeDBClasses[filePath] = class
	classNameParts := strings.Split(class.ClassName, ".")
	if len(classNameParts) > 0 {
		classShortName := strings.ReplaceAll(classNameParts[len(classNameParts)-1], "$", ".")
		packageName := strings.Join(classNameParts[:len(classNameParts)-1], ".")
		state.codebase.ProvenanceByPath[filePath] = taskCodeAuditProvenanceLocation{
			ReconstructedFile: filePath, OriginalClassFile: class.OriginalClassFile, Package: packageName, Class: classShortName,
		}
	}
}

func (state *taskCodeAuditToolState) registerJavaCodeDBClassForSourcePath(filePath string) bool {
	if state == nil || state.javaCodeDB == nil || state.codebase == nil {
		return false
	}
	filePath = filepath.ToSlash(filePath)
	if _, ok := state.codebase.JavaCodeDBClasses[filePath]; ok {
		return true
	}
	artifact, entry, ok := taskJavaCodeDBArtifactEntryForSourcePath(filePath)
	if !ok {
		return false
	}
	ctx := state.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	callCtx, cancel := context.WithTimeout(ctx, taskJavaCodeDBRequestLimit)
	defer cancel()
	output, err := state.javaCodeDB.callTool(callCtx, "get_class_source", map[string]any{
		"artifact": artifact, "entry": entry, "startLine": 1, "endLine": 1,
	})
	if err != nil {
		return false
	}
	var result taskJavaCodeDBClassSourceResponse
	if json.Unmarshal([]byte(output), &result) != nil || len(result.Results) != 1 {
		return false
	}
	source := result.Results[0]
	if source.Artifact != artifact || source.Entry != entry || source.ClassName == "" {
		return false
	}
	state.registerJavaCodeDBClass(taskJavaCodeDBClassRef{
		ClassName: source.ClassName, Artifact: source.Artifact, Entry: source.Entry,
		SHA256: source.SHA256, Application: source.Application,
	})
	return true
}

func taskJavaCodeDBArtifactEntryForSourcePath(filePath string) (string, string, bool) {
	filePath = filepath.ToSlash(filePath)
	if index := strings.Index(filePath, "!/"); index >= 0 {
		artifact := filePath[:index]
		entry := filePath[index+2:]
		if artifact == "" || entry == "" || !strings.HasSuffix(strings.ToLower(entry), ".java") {
			return "", "", false
		}
		return artifact, strings.TrimSuffix(entry, filepath.Ext(entry)) + ".class", true
	}
	if !strings.HasSuffix(strings.ToLower(filePath), ".java") {
		return "", "", false
	}
	classPath := strings.TrimSuffix(filePath, filepath.Ext(filePath)) + ".class"
	return classPath, classPath, true
}

func taskJavaCodeDBSourcePath(artifact, entry string) string {
	entry = filepath.ToSlash(entry)
	if artifact == entry && strings.HasSuffix(strings.ToLower(entry), ".class") {
		return strings.TrimSuffix(entry, filepath.Ext(entry)) + ".java"
	}
	artifact = filepath.ToSlash(artifact)
	javaEntry := strings.TrimSuffix(entry, filepath.Ext(entry)) + ".java"
	return artifact + "!/" + javaEntry
}

func taskJavaCodeDBOriginalClassFile(codebase *taskCodeAuditCodebase, artifact, entry string) string {
	if codebase == nil {
		return entry
	}
	prefix := codebase.ArchivePrefix
	if codebase.ArchiveKind == "directory" {
		prefix = codebase.OriginalSourcePrefix
	}
	if codebase.ArchiveKind == "class" {
		return codebase.ArchiveName
	}
	if artifact == entry && strings.HasSuffix(strings.ToLower(entry), ".class") {
		if prefix == "" {
			return entry
		}
		return path.Join(prefix, entry)
	}
	artifactPath := path.Join(prefix, artifact)
	if codebase.ArchiveKind != "directory" && prefix == "" && artifact == codebase.ArchiveName {
		artifactPath = codebase.ArchiveName
	}
	return artifactPath + "!" + entry
}

func taskJavaCodeDBString(value any) string {
	text, _ := value.(string)
	return text
}

func taskJavaCodeDBInt(value any, fallback int) int {
	if number, ok := value.(float64); ok {
		return int(number)
	}
	return fallback
}

func taskJavaCodeDBBoundedOutput(output string) string {
	if len(output) <= taskCodeAuditReadMaxBytes {
		return output
	}
	var bounded strings.Builder
	for _, r := range output {
		if bounded.Len()+len(string(r)) > taskCodeAuditReadMaxBytes-64 {
			break
		}
		bounded.WriteRune(r)
	}
	return bounded.String() + "\n[JavaCodeDB 输出已截断；请缩小 limit 或查询范围]"
}

func taskCodeAuditGraphToolSchema() map[string]any {
	return map[string]any{"type": "object", "properties": map[string]any{
		"className": map[string]any{"type": "string"}, "methodName": map[string]any{"type": "string"}, "descriptor": map[string]any{"type": "string"},
		"depth": map[string]any{"type": "integer", "minimum": 1, "maximum": 5}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 50},
		"offset": map[string]any{"type": "integer", "minimum": 0, "maximum": 1000},
	}, "required": []string{"className", "methodName"}}
}
