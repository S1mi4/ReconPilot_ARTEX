package server

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// taskCodeAuditJavaAdapter preserves the existing Java inventory and Maven /
// Gradle discovery rules. Binary JavaCodeDB handling remains a separate Java
// path; source adapters do not need to implement decompilation.
type taskCodeAuditJavaAdapter struct{}

var _ taskCodeAuditLanguageAdapter = taskCodeAuditJavaAdapter{}

func (taskCodeAuditJavaAdapter) Language() string { return "java" }

func (taskCodeAuditJavaAdapter) DiscoveryFile(name string, body []byte) taskCodeAuditDiscoveryFile {
	info := taskCodeAuditDiscoveryFile{
		Source: strings.EqualFold(path.Ext(name), ".java") && !isGeneratedJavaPath(name),
	}
	switch strings.ToLower(path.Base(name)) {
	case "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts":
		info.Build = true
	}
	if info.Build && body != nil {
		info.Tokens = extractBuildMetadataTokens(string(body))
		if strings.EqualFold(path.Base(name), "pom.xml") && isMavenAggregatorMetadata(string(body)) {
			info.Signals = []string{"maven_aggregator_pom"}
		}
	}
	return info
}

func (taskCodeAuditJavaAdapter) DiscoveryEvidence(tokens, signals []string) ([]string, string) {
	all := append([]string(nil), signals...)
	all = append(all, buildSignals(tokens)...)
	all = uniqueSorted(all)
	return all, strongBuildEvidence(all)
}

func (taskCodeAuditJavaAdapter) PruneDirectory(scope, rel string) bool {
	name := path.Base(filepath.ToSlash(rel))
	// Keep traversing lib/libs: nested application artifacts are handled by
	// the existing binary inventory, even when their source files are excluded.
	if strings.EqualFold(name, "lib") || strings.EqualFold(name, "libs") {
		return false
	}
	return excludedAuditDirectory(name) && excludedAuditPath(scope, rel)
}

func (taskCodeAuditJavaAdapter) ReadingNotes() string {
	return `语言阅读说明（Java）：生产 Java 源码与 JSP 模板是审计对象；测试只用于理解上下文。常见技术栈包括 Spring Boot/MVC、Servlet/JSP、JDBC/MyBatis/JPA 和 HTTP 客户端，用于理解代码，不是范围限制。阅读时结合包名、继承、接口实现、框架装配、注解与配置理解调用关系；无法从已读代码确认的连接须明确保留为未知。语言说明不限定漏洞类型。
命令执行类问题应尽力锚定实际进程执行点 ProcessBuilder.start()（准确引用接收者，如 builder.start()）或 Runtime.exec()；构造 ProcessBuilder、组装参数、拼接 shell 字符串不能证明已执行，若仅有这些真实线索必须保留不确定性。类别标签必须与真实问题相符，例如反序列化只用于反序列化 API，不能用于 SpEL、模板或脚本表达式执行。静态分析不得描述成动态利用成功。`
}

// excludedAuditPath reports whether a path (scope prefix + path inside the scope)
// is build output, tooling or a dependency directory. Names such as vendor, lib,
// build or generated are only excluded outside a Java source root: inside
// src/main/java they are legitimate package names (com/acme/vendor/...).
func excludedAuditPath(scope, rel string) bool {
	full := strings.Split(strings.ToLower(strings.Trim(filepath.ToSlash(path.Join(scope, rel)), "/")), "/")
	sourceRootEnd := javaSourceRootEnd(full)
	for index, part := range full {
		switch part {
		case ".git", ".idea", ".gradle", "node_modules":
			return true
		case "target", "build", "out", "generated", "generated-sources", "vendor", "lib", "libs":
			if sourceRootEnd < 0 || index < sourceRootEnd {
				return true
			}
		}
	}
	return false
}

// javaSourceRootEnd returns the index just after the first src/[main|test/]java
// segment run, or -1 when the path is not under a recognised Java source root.
func javaSourceRootEnd(parts []string) int {
	for index := 0; index < len(parts); index++ {
		if parts[index] != "src" {
			continue
		}
		next := index + 1
		if next < len(parts) && (parts[next] == "main" || parts[next] == "test") {
			next++
		}
		if next < len(parts) && parts[next] == "java" {
			return next + 1
		}
	}
	return -1
}

func (taskCodeAuditJavaAdapter) ClassifyFile(scope, rel string) (string, bool) {
	rel = filepath.ToSlash(rel)
	parts := strings.Split(strings.ToLower(rel), "/")
	if excludedAuditPath(scope, rel) {
		return "", false
	}
	base := strings.ToLower(path.Base(rel))
	if strings.HasSuffix(base, ".java") {
		for _, part := range parts {
			if part == "test" || part == "tests" || part == "test-classes" {
				return "test", true
			}
		}
		if strings.HasSuffix(base, "test.java") || strings.HasSuffix(base, "tests.java") {
			return "test", true
		}
		return "java", true
	}
	switch base {
	case "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradle.properties", "web.xml", "struts-config.xml":
		return "config", true
	}
	if strings.HasPrefix(base, "application") && (strings.HasSuffix(base, ".properties") || strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")) {
		return "config", true
	}
	if strings.HasSuffix(base, ".jsp") || strings.HasSuffix(base, ".jspx") || strings.HasSuffix(base, ".tag") || strings.HasSuffix(base, ".tagx") {
		return "template", true
	}
	if strings.HasSuffix(base, ".xml") && (strings.Contains(strings.ToLower(rel), "/mapper/") || strings.HasPrefix(base, "spring") || base == "beans.xml" || base == "mybatis-config.xml" || base == "hibernate.cfg.xml") {
		return "config", true
	}
	return "", false
}

func excludedAuditDirectory(name string) bool {
	switch strings.ToLower(name) {
	case ".git", ".idea", ".gradle", "target", "build", "out", "generated", "generated-sources", "node_modules", "vendor", "lib", "libs":
		return true
	default:
		return false
	}
}

var buildMetadataPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<packaging>\s*([a-z0-9_.-]{1,80})\s*</packaging>`),
	regexp.MustCompile(`(?i)<artifactId>\s*([a-z0-9_.-]{1,100})\s*</artifactId>`),
	regexp.MustCompile(`(?i)<module>\s*([a-z0-9_./-]{1,120})\s*</module>`),
	regexp.MustCompile(`(?i)(?:mainClass|mainClassName|start-class)\s*(?:=|:)\s*["']?([a-z0-9_.$/-]{1,160})`),
	regexp.MustCompile(`(?i)(?:id|group)\s*(?:\(\s*)?["']((?:org\.springframework\.boot|io\.quarkus|io\.micronaut|org\.gretty|war|application)[a-z0-9_.-]{0,120})["']`),
}

var mavenPackagingPOMPattern = regexp.MustCompile(`(?is)<packaging>\s*pom\s*</packaging>`)
var mavenModulePattern = regexp.MustCompile(`(?is)<module>\s*[^<]+\s*</module>`)
var mavenPluginManagementPattern = regexp.MustCompile(`(?is)<pluginManagement\b[^>]*>.*?</pluginManagement>`)

func isMavenAggregatorMetadata(body string) bool {
	if mavenPackagingPOMPattern.MatchString(body) {
		return true
	}
	if !mavenModulePattern.MatchString(body) {
		return false
	}
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "spring-boot-maven-plugin") {
		return false
	}
	withoutPluginManagement := mavenPluginManagementPattern.ReplaceAllString(lower, "")
	return !strings.Contains(withoutPluginManagement, "spring-boot-maven-plugin")
}

func extractBuildMetadataTokens(body string) []string {
	tokens := make([]string, 0)
	seen := map[string]bool{}
	for _, pattern := range buildMetadataPatterns {
		matches := pattern.FindAllStringSubmatch(body, 32)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			value := strings.TrimSpace(match[1])
			if value == "" || len(value) > 160 {
				continue
			}
			token := strings.ToLower(value)
			if !seen[token] {
				seen[token] = true
				tokens = append(tokens, token)
			}
		}
	}
	if len(tokens) > 24 {
		tokens = tokens[:24]
	}
	return tokens
}

func buildSignals(tokens []string) []string {
	joined := strings.ToLower(strings.Join(tokens, " "))
	var signals []string
	for marker, signal := range map[string]string{
		"spring-boot-maven-plugin": "spring_boot_maven_plugin",
		"org.springframework.boot": "spring_boot_gradle_plugin",
		"quarkus-maven-plugin":     "quarkus_maven_plugin",
		"io.quarkus":               "quarkus_gradle_plugin",
		"micronaut-maven-plugin":   "micronaut_maven_plugin",
		"io.micronaut":             "micronaut_gradle_plugin",
		"packaging=war":            "war_packaging",
	} {
		if strings.Contains(joined, marker) {
			signals = append(signals, signal)
		}
	}
	return signals
}

func strongBuildEvidence(signals []string) string {
	for _, signal := range signals {
		if signal == "maven_aggregator_pom" {
			return ""
		}
	}
	for _, signal := range signals {
		switch signal {
		case "spring_boot_maven_plugin", "spring_boot_gradle_plugin":
			return "Spring Boot application build plugin"
		case "quarkus_maven_plugin", "quarkus_gradle_plugin":
			return "Quarkus application build plugin"
		case "micronaut_maven_plugin", "micronaut_gradle_plugin":
			return "Micronaut application build plugin"
		case "war_packaging":
			return "WAR web application packaging"
		}
	}
	return ""
}

func isGeneratedJavaPath(name string) bool {
	for _, part := range strings.Split(strings.ToLower(name), "/") {
		if part == "target" || part == "build" || part == "generated" || part == "generated-sources" {
			return true
		}
	}
	return false
}
