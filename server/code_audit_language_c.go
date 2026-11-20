package server

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// taskCodeAuditCAdapter covers C translation units and headers. C++ source
// suffixes (including the conventional uppercase .C and .H) are not selected.
type taskCodeAuditCAdapter struct{}

var _ taskCodeAuditLanguageAdapter = taskCodeAuditCAdapter{}

func (taskCodeAuditCAdapter) Language() string { return "c" }

func (taskCodeAuditCAdapter) ClassifyFile(scope, rel string) (string, bool) {
	if excludedCAuditPath(scope, rel) {
		return "", false
	}
	rel = filepath.ToSlash(rel)
	base := path.Base(rel)
	if cAuditBuildMarker(base) || strings.HasSuffix(base, ".cmake") {
		return "config", true
	}
	if ext := path.Ext(base); ext != ".c" && ext != ".h" {
		return "", false
	}
	for _, part := range strings.Split(strings.ToLower(filepath.ToSlash(path.Join(scope, rel))), "/") {
		if part == "test" || part == "tests" || part == "testing" {
			return "test", true
		}
	}
	name := strings.ToLower(strings.TrimSuffix(base, path.Ext(base)))
	if strings.HasPrefix(name, "test_") || strings.HasSuffix(name, "_test") || strings.HasSuffix(name, "_tests") {
		return "test", true
	}
	return "source", true
}

func (taskCodeAuditCAdapter) PruneDirectory(scope, rel string) bool {
	return excludedCAuditPath(scope, rel)
}

func excludedCAuditPath(scope, rel string) bool {
	parts := strings.Split(strings.ToLower(filepath.ToSlash(path.Join(scope, rel))), "/")
	scopePath := strings.Trim(filepath.ToSlash(path.Clean(scope)), "/")
	scopeDepth := 0
	if scopePath != "." && scopePath != "" {
		scopeDepth = len(strings.Split(scopePath, "/"))
	}
	insideSource := false
	for index, part := range parts {
		switch part {
		case ".git", ".idea", "node_modules", "cmakefiles", "meson-private", "meson-logs", "autom4te.cache", ".deps", ".libs", "_deps", ".conan", ".conan2", "vcpkg_installed", "subprojects":
			return true
		}
		if strings.HasPrefix(part, "cmake-build-") {
			return true
		}
		if part == "src" || part == "include" || part == "lib" || part == "libs" {
			insideSource = true
		}
		// lib/libs and include are common first-party C source roots. Preserve
		// ordinary nested names such as src/build and include/vendor as well.
		if !insideSource && (index == 0 || index == scopeDepth) {
			switch part {
			case "build", "out", "dist", "_build", "vendor", "third_party", "third-party", "deps", "generated":
				return true
			}
		}
	}
	return false
}

func cAuditBuildMarker(name string) bool {
	switch strings.ToLower(path.Base(filepath.ToSlash(name))) {
	case "cmakelists.txt", "makefile", "gnumakefile", "makefile.am", "makefile.in", "configure.ac", "configure.in", "meson.build", "meson_options.txt", "meson.options":
		return true
	default:
		return false
	}
}

var cAuditCMakeTargetPattern = regexp.MustCompile(`(?mi)^\s*add_(executable|library)\s*\(\s*([a-z_][a-z0-9_.+-]{0,79})\b`)
var cAuditMesonTargetPattern = regexp.MustCompile(`(?mi)^\s*(?:(?:[a-z_][a-z0-9_]*)\s*=\s*)?(executable|library|shared_library|static_library|both_libraries)\s*\(\s*["']([a-z_][a-z0-9_.+-]{0,79})["']`)
var cAuditMakeTargetPattern = regexp.MustCompile(`(?m)^([a-zA-Z_][a-zA-Z0-9_.+-]{0,79})\s*:(?:[^=]|$)`)

func (adapter taskCodeAuditCAdapter) DiscoveryFile(name string, body []byte) taskCodeAuditDiscoveryFile {
	kind, eligible := adapter.ClassifyFile(".", name)
	info := taskCodeAuditDiscoveryFile{Source: eligible && kind == "source"}
	if !eligible || !cAuditBuildMarker(name) {
		return info
	}
	info.Build = true
	base := strings.ToLower(path.Base(filepath.ToSlash(name)))
	var pattern *regexp.Regexp
	switch base {
	case "cmakelists.txt":
		info.Signals = []string{"c_cmake_metadata"}
		pattern = cAuditCMakeTargetPattern
	case "meson.build", "meson_options.txt", "meson.options":
		info.Signals = []string{"c_meson_metadata"}
		if base == "meson.build" {
			pattern = cAuditMesonTargetPattern
		}
	case "configure.ac", "configure.in":
		info.Signals = []string{"c_autoconf_metadata"}
	default:
		info.Signals = []string{"c_make_metadata"}
		pattern = cAuditMakeTargetPattern
	}
	if body == nil || pattern == nil {
		return info
	}
	for _, match := range pattern.FindAllStringSubmatch(string(body), 24) {
		if pattern == cAuditMakeTargetPattern {
			info.Tokens = append(info.Tokens, "make_target:"+strings.ToLower(match[1]))
			continue
		}
		kind := "library"
		if strings.EqualFold(match[1], "executable") {
			kind = "executable"
		}
		info.Tokens = append(info.Tokens, kind+":"+strings.ToLower(match[2]))
	}
	info.Tokens = uniqueSorted(info.Tokens)
	return info
}

func (taskCodeAuditCAdapter) DiscoveryEvidence(tokens, signals []string) ([]string, string) {
	all := append([]string(nil), signals...)
	for _, token := range tokens {
		switch {
		case strings.HasPrefix(token, "executable:"):
			all = append(all, "c_executable_target_metadata")
		case strings.HasPrefix(token, "library:"):
			all = append(all, "c_library_target_metadata")
		}
	}
	// A build target might be a library, test or command-line tool. Static
	// build declarations do not establish a deployed or listening service.
	return uniqueSorted(all), ""
}

func (taskCodeAuditCAdapter) ReadingNotes() string {
	return `语言阅读说明（C）：阅读 .c 翻译单元与 .h 头文件，测试和构建描述用于上下文；不据此宣称支持 C++，共享头文件的实际语言需由构建上下文确认。仅静态读取，不执行构建命令、配置脚本或安装依赖。结合包含路径、宏展开、条件编译、编译选项与平台差异确定有效代码，未确认的宏值和构建条件保留为未知。通过声明与定义、链接边界、函数指针、回调注册及外部接口理解调用关系；不能仅凭名称推断实际调用目标。沿初始化、运行循环、回调和退出清理跟踪状态与资源的生命周期、所有权转移、长度和返回值约定，并说明静态证据覆盖的条件。`
}
