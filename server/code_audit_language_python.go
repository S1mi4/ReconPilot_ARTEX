package server

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// taskCodeAuditPythonAdapter reads filenames and bounded build metadata only.
// In particular, setup.py and manage.py are never imported or executed.
type taskCodeAuditPythonAdapter struct{}

var _ taskCodeAuditLanguageAdapter = taskCodeAuditPythonAdapter{}

func (taskCodeAuditPythonAdapter) Language() string { return "python" }

func (taskCodeAuditPythonAdapter) ClassifyFile(scope, rel string) (string, bool) {
	if excludedPythonAuditPath(scope, rel) {
		return "", false
	}
	name := strings.ToLower(path.Base(filepath.ToSlash(rel)))
	if (pythonAuditBuildMarker(name) && !strings.HasSuffix(name, ".py")) || name == "pytest.ini" || name == "tox.ini" || name == "pipfile.lock" {
		return "config", true
	}
	if strings.HasSuffix(name, ".pyi") {
		return "config", true
	}
	for _, suffix := range []string{".html", ".htm", ".jinja", ".jinja2", ".j2"} {
		if strings.HasSuffix(name, suffix) {
			return "template", true
		}
	}
	if !strings.HasSuffix(name, ".py") {
		return "", false
	}
	for _, part := range strings.Split(strings.ToLower(filepath.ToSlash(path.Join(scope, rel))), "/") {
		if part == "test" || part == "tests" || part == "testing" {
			return "test", true
		}
	}
	if strings.HasPrefix(name, "test_") || strings.HasSuffix(name, "_test.py") || name == "conftest.py" {
		return "test", true
	}
	return "source", true
}

func (taskCodeAuditPythonAdapter) PruneDirectory(scope, rel string) bool {
	return excludedPythonAuditPath(scope, rel)
}

func excludedPythonAuditPath(scope, rel string) bool {
	parts := strings.Split(strings.ToLower(filepath.ToSlash(path.Join(scope, rel))), "/")
	scopePath := strings.Trim(filepath.ToSlash(path.Clean(scope)), "/")
	scopeDepth := 0
	if scopePath != "." && scopePath != "" {
		scopeDepth = len(strings.Split(scopePath, "/"))
	}
	insideSource := false
	for index, part := range parts {
		switch part {
		case ".git", ".idea", ".venv", ".tox", ".nox", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".hypothesis", "site-packages", "dist-packages", ".eggs", "node_modules":
			return true
		}
		if strings.HasSuffix(part, ".egg-info") || strings.HasSuffix(part, ".dist-info") {
			return true
		}
		if part == "src" || part == "lib" {
			insideSource = true
		}
		// Ambiguous names also occur in ordinary packages (app/env, src/build).
		// Exclude them at the snapshot/service root, preserving package children.
		if !insideSource && (index == 0 || index == scopeDepth) {
			switch part {
			case "venv", "env", "build", "dist", "_build", "vendor", "third_party", "third-party", "generated", "__pypackages__":
				return true
			}
		}
	}
	return false
}

func pythonAuditBuildMarker(name string) bool {
	name = strings.ToLower(path.Base(filepath.ToSlash(name)))
	switch name {
	case "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "manage.py":
		return true
	}
	// Requirements variants are data, whereas a module named requirements.py
	// remains source. Support both pip's .txt and pip-tools' .in convention.
	if name == "requirements" {
		return true
	}
	return strings.HasPrefix(name, "requirements") &&
		(strings.HasSuffix(name, ".txt") || strings.HasSuffix(name, ".in"))
}

var pythonAuditDependencyPattern = regexp.MustCompile(`(?mi)(?:^|["'])\s*(django|flask|fastapi|starlette|aiohttp|tornado|uvicorn|gunicorn|waitress|hypercorn)(?:\[[a-z0-9_,.-]+\])?\s*(?:[<>=!~;]|["']|$)`)
var pythonAuditEntrypointPattern = regexp.MustCompile(`(?mi)^\s*\[(?:project\.(?:scripts|gui-scripts)|options\.entry_points|tool\.poetry\.scripts)\]\s*(?:#.*)?$`)

func (adapter taskCodeAuditPythonAdapter) DiscoveryFile(name string, body []byte) taskCodeAuditDiscoveryFile {
	kind, eligible := adapter.ClassifyFile(".", name)
	info := taskCodeAuditDiscoveryFile{Source: eligible && kind == "source"}
	if !eligible || !pythonAuditBuildMarker(name) {
		return info
	}
	info.Build = true
	base := strings.ToLower(path.Base(filepath.ToSlash(name)))
	switch base {
	case "manage.py":
		info.Signals = []string{"python_manage_script"}
	case "pyproject.toml":
		info.Signals = []string{"python_pyproject_metadata"}
	case "setup.py", "setup.cfg":
		info.Signals = []string{"python_setup_metadata"}
	case "pipfile":
		info.Signals = []string{"python_pipfile_metadata"}
	default:
		info.Signals = []string{"python_requirements_metadata"}
	}
	// Python script bodies are code, not declarative metadata. Even when the
	// caller supplies them, do not infer dependencies from setup/manage scripts.
	if body == nil || base == "setup.py" || base == "manage.py" {
		return info
	}
	for _, match := range pythonAuditDependencyPattern.FindAllStringSubmatch(string(body), 32) {
		info.Tokens = append(info.Tokens, strings.ToLower(match[1]))
	}
	info.Tokens = uniqueSorted(info.Tokens)
	if pythonAuditEntrypointPattern.Match(body) {
		info.Signals = append(info.Signals, "python_script_entrypoints_metadata")
	}
	return info
}

func (taskCodeAuditPythonAdapter) DiscoveryEvidence(tokens, signals []string) ([]string, string) {
	all := append([]string(nil), signals...)
	for _, token := range tokens {
		switch strings.ToLower(token) {
		case "django", "flask", "fastapi", "starlette", "aiohttp", "tornado", "uvicorn", "gunicorn", "waitress", "hypercorn":
			all = append(all, "python_dependency_"+strings.ToLower(token))
		}
	}
	// Dependencies and console scripts occur in libraries and developer tools,
	// too. Filename/dependency metadata cannot confirm a deployed service.
	return uniqueSorted(all), ""
}

func (taskCodeAuditPythonAdapter) ReadingNotes() string {
	return `语言阅读说明（Python）：生产 .py 是阅读对象；.pyi、构建配置和测试用于上下文，不将类型桩视为运行实现。仅静态读取，不执行脚本、不导入目标模块、不安装依赖。结合包与相对导入、装饰器、描述符、元类、动态导入和运行时注册理解调用关系；名称相同或依赖声明不能证明实际绑定。跟踪配置、环境变量、条件分支及框架装配对行为的影响，区分导入阶段、应用启动、请求或任务回调与退出清理的生命周期；异步任务、生成器和上下文管理器需结合调度与资源归属阅读。静态证据无法确定的动态行为与部署条件应明确保留为未知。`
}
