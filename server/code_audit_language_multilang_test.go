package server

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestTaskCodeAuditMultilangPythonClassification(t *testing.T) {
	adapter := taskCodeAuditPythonAdapter{}
	if adapter.Language() != "python" {
		t.Fatal("Python adapter language changed")
	}
	for _, tc := range []struct {
		scope, file, kind string
	}{
		{".", "app.py", "source"},
		{".", "src/acme/__init__.py", "source"},
		{".", "src/acme/__main__.py", "source"},
		{".", "src/acme/build/worker.py", "source"},
		{".", "src/acme/vendor/client.py", "source"},
		{".", "src/env/settings.py", "source"},
		{".", "acme/env/settings.py", "source"},
		{".", "lib/acme/runtime.py", "source"},
		{"src/acme", "build/worker.py", "source"},
		{".", "typing/api.pyi", "config"},
		{".", "pyproject.toml", "config"},
		{".", "setup.py", "source"},
		{".", "setup.cfg", "config"},
		{".", "requirements.txt", "config"},
		{".", "requirements-dev.in", "config"},
		{".", "Pipfile", "config"},
		{".", "Pipfile.lock", "config"},
		{".", "manage.py", "source"},
		{".", "pytest.ini", "config"},
		{".", "tox.ini", "config"},
		{".", "tests/api.py", "test"},
		{".", "test/api.py", "test"},
		{"tests", "api.py", "test"},
		{".", "src/acme/test_api.py", "test"},
		{".", "src/acme/api_test.py", "test"},
		{".", "conftest.py", "test"},
		{".", "src/acme/contest.py", "source"},
		{".", "requirements.py", "source"},
		{".", ".venv/lib/api.py", ""},
		{".", "venv/api.py", ""},
		{".", "env/api.py", ""},
		{".", ".tox/py312/api.py", ""},
		{".", ".nox/tests/api.py", ""},
		{".", "src/acme/__pycache__/api.py", ""},
		{".", "src/site-packages/api.py", ""},
		{".", "acme.egg-info/api.py", ""},
		{".", "acme.dist-info/api.pyi", ""},
		{".", "__pypackages__/3.12/lib/api.py", ""},
		{".", "build/lib/api.py", ""},
		{".", "dist/api.py", ""},
		{".", "vendor/api.py", ""},
		{"services/api", "build/api.py", ""},
		{"services/api", "venv/api.py", ""},
		{".venv/lib", "api.py", ""},
		{"build/lib", "api.py", ""},
		{".", "main.c", ""},
		{".", "README.md", ""},
	} {
		t.Run(tc.scope+"/"+tc.file, func(t *testing.T) {
			kind, eligible := adapter.ClassifyFile(tc.scope, tc.file)
			if kind != tc.kind || eligible != (tc.kind != "") {
				t.Fatalf("ClassifyFile(%q, %q)=(%q, %t), want %q", tc.scope, tc.file, kind, eligible, tc.kind)
			}
		})
	}
}

func TestTaskCodeAuditMultilangCClassification(t *testing.T) {
	adapter := taskCodeAuditCAdapter{}
	if adapter.Language() != "c" {
		t.Fatal("C adapter language changed")
	}
	for _, tc := range []struct {
		scope, file, kind string
	}{
		{".", "main.c", "source"},
		{".", "include/api.h", "source"},
		{".", "lib/runtime.c", "source"},
		{".", "libs/runtime.c", "source"},
		{".", "src/build/runtime.c", "source"},
		{".", "include/vendor/api.h", "source"},
		{".", "lib/generated/table.c", "source"},
		{"src/acme", "vendor/runtime.c", "source"},
		{".", "tests/runtime.c", "test"},
		{"tests", "runtime.c", "test"},
		{".", "test_runtime.c", "test"},
		{".", "src/runtime_test.h", "test"},
		{".", "src/runtime_tests.c", "test"},
		{".", "src/contest.c", "source"},
		{".", "CMakeLists.txt", "config"},
		{".", "cmake/platform.cmake", "config"},
		{".", "Makefile", "config"},
		{".", "Makefile.am", "config"},
		{".", "configure.ac", "config"},
		{".", "meson.build", "config"},
		{".", "meson_options.txt", "config"},
		{".", "build/api.c", ""},
		{".", "out/api.h", ""},
		{".", "vendor/api.c", ""},
		{".", "third_party/api.c", ""},
		{".", "deps/api.c", ""},
		{".", "cmake-build-debug/api.c", ""},
		{".", "src/CMakeFiles/probe.c", ""},
		{".", "_deps/library-src/api.c", ""},
		{".", "subprojects/library/api.c", ""},
		{".", "vcpkg_installed/include/api.h", ""},
		{".", ".conan2/api.c", ""},
		{".", "meson-private/probe.c", ""},
		{"services/api", "build/api.c", ""},
		{"build/src", "api.c", ""},
		{".", "main.C", ""},
		{".", "api.H", ""},
		{".", "main.cpp", ""},
		{".", "main.cc", ""},
		{".", "main.cxx", ""},
		{".", "api.hpp", ""},
		{".", "app.py", ""},
	} {
		t.Run(tc.scope+"/"+tc.file, func(t *testing.T) {
			kind, eligible := adapter.ClassifyFile(tc.scope, tc.file)
			if kind != tc.kind || eligible != (tc.kind != "") {
				t.Fatalf("ClassifyFile(%q, %q)=(%q, %t), want %q", tc.scope, tc.file, kind, eligible, tc.kind)
			}
		})
	}
}

func TestTaskCodeAuditMultilangDirectoryPruning(t *testing.T) {
	for _, tc := range []struct {
		adapter          taskCodeAuditLanguageAdapter
		scope, directory string
		prune            bool
	}{
		{taskCodeAuditPythonAdapter{}, ".", ".git", true},
		{taskCodeAuditPythonAdapter{}, ".", ".venv", true},
		{taskCodeAuditPythonAdapter{}, ".", ".pytest_cache", true},
		{taskCodeAuditPythonAdapter{}, ".", ".mypy_cache", true},
		{taskCodeAuditPythonAdapter{}, ".", ".ruff_cache", true},
		{taskCodeAuditPythonAdapter{}, ".", "build", true},
		{taskCodeAuditPythonAdapter{}, "services/api", "dist", true},
		{taskCodeAuditPythonAdapter{}, ".", "acme/env", false},
		{taskCodeAuditPythonAdapter{}, ".", "src/acme/vendor", false},
		{taskCodeAuditPythonAdapter{}, "src/acme", "build", false},
		{taskCodeAuditPythonAdapter{}, ".", "lib", false},
		{taskCodeAuditCAdapter{}, ".", ".git", true},
		{taskCodeAuditCAdapter{}, ".", "CMakeFiles", true},
		{taskCodeAuditCAdapter{}, ".", "cmake-build-release", true},
		{taskCodeAuditCAdapter{}, ".", "autom4te.cache", true},
		{taskCodeAuditCAdapter{}, ".", ".deps", true},
		{taskCodeAuditCAdapter{}, ".", ".libs", true},
		{taskCodeAuditCAdapter{}, ".", "_deps", true},
		{taskCodeAuditCAdapter{}, "services/api", "build", true},
		{taskCodeAuditCAdapter{}, ".", "lib", false},
		{taskCodeAuditCAdapter{}, ".", "libs", false},
		{taskCodeAuditCAdapter{}, ".", "src/build", false},
		{taskCodeAuditCAdapter{}, "include", "vendor", false},
		{taskCodeAuditCAdapter{}, ".", "cmake", false},
	} {
		if got := tc.adapter.PruneDirectory(tc.scope, tc.directory); got != tc.prune {
			t.Errorf("%s PruneDirectory(%q, %q)=%t, want %t", tc.adapter.Language(), tc.scope, tc.directory, got, tc.prune)
		}
	}
}

func TestTaskCodeAuditMultilangPythonDiscovery(t *testing.T) {
	adapter := taskCodeAuditPythonAdapter{}
	for _, name := range []string{"pyproject.toml", "package/setup.py", "setup.cfg", "requirements", "requirements.txt", "requirements-prod.txt", "requirements_dev.in", "Pipfile", "manage.py"} {
		info := adapter.DiscoveryFile(name, nil)
		if !info.Build || info.Source != strings.HasSuffix(name, ".py") {
			t.Errorf("%s: expected build marker (scripts also source), got %+v", name, info)
		}
	}
	for _, name := range []string{"app.py", "src/app/__init__.py", "app/env/config.py"} {
		info := adapter.DiscoveryFile(name, []byte(`import fastapi`))
		if !info.Source || info.Build || len(info.Tokens) != 0 || len(info.Signals) != 0 {
			t.Errorf("%s: expected source without reading source bodies, got %+v", name, info)
		}
	}
	for _, name := range []string{"typing.pyi", "tests/app.py", "test_app.py", "conftest.py", ".venv/app.py", "build/lib/app.py", "vendor/setup.py", "node_modules/pyproject.toml", "Pipfile.lock", "requirements.md", "Makefile"} {
		info := adapter.DiscoveryFile(name, nil)
		if info.Source || info.Build {
			t.Errorf("unexpected discovery candidate %s: %+v", name, info)
		}
	}
	for _, tc := range []struct {
		name, body, dependency string
	}{
		{"pyproject.toml", "[project]\ndependencies = [\"fastapi>=0.100\", \"uvicorn[standard]\"]\n[project.scripts]\napp = \"library.cli:main\"", "fastapi"},
		{"requirements-dev.txt", "# flask is only mentioned in a comment\nDjango>=5.0\n", "django"},
		{"setup.cfg", "[options]\ninstall_requires =\n    aiohttp>=3\n", "aiohttp"},
		{"Pipfile", "[packages]\nflask = \"*\"\n", "flask"},
	} {
		info := adapter.DiscoveryFile(tc.name, []byte(tc.body))
		signals, strong := adapter.DiscoveryEvidence(info.Tokens, info.Signals)
		if strong != "" || !slices.Contains(info.Tokens, tc.dependency) || !slices.Contains(signals, "python_dependency_"+tc.dependency) {
			t.Errorf("%s: metadata hints missing or overconfirmed: %+v, signals=%v strong=%q", tc.name, info, signals, strong)
		}
		if tc.name == "pyproject.toml" && !slices.Contains(signals, "python_script_entrypoints_metadata") {
			t.Error("pyproject console script declaration was not surfaced as a metadata hint")
		}
		if tc.name == "requirements-dev.txt" && slices.Contains(info.Tokens, "flask") {
			t.Error("comment was treated as a declared dependency")
		}
	}
	for _, name := range []string{"setup.py", "manage.py"} {
		info := adapter.DiscoveryFile(name, []byte("raise RuntimeError('do not run')\ninstall_requires=['django']"))
		_, strong := adapter.DiscoveryEvidence(info.Tokens, info.Signals)
		if len(info.Tokens) != 0 || strong != "" {
			t.Errorf("script body treated as declarative deployment evidence: %+v, strong=%q", info, strong)
		}
	}
}

func TestTaskCodeAuditMultilangCDiscovery(t *testing.T) {
	adapter := taskCodeAuditCAdapter{}
	for _, name := range []string{"CMakeLists.txt", "subdir/Makefile", "makefile", "GNUmakefile", "Makefile.am", "Makefile.in", "configure.ac", "configure.in", "meson.build", "meson_options.txt", "meson.options"} {
		info := adapter.DiscoveryFile(name, nil)
		if !info.Build || info.Source {
			t.Errorf("%s: expected build metadata only, got %+v", name, info)
		}
	}
	for _, name := range []string{"src/main.c", "include/api.h", "lib/runtime.c"} {
		info := adapter.DiscoveryFile(name, []byte(`add_executable(service main.c)`))
		if !info.Source || info.Build || len(info.Tokens) != 0 || len(info.Signals) != 0 {
			t.Errorf("%s: expected source without reading source bodies, got %+v", name, info)
		}
	}
	for _, name := range []string{"main.cpp", "main.C", "api.H", "api.hpp", "tests/main.c", "test_main.c", "build/main.c", "_deps/api.h", "vendor/CMakeLists.txt", "cmake-build-debug/Makefile", "cmake/platform.cmake", "pyproject.toml"} {
		info := adapter.DiscoveryFile(name, nil)
		if info.Source || info.Build {
			t.Errorf("unexpected discovery candidate %s: %+v", name, info)
		}
	}
	for _, tc := range []struct {
		name, body, token, signal string
	}{
		{"CMakeLists.txt", "project(shared C)\nadd_library(shared STATIC shared.c)\n", "library:shared", "c_library_target_metadata"},
		{"CMakeLists.txt", "# add_executable(fake fake.c)\nadd_executable(tool main.c)\n", "executable:tool", "c_executable_target_metadata"},
		{"meson.build", "project('shared', 'c')\nlib = static_library('shared', 'shared.c')\n", "library:shared", "c_library_target_metadata"},
		{"meson.build", "executable('tool', 'main.c')\n", "executable:tool", "c_executable_target_metadata"},
		{"Makefile", "all: libshared.a\nlibshared.a: shared.o\n\t$(AR) rcs $@ $^\n", "make_target:libshared.a", "c_make_metadata"},
	} {
		info := adapter.DiscoveryFile(tc.name, []byte(tc.body))
		signals, strong := adapter.DiscoveryEvidence(info.Tokens, info.Signals)
		if strong != "" || !slices.Contains(info.Tokens, tc.token) || !slices.Contains(signals, tc.signal) {
			t.Errorf("%s: metadata hints missing or overconfirmed: %+v, signals=%v strong=%q", tc.name, info, signals, strong)
		}
		if slices.Contains(info.Tokens, "executable:fake") {
			t.Error("comment was treated as a declared target")
		}
	}
}

func TestTaskCodeAuditMultilangEvidenceIsConservative(t *testing.T) {
	for _, adapter := range []taskCodeAuditLanguageAdapter{taskCodeAuditPythonAdapter{}, taskCodeAuditCAdapter{}} {
		input := make([]string, 2, 8)
		copy(input, []string{"existing_hint", "existing_hint"})
		before := slices.Clone(input[:cap(input)])
		signals, strong := adapter.DiscoveryEvidence([]string{"django", "executable:tool", "library:shared"}, input)
		if strong != "" || slices.Contains(signals, "") || slices.Contains(signals[1:], signals[0]) {
			t.Errorf("%s: unexpected confirmation or duplicate signals: %v, %q", adapter.Language(), signals, strong)
		}
		if !reflect.DeepEqual(before, input[:cap(input)]) {
			t.Errorf("%s mutated caller-owned metadata signals", adapter.Language())
		}
		notes := adapter.ReadingNotes()
		if strings.TrimSpace(notes) == "" || !strings.Contains(notes, "生命周期") || !strings.Contains(notes, "条件") {
			t.Errorf("%s reading notes do not describe lifecycle and conditional behavior", adapter.Language())
		}
	}
}
