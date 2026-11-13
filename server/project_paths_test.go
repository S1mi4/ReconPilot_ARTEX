package server

import (
	"os"
	"path/filepath"
	"testing"
)

// 磁盘也按项目分区：任务文件在 <data>/projects/<project>/tasks/<task>/ 下，老目录
// 第一次被访问时搬过去（同一文件系统 rename），不会留下两份。
func TestTaskDataDirAdoptsLegacyLayout(t *testing.T) {
	base := t.TempDir()
	m := &Manager{dir: base, tasks: map[string]*Task{}}

	legacy := filepath.Join(base, "tasks", "7", "reports")
	if err := os.MkdirAll(legacy, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	dir := m.taskDataDir(3, 7)
	want := filepath.Join(base, "projects", "3", "tasks", "7")
	if dir != want {
		t.Fatalf("task dir = %s, want %s", dir, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "reports", "a.txt")); err != nil {
		t.Fatalf("legacy files were not adopted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "tasks", "7")); !os.IsNotExist(err) {
		t.Fatalf("legacy dir still present after adoption: %v", err)
	}

	// 不同项目永远不会解析到同一个目录。
	if m.projectDataDir(4) == m.projectDataDir(3) {
		t.Fatal("two projects must not share a data directory")
	}
	// 没有项目（迁移前的裸调用）保持原布局。
	if got := m.taskDataDir(0, 0); got != base {
		t.Fatalf("project-less base = %s, want %s", got, base)
	}
}
