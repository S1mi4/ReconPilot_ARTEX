# 白盒审计多语言（Java / Python / C）与开放式审计设计方案

状态：第 1–6 步的实现与离线评估夹具已在本地完成。真实模型召回率/精确率校准尚未执行；详见第 13 节。
适用范围：`server/java_code_audit*.go`、`server/codebase_discovery.go`、`db/code_audits.go`、`agent/promptcatalog.go`、前端 `web/src` 中的白盒审计相关部分。

## 1. 背景与目标

当前白盒审计只支持 Java，并且在三个方面替模型做了限定：

1. 语言：服务发现、文件分类、提示词、sink 目录、JavaCodeDB 都是 Java 专属。
2. 漏洞类型：`normalizeTaskCodeAuditVulnClass` / `db.ValidTaskCodeAuditVulnClass` 只接受 6 类（SQL 注入、命令注入、路径穿越、SSRF、XSS、不安全反序列化），枚举之外的候选会被拒绝。
3. 证据形态：证据结构是 source → sink → flow，只适合污点型漏洞。

目标：

- 同时支持 Java、Python、C。
- 不再用提示词或枚举限定"找什么"，由模型按自身能力自行审计和做污点分析。
- 平台只约束"证据是否真实"，不约束"结论是什么类型"。这与已落地的 A/B/C 分级原则一致：证据完整性是硬门槛，结论性和类别不是。

非目标：

- 不修改任何预算相关逻辑（默认不限预算是用户的明确选择）。
- 第一版不做 C 二进制审计，不做调用图索引。

## 2. 设计原则

1. 平台约束证据，不约束类型：锚点必须在范围内、行已被读过、摘录与读到的代码匹配、符号真实存在。
2. 类别是标签，不是准入条件：模型自由给出，平台只归一化和去重。
3. 语言差异只描述"怎么读代码"，不描述"该找什么漏洞"。
4. 在动态分发（Python）和宏/函数指针（C）下，符号邻近和 sink 正则误判更多，因此这类检查保持为软问题，由 B 级承接。
5. 不限定类型后，覆盖率靠平台账本保证，而不是靠类别清单。

## 3. 总体架构

分成两层：

- **语言无关的审计内核**（直接复用现有实现）：队列与续跑、分块、按 run 取消、扫描缓存、身份键、A/B/C 分级登记、硬/软校验拆分、一次修复重试、证据合并规则、前端 A/B 展示。
- **语言适配器 `LanguageAdapter`**（每种语言一份，保持很小）：
  - 服务发现标记。
  - 文件分类与排除目录。
  - 符号规范化（供身份键使用）。
  - 可选的语言阅读说明（宏、动态分发、装饰器等，不含漏洞清单）。
  - Java 适配器额外挂载可选的二进制能力（JavaCodeDB / CFR）。

适配器不再包含"漏洞类集合"和"sink 目录"。

### 3.1 各语言发现与分类

| 语言 | 构建/服务标记 | 排除目录示例 |
| --- | --- | --- |
| Java | pom.xml、build.gradle(.kts)、settings.gradle | build、target、generated |
| Python | pyproject.toml、setup.py、requirements.txt、manage.py | venv、.venv、site-packages、`__pycache__` |
| C | Makefile、CMakeLists.txt、configure.ac、meson.build | build、third_party、vendor |

- `task_code_services` 增加 `language` 字段，允许多语言服务。
- 混合语言服务按文件所属语言分块，同一块不跨语言。
- 现有 Kind（java/template/config/test）改为"语言无关的 kind + 语言标识"。

### 3.2 二进制模式

JavaCodeDB / CFR 反编译只属于 Java 适配器的可选能力。C 与 Python 只走源码模式。C 二进制审计留待后续单独立项。

## 4. 开放式漏洞类型

### 4.1 去掉的限制

- `db.ValidTaskCodeAuditVulnClass` 的枚举准入：改为只校验非空、长度与字符集。
- `taskCodeAuditSinkPatterns` 的 API 族正则：保留为"提示"或直接删除，不再作为拒绝依据。
- `taskCodeAuditCommandSinkIsExecution` 等按类别写死的判定：仅在归一化后落入对应桶时作为软提示。
- 提示词中不再列"重点关注类型"，只写平台证据契约。

### 4.2 类别归一化

- 模型自由给出 `vuln_class`，可选 `cwe`。
- 平台映射到已知桶（SQL_INJECTION、COMMAND_INJECTION、PATH_TRAVERSAL、SSRF、XSS、UNSAFE_DESERIALIZATION、MEMORY_SAFETY、CODE_INJECTION、AUTHZ、CRYPTO、RACE、LOGIC 等），映射不上归 `OTHER`，并保留模型原始标签（`vuln_class_raw`）。
- 原因：`vuln_class` 同时用于身份键去重、筛选、报告模板和 UI 分组。完全自由的字符串会因写法不同造成重复登记。
- 身份键改为"文件 + 锚点符号 + 归一化类别桶"，不再依赖精确枚举值。命令注入的链条归一化只在命中该桶时生效。
- 已有数据按原值映射到对应桶，不需要迁移类别含义。

## 5. 证据结构：锚点 + 推理链

### 5.1 新结构

- `anchors[]`：每项含文件、行号、摘录、角色。角色由模型自由命名，如 source、sink、check、alloc、free、lock、missing_check。
- `reasoning_chain[]`：按顺序引用锚点，说明漏洞成立的推理。
- 污点分析仍然支持，source/sink 只是角色名，不再是必填字段。

这样可以覆盖没有 source/sink 概念的漏洞：鉴权绕过、竞态、加密误用、业务逻辑、C 的内存生命周期问题等。

### 5.2 校验规则（与类别无关）

硬门槛（失败即 C 级，存为 incomplete）：

- 标题、类别、至少一个核心锚点。
- 锚点文件在审计范围内。
- 锚点行号已被本次读取覆盖。
- 锚点符号在行附近真实存在。
- 二进制模式下的来源信息完整（仅 Java）。

软问题（降为 B 级，置信度强制为 low，不自动排队报告）：

- 该类别"通常期望"的证据缺失，例如缺 flow、缺入口、缺控制措施、缺利用性说明。
- 摘录非逐字匹配。
- 可选的 API 提示不匹配。
- 置信度不是 high/medium。

### 5.3 兼容

保留旧的 `source` / `sink` / `flow` 字段。出现时自动转换为锚点，因此已有数据、测试与前端不会失效。

## 6. 覆盖率保障（新增）

不限定类型后，主要风险是模型在每个文件上"随便看看"。平台层补两个机制：

1. **文件覆盖账本**：记录哪些生产文件被读过、被分析过；遗漏的文件进入补审队列。复用现有分块与续跑能力。
2. **收尾扫描**：各块完成后，带着已登记发现，让模型专门寻找跨文件、跨模块的遗漏。

## 7. 提示词与命名

- Agent 重命名为 `whitebox_audit`，语言作为参数。
- 提示词拆成"通用契约 + 语言阅读说明"。
- 保留 `whitebox_java_audit` 作为别名，避免已有配置和数据失效。
- 文件名 `java_code_audit*.go` 暂不重命名，等适配器稳定后再处理。

## 8. 语言特定风险（只做处理方式说明）

- **Python**：动态分发、装饰器路由、框架隐式入口。符号邻近检查对属性访问要放宽；sink 提示不作拒绝依据。
- **C**：宏、函数指针、条件编译。内存安全类漏洞用锚点（alloc/use/free/check）表达，而不是 source→sink。
- 两者的标识符正则需要放宽到各自的写法（例如 Java 的 `$`、C 的 `->`、Python 的点号属性）。

## 9. 影响面

| 层 | 改动 |
| --- | --- |
| `db` | `ValidTaskCodeAuditVulnClass` 去枚举准入、新增 `vuln_class_raw`、身份键重算、`task_code_services.language` |
| `server` | 适配器接口、锚点证据解析与校验、类别归一化、覆盖账本、收尾扫描 |
| `agent` | 提示词拆分与重命名 |
| `web` | 类别展示改为归一化桶 + 原始标签、锚点列表展示、语言标识 |
| `schema.sql` | 幂等迁移，保持与现有迁移风格一致 |

## 10. 落地顺序

1. **泛化，不加语言**：类别开放化 + 锚点证据泛化，仍只跑 Java；Java 现有测试保持通过，并补充"枚举外类别可登记""无 source/sink 的锚点证据可登记"测试。
2. **抽取适配器接口**：把 Java 实现原样迁入，行为不变。
3. **接入 Python**：最接近现有模型，用来验证抽象是否正确。
4. **接入 C**：重点验证内存安全类锚点表达。
5. **覆盖账本与收尾扫描**。
6. 每种语言准备一个靶场项目，统计 A/B/C 各层比例与拒绝原因，再调校阈值。

## 11. 测试与验证

- Go：适配器发现与分类单测；类别归一化与身份键单测；锚点校验（硬/软）单测；DB 合并与晋升回归（沿用 `db/code_audit_registration_test.go`）。
- 前端：`cd web && npm run check`，涉及编译时 `npm run build:static`。
- 实测：各语言靶场上的 A/B/C 分布、重复登记率、漏报抽查。

## 12. 风险与待决事项

- 类别完全开放会增加去重难度，依赖归一化桶的质量，需要持续调整映射表。
- 去掉类别提示后，模型输出的类型分布会更不稳定，需要靶场实测对比。
- 锚点角色是自由文本，前端展示需要容忍未知角色。
- 覆盖账本会增加一轮模型调用的时间，是否默认开启待实测后决定。
- C 二进制审计与调用图索引（tree-sitter / ctags）作为后续增量，不在本方案范围。

## 13. 实施进展

### 第 1 步（类别开放化 + 锚点证据泛化，仍只跑 Java）：已完成

- `db.ValidTaskCodeAuditVulnClass` 不再是枚举，只校验 `^[A-Z][A-Z0-9_]{0,63}$`。
- `normalizeTaskCodeAuditVulnClass` 先把常见同义词归到共享桶（含 AUTHORIZATION_BYPASS、CODE_INJECTION、BUFFER_OVERFLOW 等）；其余标签生成 UPPER_SNAKE slug；没有 ASCII 字母的标签生成稳定的 `OTHER_<hash>`，保证不同标签不会互相合并。
  - 与 4.2 的差异：没有新增 `vuln_class_raw` 字段。模型原始标签保存在候选的 `category` 中，不额外落库。
- 候选新增 `anchors[]`（role/file/line/symbol/description）和 `reasoning_chain[]`，旧的 source/sink/flow 保持兼容。
  - 有 anchors 时 source/sink 可省略；source/sink 只填一部分仍是硬问题。
  - 没有 anchors 时保持原有严格的 source→sink 契约。
  - 每个 anchor 都做硬校验：范围内、已读取、符号出现在行附近。缺 role、缺 reasoning_chain 属于软问题（B 级）。
- 身份键：没有 source/sink 坐标时，使用"类别 + 去重排序后的 (文件, 规范化符号)"，不依赖行号、顺序和措辞。命令注入的链条键逻辑不变。
- 二进制来源信息（provenance）支持 anchors；比较改为 `reflect.DeepEqual`。
- 提示词与平台契约不再列出"重点类型"，模型自行命名 category；前端新增锚点和推理链展示，source/sink 为空时不再显示 "?:?"。
- 测试：`java_code_audit_open_class_test.go`（类别归一化、锚点硬/软规则、身份键）和 `db/code_audit_registration_test.go` 中的"锚点类候选只登记一次"。

### 第 2 步（抽取适配器接口，保持 Java 行为）：已完成

- 新增 `server/code_audit_language.go`，定义内部 `taskCodeAuditLanguageAdapter` 接口，负责语言标识、文件分类、目录裁剪、服务发现元数据与语言阅读说明。生产实现目前只注册 Java；未知语言返回不支持，不回退为 Java。
- 新增 `server/code_audit_language_java.go`，迁入原有 Java 源码/测试/JSP/配置文件分类、Maven/Gradle 标记和元数据提取、聚合工程判定及构建证据规则。保留源根下 `vendor/build/lib` 等合法包名，以及扫描 `lib/libs` 中二进制包的原有行为。
- 代码库通过选定的适配器收集文件、裁剪目录；未带语言信息的现有快照仍默认 Java。生产文件判断集中到一个函数，队列执行、文件计数、分块与入口证据校验共用，兼容原有 `java` 和 `template`，为后续适配器支持通用的 `source`。
- 服务发现通过适配器识别源码与构建清单，并提取元数据；发现过程仍不读取源码正文，原有构建清单大小限制保持不变。Java 聚合工程信号由 Java 适配器产生。
- 提示词拆分为通用证据契约与适配器的语言阅读说明；Java 框架、装配与进程调用说明集中到 Java 适配器。不增加漏洞类型白名单。
- 兼容性决策：暂保留 `whitebox_java_audit` 配置键与自定义提示词读取方式，不新增 Agent、不覆盖用户提示词；保留 `java_files`、`kind="java"` 等既有字段。服务语言字段、通用 Agent 键与混合语言分块随 Python/C 接入落地，避免本次纯重构引入迁移。
- JavaCodeDB 与二进制来源校验继续走已有独立流程，源码适配器不要求实现反编译。
- 身份键与符号规范化仍由现有 DB 逻辑处理，本步不重算身份键、不更改去重语义；后续出现实际语言差异时再扩展该接口。
- 新增 `server/code_audit_language_test.go`：验证 Java 分类/目录/发现证据兼容性，并用仅测试用适配器验证文件收集、工具读取、发现元数据与提示词确实使用选定适配器。测试用适配器不注册到生产。
- 预算逻辑未修改；没有前端或数据库结构变更。
- 验证结果：新增适配器测试、带 `javacodedb` 标签的服务发现/白盒审计回归、DB 白盒审计回归均通过；`go vet ./server ./agent ./db`、`go vet -tags javacodedb ./server`、gofmt 与 `git diff --check` 通过。
- 已执行 `go test ./...`：`server` 包通过；全仓仍因先前已有的会话目录重复 `main`、agent 审批/任务范围测试、DB 拦截规则外键测试、intercept 静态 sed 测试和 llmrec 缺表测试而失败，详见本地 `/tmp/artex-adapter-go-full.log`。测试使用单独的临时 PostgreSQL 容器，未使用运行中的 ARTEX 数据库。未进行真实 LLM 审计实测；本步无前端改动，未重复前端构建。

### 第 3 步（Python）与第 4 步（C）：已完成

- 注册 Python、C 源码适配器，并支持单语言或 Java/Python/C 混合服务。混合服务使用同一服务记录和运行记录，按语言拆分主要审计块；Java 二进制能力仍仅对包含 Java 的服务开放。
- Python 识别 `.py` 生产实现、模板、测试与配置上下文；C 识别 `.c/.h` 实现与头文件。分别处理测试目录、虚拟环境/依赖/生成目录、常见构建清单。发现仅读取受限声明式元数据，不执行或导入目标代码；Python 的 `setup.py`/`manage.py` 会作为源代码审计，但其正文不作为构建元数据解析。
- 服务发现保存 `languages` 与按语言统计的源码数量。语言证据由扫描器产生；较旧记录缺少语言时仍按 Java 兼容。较早版本扫描的迟到结果不会覆盖最新版本的语言集合。
- 发现、分类、混合文件分块、原生锚点证据、大小写/限定名身份去重、Java 二进制分派均有自动回归测试。

### 第 5 步（覆盖账本与收尾扫描）：已完成

- 运行记录持久化每个生产文件的语言、实际读取状态、模型声明分析状态、尝试次数和观察到的行数。只有本轮分配、通过只读工具读到并在顶层 `analyzed_files` 声明分析完成的文件才推进分析覆盖；搜索命中或模型单独声称覆盖不够。
- 每次执行最多自动补审一轮；仍有缺口时保存为可续跑状态。续跑以文件台账为准，不依赖可能跳过缺口的旧数字游标。
- 所有生产文件补齐后按生产语言进行收尾扫描。每种语言的扫描需实际读取该语言的生产源码；扫描进度持久化，续跑跳过已完成扫描。只有完成台账和所有扫描后才将新式源码运行标记完成。
- Finding 历史对账会校验新式运行的文件台账、分析状态与收尾扫描，避免覆盖不完整时把未再次观察到的旧 Finding 标记为已修复。历史运行和 Java 二进制运行没有文件台账，继续使用原有对账规则。
- 台账表示实际工具读取和模型自述分析的组合，并非逐行覆盖证明或“无漏洞”证明；行数是一次运行中观察到的最大 distinct 行数，并非跨续跑行集合的精确并集。前端明确显示读取/分析/缺口与收尾状态。

### 第 6 步（离线靶场夹具）：已完成

- `server/testdata/multilang_audit/` 提供 Java、Python、C 各一组小型源码夹具和测试上下文，每种语言包含一个预期问题与一个安全对照。
- 通过 `server/code_audit_fixture_inventory_test.go` 验证适配器收集、生产/测试分类、源码读取及锚点可读性。夹具不会被编译、执行或部署。
- `server/testdata/multilang_audit/README.md` 说明稳定锚点、预期结果、隔离使用方式及 A/B/C 评估流程。没有运行真实模型，因此尚无召回率、精确率、重复率或阈值校准数据。模型评估只应在隔离的本地实验环境执行，不暴露夹具服务。

### 验证结果与限制

- 已通过定向 Go 回归：Java/Python/C 服务发现和分类、混合语言 inventory/分块、开放类别与锚点证据、原生身份键、补审、覆盖持久化、收尾扫描续跑、Finding 对账、归档兼容、会话别名 token 聚合，以及新增夹具 inventory 测试。
- `go vet ./server ./agent ./db` 通过；带 `javacodedb` 的 Java、服务发现、多语言覆盖定向回归通过。DB 与服务端集成测试使用临时独立 PostgreSQL，没有连接运行中的 ARTEX 数据库。
- `web` 静态构建通过。全量 `npm run check` 当前报告仓库 221 个文件中 115 个错误、210 个警告、819 个提示；错误分布涉及既有全仓格式与 lint 问题。需在有基线对比的后续整理中处理。真实浏览器交互未验证。
- `go test ./...` 已执行但全仓未通过，失败来自此前存在的任务范围/审批、拦截规则外键、静态 sed 和缺失 llmrec 表等测试；`server` 包在该全量运行中通过。最近变更另有上述定向回归通过。完整失败记录位于本机 `/tmp/artex-multilang-go-full.log`。
- 预算默认值、预算判断与预算界面未修改；没有提交或推送。
