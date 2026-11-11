# antigravity-context-unlock

**解除 Antigravity 桌面端应用（`language_server`）在 Google OAuth 原生通道下的 256K 本地上下文自动压缩限制，将本地压缩预算提升至模型声明的物理上界（`maxTokens - maxOutputTokens`，例如 `Gemini 3.8 Flash` 由 `256,000` 提升至 `983,040` tokens），并附双通道（Google OAuth 原生通道与企业网关通道）完整逆向机制报告。**

- **适用软件**：Antigravity 桌面端应用（核心推理引擎 `/opt/Antigravity/resources/bin/language_server`，**非**命令行工具 `antigravity-cli` / `/usr/bin/agy`；命令行版请参阅 [`agy-context-unlock`](https://github.com/MatrixC7/agy-context-unlock)）
- **已验证版本**：`antigravity 2.31.0-1` Linux x86-64（`Built at CL: 1017595969`；原版 `SHA256: e49711c4f7b2fa0e62c0e130c9566579423094b63647bdce82f4ddd81eeb983f`，补丁后 `SHA256: a1ceb2f2064835273524310592dc35998767f6bec81d05882117b9d1b85c7e6e`），并通过动态解析 Go `pclntab` 符号表与 59 字节指令窗口签名支持跨版本定位
- **各通道机制与适用说明**：
  - **Google OAuth 原生通道**（`daily-cloudcode-pa.googleapis.com`）：未修补时，`Gemini 3.8 Flash` 与 `Gemini 4 Argon` 的本地预算均被限制在 `256,000` tokens，且桌面端不存在 UI 档位切换器或覆盖环境变量；**应用本仓库 8 字节补丁后，本地预算自动采用引擎计算的物理上界 `maxTokens - maxOutputTokens`（如 `983,040` tokens，提升 3.84 倍）**
  - **企业网关 / 自定义模型通道**（通过 `~/.antigravity/settings.json` 的 `gateway` 或 `AGY_LLM_GATEWAY_*` 接入，`apiProvider = 31`）：桌面端默认已绕开 256K 钳位分支，直接按网关目录参数计算预算（如 `1,000,000 - 128,000 = 872,000` tokens），**无需二进制补丁即可通过目录参数配置**
- **运行依赖**：仅需 Python 3 标准库（零第三方依赖）
- **许可证**：[MIT License](LICENSE)

---

## 1. 背景与问题定义

在 Antigravity 桌面端中使用 Google 账号登录（OAuth 原生通道）进行长对话时，尽管 `Gemini 3.8 Flash` 与 `Gemini 4 Argon` 系列模型宣告的最大输入容量为 **1,048,576 tokens**（`maxTokens = 1048576`，`maxOutputTokens = 65536`），对话仍会在服务端输入约 **23.4 万 tokens**（对应本地 SQLite 诊断估算字段 `estimated_tokens_used` 约 **42.5 万–43.8 万**，或日常混合代码对话中约 **24.0 万–25.6 万**）时触发自动压缩（Checkpointing），将早期多轮历史替换为一段延续摘要。

通过对桌面端推理引擎 `language_server`、Electron 前端归档包 `app.asar` 以及 TLS 流量的联合审计，可以确认以下三项核心事实：

1. **自动压缩由本地 `language_server` 引擎主动发起，而非云端推理接口在主请求上的硬性截断。**
   发往 `v1internal:streamGenerateContent` 的主请求 JSON 中不包含任何 `checkpointConfig`、`maxTokenLimit` 或 `contextWindow` 字段。引擎在每轮发送主请求前，通过内部混合计量（历史模型报告用量前缀 + 本轮新增消息本地估算增量）与本地预算上限 `CheckpointConfig.MaxTokenLimit` 比较；一旦超限，客户端会主动发送一条独立的 `requestType: "checkpoint"` 摘要请求，在本地 SQLite `steps` 表写入一条 `step_type = 23` 的记录，并用摘要替换历史消息（请求体体积缩减约 95.6%）。与此同时，引擎向 `v1internal:recordTrajectoryAnalytics` 上报的遥测载荷中直接包含内存里生效的 `"maxTokenLimit": 256000`。
2. **桌面端原生通道不存在用户可达的配置入口（与命令行工具 `agy` 不同）。**
   命令行工具 `agy` 二进制内预置了 `/model` 菜单档位切换器、`settings.json` 的 `contextWindow` 读取函数及 `AGY_CLI_AUTO_COMPACT_OVERRIDE` 环境变量（仅被内部门禁阻断）；而桌面端 Electron 前端包（`app.asar` 全部 1,097 个条目）未实现上下文窗口档位选择器，引擎侧 Checkpoint 决策链路的 12 个核心函数也不读取任何窗口覆盖环境变量。
3. **引擎内部存在两重独立的 `256,000` 预算约束（仅作用于原生通道，企业网关天然豁免）：**
   - **第一重（Provider 默认钳位）**：`utils.GetCheckpointConfig` 针对 `apiProvider` 为 `3`（Vertex）、`24`（Google Gemini）或 `26`（Anthropic Vertex）的模型执行 `min(x, 256000)` 钳位。（企业网关模型的 `apiProvider` 为 `31`，在此处直接跳过钳位。）
   - **第二重（按模型策略覆盖）**：`config.applyFeatureProviderCheckpointOverrideConfig` 读取模型目录中的 `CASCADE_USE_EXPERIMENT_CHECKPOINTER` 策略对象（`Gemini 3.8 Flash` 与 `Gemini 4 Argon` 均为 `"max_token_limit": "256000"`），并通过 `config.MergeConfigsDedup` 覆盖默认配置；随后由 `config.clampAndValidateConfig` 调用 `utils.ClampCheckpointConfigForModelInfo` 执行模型容量上界检查。因此，仅修改第一重默认钳位无法改变最终生效的 `256,000` 预算。

---

## 2. 解决方案：8 字节二进制补丁（动态物理上界）

`antigravity_context_unlock.py` 内置纯 Python 标准库实现的 ELF64 与 Go 1.18+ 运行时符号表（`pclntab`）解析器。脚本不依赖固定文件偏移，而是按符号名定位目标函数 `utils.ClampCheckpointConfigForModelInfo`，在校验全文件唯一的 **59 字节上下文指令窗口**后，替换该上界检查点的 **8 字节指令序列**（全文件实际仅变动 **5 个字节值**）：

| 阶段 | 机器码字节（8 字节站点） | x86-64 汇编语义（`CL 1017595969`，`0x6ab7460`） | 行为说明 |
|---|---|---|---|
| **修补前** | `39 70 0c 76 03 89 70 0c` | `cmp [rax+0xc], esi` ; `jbe .done` ; `mov [rax+0xc], esi` | 仅当 `MaxTokenLimit > esi` 时才将其下压至物理上界 `esi`，保留上游合并进来的 `256,000`。 |
| **修补后** | `89 70 0c eb 03 90 90 90` | `mov [rax+0xc], esi` ; `jmp .done` ; `nop ×3` | **无条件**将引擎已计算好的物理上界 `esi` 写入 `CheckpointConfig.MaxTokenLimit`（`[rax+0xc]`）。 |

### 为什么该方案简洁且自洽

1. **零硬编码阈值常数**：寄存器 `esi` 由引擎自身在站点前序指令（`0x6ab7453..0x6ab7459`）根据当前模型的 `ModelInfo` 动态算出：
   $$\text{MaxTokenLimit} = \text{ModelInfo.MaxTokens} - \text{ModelInfo.MaxOutputTokens}$$
   对于 `Gemini 3.8 Flash`（`1,048,576 - 65,536`），运行期自动得到 **`983,040`**（原版 `256,000` 的 **3.840 倍**），无需手动维护配置文件或启动包装脚本。
2. **满足引擎自身的上界校验**：在常规模型参数（`0 < maxOutputTokens < maxTokens`）下，写入值恰好等于后续校验函数 `utils.ValidateCheckpointConfigForModelInfo`（`0x6ab74a0`）允许的最大合法上界 `ctx - maxOutputTokens`，不会触发内部配置校验错误。
3. **完整保留其余策略语义**：补丁仅改写偏移 `+0xc`（`MaxTokenLimit`），策略合并阶段写入的 `use_model_reported_token_count`（决定使用服务端真实 Token 前缀而非粗糙字节估算）、`token_threshold`、`strategy`、`is_sync`、延续摘要提示词及单条消息 `192 KB` 截断逻辑均保持原样。

---

## 3. 安装与使用指南

### 前置条件

1. **先完全退出 Antigravity 桌面端应用**（确保后台无正在运行的 `language_server` 进程），且不要在系统包管理器升级 `antigravity` 的同时执行修补。
2. 确认目标二进制文件的写权限：在标准软件包安装下，若 `/opt/Antigravity/resources/bin/language_server` 属主为 `root:root`，请在 `patch` 与 `restore` 命令前加上 `sudo`；若目录归属当前用户，可直接运行。

### 标准操作流程

```bash
git clone <repository-url> ~/.local/share/antigravity-context-unlock
cd ~/.local/share/antigravity-context-unlock

# 1. 只读自检：解析 Go 符号表、校验 59 字节指令窗口（默认不强制构建哈希白名单）
python3 antigravity_context_unlock.py self-test

# 2. 应用补丁（首次运行自动在同目录创建原子备份 language_server.ctxunlock-backup 及哈希元数据）
sudo python3 antigravity_context_unlock.py patch --yes

# 3. 校验补丁状态与备份配对关系（确认输出 state : PATCHED 且 pairs : yes）
python3 antigravity_context_unlock.py verify
```

确认输出包含 `state  : PATCHED` 与 `pairs : yes` 后，正常启动 Antigravity 桌面应用即可生效，日常使用无需任何额外参数或环境变量。

### 软件包升级后的处理方式

`/opt/Antigravity/resources/bin/language_server` 由系统软件包（如 Arch Linux 上的 `antigravity`）管理，每次软件包升级都会用新版原厂二进制覆盖该文件：

1. **手动更新**：
   - 升级完成后可先运行 `python3 antigravity_context_unlock.py self-test`，查看新版本是否通过结构签名检查。默认不要求 SHA256 在白名单中；只有显式指定 `--strict-build` 才强制白名单。
   - 执行 `sudo python3 antigravity_context_unlock.py patch --yes --refresh-backup`：若现有备份属于另一构建，脚本先将新版原文件及 `.json` 侧车写入临时文件并同步，再原子替换旧备份、更新侧车，确认配对后修补。**只保留最新构建的一份原版备份，不再生成历史归档。**
   - 不带 `--refresh-backup` 时仍保留原行为：遇到不同构建的备份退出 `3`，不覆盖旧备份。不带 `--yes` 时仅预览，不写入。已修补文件保持幂等，不刷新备份。
   - 新备份准备失败时旧备份不受影响；目标文件只在新版备份确认可用后才修补。不支持的指令结构、不可读备份、当前构建的侧车哈希不一致仍会中止；刷新时也拒绝替换符号链接或非普通文件。旧工具已生成的归档不会自动删除，可按需手动清理。
2. **Pacman 自动更新 Hook（可选，适用于 Arch Linux / EndeavourOS / CachyOS）**：
   - 仓库 [`pacman/99-antigravity-context-unlock.hook`](pacman/99-antigravity-context-unlock.hook) 提供了 `PostTransaction` Hook 模板，已使用 `patch --yes --refresh-backup`，新版通过结构校验即可自动刷新最新备份并重新修补。已有安装若已使用此参数，只需更新脚本；更早的安装还需同步 Hook 的 `Exec` 参数。
   - **安全提示**：Pacman Hook 由 `libalpm` 以 `root` 权限直接通过 `execv(3)` 调用（不经过 shell，`~` 与 `$HOME` 均不展开）。若启用自动 Hook，务必先将 `antigravity_context_unlock.py` 安装至 `root:root` 拥有且普通用户不可写的系统目录（如 `/usr/local/share/antigravity-context-unlock/`），切勿在 Hook 中指向普通用户主目录下的可写路径。

---

## 4. 适用场景与各通道表现对比

| 客户端与接入通道 | 代表模型 | 未修补时的本地预算与表现 | 修补后的本地预算与表现 |
|---|---|---|---|
| **Antigravity 桌面端**<br>Google OAuth 原生通道 | `Gemini 3.8 Flash (High)`<br>`Gemini 4 Argon (High)` | `max_context_tokens = 256,000`<br>（受控填充下服务端 SSE 约 **234K**、DB 估算约 **425K–438K** 时触发 `step_type=23` 压缩） | **`max_context_tokens = 983,040`**（`1,048,576 - 65,536`）<br>（Flash 实测连续 40 轮、DB 估算达 **1,117,452** 全程 0 次压缩） |
| **Antigravity 桌面端**<br>企业网关通道（`apiProvider = 31`） | `<gateway>/gemini-3.8-flash-high`<br>`<gateway>/gemini-4-argon-high`<br>`<gateway>/deepseek-v4.1-flash-1017` | **默认已为 `872,000`**（当目录声明 `1,000,000 / 128,000` 时；实测 SSE 达 **625K–718K**、请求体达 **3.49 MB** 后才压缩） | **无需打二进制补丁**；需要调整预算时直接修改网关目录（`models.listSource`）返回的 `maxTokens` / `maxOutputTokens` 即可 |
| *(对照)* **`antigravity-cli`（`agy`）**<br>原生通道 & 企业网关通道 | 原生及网关各模型 | 两条通道均被钳位在 **`256,000`**，且受单模型白名单与 Feature Flag 阻断 | 需使用针对 CLI 的 20 字节补丁工具（[`agy-context-unlock`](https://github.com/MatrixC7/agy-context-unlock)）解锁 `/model` 与 `settings.json` |

---

## 5. 验证与诊断工具

### 1. 静态状态校验与内嵌策略表查看（纯离线只读）

```bash
# 查看当前补丁状态、构建匹配信息及备份配对状态
python3 antigravity_context_unlock.py verify

# 查看二进制文件内嵌的各模型家族默认 Checkpoint 预算表
python3 antigravity_context_unlock.py info
```

### 2. SQLite 会话数据库只读检查（`tools/inspect_session.py`）

无需启动应用，以双重只读保护（`mode=ro` + `PRAGMA query_only=ON`）解析 `~/.gemini/antigravity/conversations/<uuid>.db` 中的 `gen_metadata` 与 `step_type = 23` 压缩记录（仅读取数值诊断元数据，不读取对话正文）：

```bash
python3 tools/inspect_session.py <conversation-uuid-or-db-path> --rows
```

### 3. 独立引擎在线功能验证（`verify_live.py`）

以 `--standalone` 模式在本地回环端口拉起 `language_server`（不启动 Electron GUI），发送 2 轮测试消息并只读校验落库的 `max_context_tokens` 是否等于预期值：

```bash
# 若网络环境需经代理访问 Google 服务，可通过 HTTPS_PROXY 环境变量或 --proxy 指定
python3 verify_live.py --expect 983040
```

### 4. 离线单元测试套件

包含自动化测试（合成 Go 1.18+ ELF64 夹具、59 字节窗口边界与立即数假阳性拦截、跨版本单份备份刷新与干跑/中断保护、备份侧车与单快照还原竞争防护、真实二进制临时副本往返哈希校验及会话解析器测试）：

```bash
python3 -B -m unittest discover -s tests -v
```

---

## 6. 仓库文档导航

本仓库按“通俗概念导读 → 补丁逆向实现 → 双通道完整取证报告”提供分层文档体系，便于不同背景的读者按需查阅：

### 通俗导读与补丁实现原理
- **[《原理与使用指南（通俗导读）》（`docs/overview-and-guide.md`）](docs/overview-and-guide.md)**
  面向所有读者：用清晰的问答与流程图解释桌面端自动压缩的触发过程、三种 Token 计数口径与内部混合计量公式、为什么桌面端原生通道与命令行 `agy` 的解锁方式不同、以及为什么桌面端企业网关天然拥有 872K 预算。
- **[《二进制补丁与脚本实现详解》（`docs/binary-patch-internals.md`）](docs/binary-patch-internals.md)**
  面向开发者与逆向工程读者：深入解析 `antigravity_context_unlock.py` 的 ELF64 + Go `pclntab` 解析器、`CheckpointConfig` 调用链与两重 256K 约束、59 字节指令签名与 8 字节补丁反汇编对比、备份/配对安全状态机，以及 `Gemini 3.8 Flash` 修补前后 23 轮 vs. 40 轮受控实测数据。

### 深度技术报告与实验证据
- **[《技术报告：Google OAuth 原生通道上下文机制与实测数据》（`docs/mechanism-native-oauth.md`）](docs/mechanism-native-oauth.md)**
  完整记录桌面端原生通道的六步生命周期、内部混合计量汇编、`recordTrajectoryAnalytics` 遥测载荷、`selectCheckpointExperimentKey` 三级实验键探测与 Protobuf 枚举描述符静态溯源、`Gemini 3.8 Flash` / `Gemini 4 Argon` 逐轮实测表及 5,437 轮历史真实会话统计。
- **[《技术报告：企业网关与自定义模型通道上下文机制与实测数据》（`docs/mechanism-enterprise-gateway.md`）](docs/mechanism-enterprise-gateway.md)**
  完整记录桌面端企业网关通道的 Tier 1–4 模型发现链路、`apiProvider = 31` 绕开 256K 钳位的汇编算式、OpenAI `/v1/chat/completions` 协议指纹、三模型（Flash / Argon / DeepSeek）77 行实测对照表、单条消息 192 KB 截断溯源，以及 `creepDS3` 反例实验与证据边界分析。

---

## 7. 安全机制、已知边界与一键回滚

### 安全防护设计
- **全文件唯一 59 字节指令窗口**：同时校验补丁点前 30 字节、补丁点 8 字节与补丁点后 21 字节，要求该 59 字节序列在全文件中唯一出现且完整落在目标函数 `[va, end)` 内，杜绝误匹配指令立即数或数据表；若未来构建函数结构变化，脚本以退出码 `3` 安全中止，不写入任何字节。
- **强制前置备份与侧车校验**：补丁提交前必须确认同目录存在匹配原版二进制的备份文件（`language_server.ctxunlock-backup`，首次通过 `os.link` 原子创建）并校验已有 `.ctxunlock-backup.json` 哈希侧车。`--refresh-backup` 仅在当前文件为已通过结构校验的原版且备份属于另一构建时，通过 `os.replace` 将旧备份替换为新版配对备份；不保留历史版本。
- **单快照决策与原子替换**：每次运行仅读取一次目标二进制快照，写入前重新核对磁盘 `inode / dev / size / mtime_ns` 防止并发升级冲突，并通过同目录临时文件 + `fsync` + `os.replace` + 目录 `fsync` 完成原子替换。
- **内容级配对还原**：`restore` 仅读取一次备份快照，并在写回前验证“对备份重施 8 字节补丁能否逐字节复现当前目标文件”，防止误将旧版本的备份还原到新版本安装目录中。

### 已知边界说明
1. **客户端门禁解除不等于扩容上游物理窗口**：`983,040` 是客户端引擎根据模型声明容量算出的本地预算上限；实际超长会话能否跑到接近 1M tokens 仍取决于 Google 云端推理服务当时的真实物理限制、超时策略与账号配额。
2. **作用范围涵盖经过该函数的全部模型**：补丁修改 `utils.ClampCheckpointConfigForModelInfo` 函数体，对所有经过该函数且 `maxTokens > 0` 的原生模型统一生效，不提供按单一模型过滤的独立开关。
3. **单条用户消息截断独立存在**：引擎在 `TrajectoryConversionConfig.MaxTokensPerUserInputStep` 中默认对单条用户输入保留约 `192 KB`（`64,000 × 3` 字节），该限制独立于多轮会话总预算，本补丁未改动该参数。

### 一键还原原版二进制

```bash
# 先退出 Antigravity 桌面应用，再从配对备份原子还原原版 language_server
sudo python3 antigravity_context_unlock.py restore --yes

# 如曾手动安装 Pacman Hook，一并移除
sudo rm -f /etc/pacman.d/hooks/99-antigravity-context-unlock.hook
```

---

## 8. 致谢与参考

本项目的机制分析、抓包取证与实验设计，参考了社区中关于 Antigravity 上下文行为的相关讨论与记录。感谢以下来源提供的线索与背景资料：

- **[google-antigravity/antigravity-cli Issue #1245](https://github.com/google-antigravity/antigravity-cli/issues/1245)**
  官方仓库中关于上下文窗口实际生效范围的 Issue 讨论，为本项目最初确认"256K 行为需要独立验证"提供了重要切入点。
- **[afengblog：Google Antigravity 256K 上下文窗口限制与无头模式政策变更](https://afengblog.com/blog/antigravity-256k-context-discrepancy.html)**
  对 Antigravity 上下文容量与实际压缩点之间差异的整理，为本项目梳理"多种 Token 计数口径"提供了参考视角。
- **[linux.do 讨论帖 topic/3117832](https://linux.do/t/topic/3117832)**
  社区中对相关现象的实测交流与经验分享，为实验方向的取舍提供了帮助。

在机制梳理、脚本实现、文档撰写与实测验证中，主要工作由以下大语言模型完成：**Gemini 3.8 Flash**、**Gemini 4 Argon**、**DeepSeek V4.1 Flash 1017** 与 **GPT-6.1 Sol**；仓库维护者仅提供了需求设定、运行环境与实机测试条件等协助。谨致谢意。

---

## 9. 许可证

本项目基于 [MIT License](LICENSE) 发布。
