# 二进制补丁与脚本实现详解（`antigravity_context_unlock.py`）

> 本文档面向开发者、系统管理员与逆向工程研究人员，详细说明 `antigravity_context_unlock.py` 的内部实现原理、Go 1.18+ `pclntab` 动态符号解析算法、`CheckpointConfig` 构造链路中的两重 256K 约束、59 字节指令窗口与 8 字节补丁的反汇编对比、备份与还原安全状态机，以及在 `antigravity 2.31.0-1`（`CL 1017595969`）上的受控 A/B 实测数据。

---

## 1. 设计目标与架构概览

Antigravity 桌面端的核心推理与会话编排引擎 `/opt/Antigravity/resources/bin/language_server` 是一个体积约 206.8 MB 的 Go 语言 Linux x86-64 PIE（位置无关可执行）二进制文件。虽然标准 ELF 符号表已被剥离（stripped），但二进制内部完整保留了 Go 运行时函数表（`pclntab`）。

与命令行工具 `antigravity-cli`（`/usr/bin/agy`）不同，桌面端并未在前端或配置文件中预留被门禁隐藏的上下文档位切换闭环（见 [《Google OAuth 原生通道技术报告》](mechanism-native-oauth.md) 第 6 节）。因此，`antigravity_context_unlock.py` 采用了针对桌面端引擎量身定制的最小侵入架构：

1. **零外部依赖**：完全基于 Python 3 标准库（`struct`、`hashlib`、`json`、`tempfile`、`os`）实现 ELF64 与 Go 1.18+ `pclntab` 解析，无需安装 `objdump`、`radare2` 或任何第三方包。
2. **动态符号解析 + 全文件唯一 59 字节指令窗口**：先通过 `pclntab` 定位目标函数 `utils.ClampCheckpointConfigForModelInfo` 的精确可执行文件偏移区间 `[start, end)`，再校验由前序指令（30 B）+ 补丁站点（8 B）+ 后序指令（21 B）组成的 **59 字节上下文窗口**在全文件中唯一出现且整体位于函数边界内。
3. **单点 8 字节无条件物理上界写入**：不向二进制注入任何硬编码 Token 常数，而是将引擎自身已算入寄存器 `esi` 的模型物理上界（`MaxTokens - MaxOutputTokens`）从“超限才截断”改为“无条件写入 `CheckpointConfig.MaxTokenLimit`”。
4. **严格故障闭合（Fail-Closed）的备份与配对机制**：通过 `os.link` 原子创建原版备份与 SHA256 侧车元数据，写入前复核文件身份（`inode / dev / size / mtime_ns`），还原时基于单次内存快照验证内容级配对关系。

---

## 2. ELF64 与 Go `pclntab` 动态符号解析器

脚本前部由 `ELFFile` 与 `GoSymbols` 两个核心类组成，负责在不依赖外部工具的情况下还原全部 Go 函数的名称与起止地址（以下实测数值基于 `antigravity 2.31.0-1` / `CL 1017595969`）：

```text
[读取 ELF64 二进制文件: 206,811,536 字节]
        │
        ▼
1. 解析段表与节表 (ELFFile)
   ├── 校验 ELF64 小端序与 EM_X86_64 (0x3e)
   ├── 建立仅限可执行区间的地址转换 va_to_off_exec (检查 SHF_EXECINSTR=0x4 / PF_X=0x1)
   └── 扫描 SHT_RELA 重定位节，提取全部 R_X86_64_RELATIVE (type 8) 重定位映射
        │
        ▼
2. 定位 Go 1.18+ 主函数表 (GoSymbols._find_pclntab)
   ├── 搜索魔数 0xFFFFFFF1 (小端字节 f1 ff ff ff 00 00)
   ├── 校验 minLC (1/2/4)、指针宽度 (8)、函数总数 nfunc 及首函数名可见 ASCII 字符
   └── 结合 SHT_RELA 重定位槽，优先选取被 runtime.moduledata (+0xa0 minpc == +0xb0 text) 引用的主表
        │
        ▼
3. 还原代码段基址与函数边界 (_find_text_base & _build)
   ├── 从指向 pclntab_va 的 moduledata 重定位槽读取 +0xb0 (text)，获得 text_base = 0x5461080
   │   （并对抽样函数入口做可执行性与非 0x00/0xCC 填充字节校验）
   └── 遍历 functab 的 (entryoff, funcoff) 条目（nfunc = 168,140）：
       • 注意 Go 1.18+ 布局中 _func 记录基址为 pcln_off + funcoff（无符号 uint32），
         函数名偏移为 _func+4 处的有符号 int32（相对 funcnametab）
       • 排序后得到每个函数的精确虚拟地址区间 [text_base + eo, text_base + next_eo)
```

与此同时，`embedded_profiles()` 函数可在只读数据段（`CL 1017595969` 中位于文件偏移 `0xa483988` / VA `0xac83988`，长 `28,210` 字节）自动定位并解析内嵌的 JSON 配置表，供 `info` 子命令直接读取各模型家族的内置默认 `max_token_limit`。

---

## 3. `CheckpointConfig` 构造链路与两道 `256,000` 天花板

在桌面端引擎的 `cortex/config` 与 `cortex/utils` 包中，单次会话组装 `CheckpointConfig` 的完整调用链如下（虚拟地址为 `CL 1017595969` 实测值）：

```text
cortex.(*CascadeManager).getCascadeConfig                        0x7a4f9ac (调用点)
 └─ config.GetCascadeConversationalConfigWithExperiment          0x6c45dc0
     ├─ config.augmentConversationalConfigWithExperiment         0x6c43080
     │   └─ config.applyFeatureProviderCheckpointOverrideConfig  0x6c45320
     │       ├─ config.resolveDefaultCheckpointConfig            0x6c46f60
     │       │   └─ utils.GetCheckpointConfigForModelInfo        0x6ab7200
     │       │       ├─ utils.GetCheckpointConfig                0x6ab6cc0  ◄── 天花板 ①（Provider 默认钳位）
     │       │       │   └─ utils.GetDefaultCheckpointConfigForModel 0x6ab6940
     │       │       └─ utils.ClampCheckpointConfigForModelInfo  0x6ab7420  （合并前首次调用）
     │       ├─ config.selectCheckpointExperimentKey             0x6c45140
     │       └─ config.MergeConfigsDedup                         0x6c4cf00  ◄── 合并策略 "max_token_limit": "256000"
     └─ config.clampAndValidateConfig                            0x6c46220
         ├─ utils.ClampCheckpointConfigForModelInfo              0x6ab7420  ◄── 天花板 ②（合并后再次调用，补丁位点）
         └─ utils.ValidateCheckpointConfigForModelInfo           0x6ab74a0
```

### 3.1 天花板 ①：`utils.GetCheckpointConfig`（`0x6ab6cc0`）的 Provider 门禁钳位

```asm
6ab6cfa: cmp  edx, 0x3          ; apiProvider == 3  (API_PROVIDER_GOOGLE_VERTEX) ?
6ab6cfd: je   6ab6d0e
6ab6d00: cmp  edx, 0x18         ; apiProvider == 24 (API_PROVIDER_GOOGLE_GEMINI) ?
6ab6d03: je   6ab6d0e
6ab6d05: cmp  edx, 0x1a         ; apiProvider == 26 (API_PROVIDER_ANTHROPIC_VERTEX) ?
6ab6d08: jne  6ab7051           ; 其他 provider（如企业网关 31）-> 直接跳过 256K 钳位！
...
6ab6de2: cmp  edx, 0x3e800      ; 0x3e800 == 256000
6ab6de8: mov  esi, 0x3e800
6ab6ded: cmovb esi, edx         ; esi = min(默认推导预算, 256000)
```

在 Google OAuth 原生通道下，`Gemini 3.8 Flash` 与 `Gemini 4 Argon` 的 `apiProvider` 为 `24`（`0x18`），命中上述分支，将 `GetDefaultCheckpointConfigForModel` 算出的 `983,040` 压低为 `256,000`。

### 3.2 策略合并与天花板 ②：为什么必须修补 `ClampCheckpointConfigForModelInfo`

紧接着在 `applyFeatureProviderCheckpointOverrideConfig`（`0x6c45320`）中，引擎查找该模型的实验策略键 `CASCADE_USE_EXPERIMENT_CHECKPOINTER`（其 JSON 载荷同样声明 `"max_token_limit": "256000"`），并通过 `config.MergeConfigsDedup`（`0x6c4cf00`）用非零策略字段覆盖第 1 步生成的默认配置。

因此，如果只把天花板 ① 的 `0x3e800` 改大，合并进来的策略值依然会把 `MaxTokenLimit` 重新写成 `256,000`。

而在策略合并完成之后，`config.clampAndValidateConfig`（`0x6c46220`）会第二次调用 **`utils.ClampCheckpointConfigForModelInfo`（`0x6ab7420`）**。观察该函数的完整机器码逻辑：

```asm
; 目标函数：utils.ClampCheckpointConfigForModelInfo (0x6ab7420 .. 0x6ab74a0, 128 字节)
; 参数寄存器：rax = *CheckpointConfig, rbx = *ModelInfo

6ab742a: cmp   DWORD PTR [rax+0xc], 0      ; CheckpointConfig.MaxTokenLimit == 0 ?
6ab742e: jne   6ab744c                     ; 非零则跳至上界检查
6ab7430: movsxd rdx, DWORD PTR [rbx+0x14]  ; rdx = ModelInfo.MaxTokens
6ab7434: cmp   rdx, 0x9c40                 ; 与 40,000 比较
6ab743b: jg    6ab7442
6ab743d: xor   edx, edx
6ab7440: jmp   6ab7449
6ab7442: add   rdx, -0x9c40                ; rdx = MaxTokens - 40000
6ab7449: mov   DWORD PTR [rax+0xc], edx    ; 零值兜底写入

; ── 上界计算与条件存储区（59 字节上下文窗口覆盖 0x6ab7442 .. 0x6ab747d）──
6ab744c: mov   edx, DWORD PTR [rbx+0x14]   ; edx = ctx (ModelInfo.MaxTokens)
6ab744f: test  edx, edx
6ab7451: jle   6ab7468                     ; ctx <= 0 -> 跳至 .done，不做改动
6ab7453: mov   esi, edx                    ; esi = ctx
6ab7455: sub   edx, ecx                    ; edx = ctx - MaxOutputTokens
6ab7457: cmp   ecx, esi
6ab7459: cmovb esi, edx                    ; 若 MaxOutputTokens < ctx (无符号)，则 esi = ctx - MaxOutputTokens
6ab745c: nop   DWORD PTR [rax+0x0]

6ab7460: cmp   DWORD PTR [rax+0xc], esi    ; ◄── 8 字节补丁站点起点 (0x6ab7460)
6ab7463: jbe   6ab7468                     ; 若 MaxTokenLimit <= esi，跳过写入（保留 256,000）
6ab7465: mov   DWORD PTR [rax+0xc], esi    ; MaxTokenLimit = esi
6ab7468: mov   rcx, QWORD PTR [rax+0x50]   ; .done 块起点（后续检查 MaxOutputTokens）
```

> **调用次数与下游边界说明**：
> - 由于补丁直接修改 `ClampCheckpointConfigForModelInfo` 的函数体，上述调用树中的**两次调用**（策略合并前在 `resolveDefaultCheckpointConfig` 内、策略合并后在 `clampAndValidateConfig` 内）都会执行修改后的指令；其中真正覆盖掉实验策略 `"256000"` 的是合并后的第二次调用。
> - 在 `getCascadeConfig` 返回之后，引擎中仍存在 `config.MergeCascadeConfigsWithOverwrites`（`0x6c4b5e0`），若上层 RPC 调用方在请求参数 `CascadeConfig.CheckpointConfig` 中显式传入了非零的 `MaxTokenLimit` 覆盖值，仍会在更下游覆盖该字段。在常规桌面会话与受控实测中，调用方传入的 `user_config` 不携带 `checkpoint_config`（见网关报告第 3.4 节），故 `983,040` 全程稳定生效。

---

## 4. 8 字节补丁指令对比与 59 字节安全签名窗口

### 4.1 补丁站点前后指令逐字节对比

补丁位点位于 `utils.ClampCheckpointConfigForModelInfo + 0x40`（`CL 1017595969` 中 VA 与文件偏移均为 `0x6ab7460`）：

```text
修改前 (8 字节: 39 70 0c 76 03 89 70 0c):
  6ab7460: 39 70 0c                cmp    DWORD PTR [rax+0xc], esi
  6ab7463: 76 03                   jbe    6ab7468
  6ab7465: 89 70 0c                mov    DWORD PTR [rax+0xc], esi

修改后 (8 字节: 89 70 0c eb 03 90 90 90):
  6ab7460: 89 70 0c                mov    DWORD PTR [rax+0xc], esi
  6ab7463: eb 03                   jmp    6ab7468
  6ab7465: 90 90 90                nop ; nop ; nop
```

对比前后两个 8 字节序列（偏移 `+1` 与 `+2` 仍为 `70 0c`，偏移 `+4` 仍为 `03`），**全文件 206,811,536 个字节中实际发生数值变化的仅有 5 个偏移**：`0x6ab7460`、`0x6ab7463`、`0x6ab7465`、`0x6ab7466`、`0x6ab7467`。

### 4.2 为什么采用 59 字节上下文窗口而非仅匹配 8 字节

如果补丁器仅搜索 8 字节 `39 70 0c 76 03 89 70 0c`，在大型二进制文件中存在两个潜在风险：一是未来编译器在别处生成相同的短指令序列，二是某条 `movabs` 64 位立即数或只读数据表中恰好包含相同字节（参见原生通道报告第 6.2 节中对 `.text` 段 32 处 `00 e8 03 00` 字节假阳性的实证分析）。

为此，`antigravity_context_unlock.py` 定义了横跨前后完整基本块的 **59 字节签名窗口**：
- **`SITE_PREFIX`（前 30 字节，`0x6ab7442..0x6ab7460`）**：包含零值兜底末尾 `add rdx, -0x9c40; mov [rax+0xc], edx` 及完整的物理上界计算指令链 `mov edx, [rbx+0x14] ... cmovb esi, edx; nop dword ptr [rax+0x0]`；
- **补丁站点（中 8 字节，`0x6ab7460..0x6ab7468`）**：`ORIGINAL_SITE` 或 `PATCH_PHYSICAL_MAX`；
- **`SITE_SUFFIX`（后 21 字节，`0x6ab7468..0x6ab747d`）**：包含 `.done` 块起始的 `mov rcx, [rax+0x50]; test rcx, rcx ... jle .ret` 指令序列。

`locate_site()` 强制要求：
1. `CONTEXT_PRISTINE` 与 `CONTEXT_PATCHED` 在**整个二进制文件**中的出现次数之和必须严格等于 `1`（既排除多处重名，也拒绝同时含两种形态或全不匹配的未知文件）；
2. 整个 59 字节窗口区间 `[ctx_off, ctx_off + 59)` 必须**完全落在** `pclntab` 解析出的 `utils.ClampCheckpointConfigForModelInfo` 函数体 `[start, end)` 内部。

### 4.3 与 `ValidateCheckpointConfigForModelInfo`（`0x6ab74a0`）的兼容性分析

紧随 `ClampCheckpointConfigForModelInfo` 之后，`clampAndValidateConfig` 会传入 `PlannerConfig.MaxOutputTokens`（当模型目录 `MaxOutputTokens > 0` 时与 `ModelInfo.MaxOutputTokens` 等值）并调用 `utils.ValidateCheckpointConfigForModelInfo`（`0x6ab74a0`），校验约束为无符号比较 `MaxTokenLimit <= ctx - maxOutputTokens`（等号合法）。
- 对于官方原生目录中的所有主力对话模型——包括 `Gemini 3.8 Flash` / `Gemini 4 Argon`（`65,536 < 1,048,576` → `esi = 983,040`）、`Claude Opus 5.5` / `Claude Sonnet 5.5`（`128,000 < 1,000,000` → `esi = 872,000`）以及单次输出上限扩展至 256 Ki 的 `Gemini 4 Carbon`（`262,144 < 1,048,576` → `esi = 786,432`）——`cmovb` 算出的 `esi` 均恰好等于校验上界，100% 通过校验。
- **理论边界说明**：若未来某个异常模型目录条目配置了 `maxOutputTokens >= maxTokens`（例如仅用于图像生成的 `gemini-3.1-flash-image` 宣告 `65,536 / 65,536`），`Clamp` 处的无符号 `cmovb` 会保留 `esi = ctx`，而 `Validate` 的上界为 `0`，两者算式并非在一切退化参数下恒等。

### 4.4 明确保持不变的引擎组件

| 引擎组件 / 行为 | 是否修改 | 说明 |
|---|---:|---|
| `utils.GetCheckpointConfig` 的 `min(x, 256000)` | 否 | 被下游合并后的 `ClampCheckpointConfigForModelInfo` 无条件覆盖，无需改动 |
| 实验策略合并 `config.MergeConfigsDedup` | 否 | 完整保留 `use_model_reported_token_count`、`token_threshold`、`strategy`、`is_sync` 等字段 |
| 单条用户消息约 `192 KB` 截断（`MaxTokensPerUserInputStep = 64000`） | 否 | 属于单步输入转换配置，与多轮总预算独立 |
| 独立摘要请求生成与 `step_type = 23` 落库逻辑 | 否 | 当真实混合计数达到新上限（如 `983,040`）时，仍可正常触发摘要归档 |
| 网络通信协议与请求 JSON 键集合 | 否 | 纯本地配置上界调整，不改变任何出站 HTTP/HTTPS 请求格式 |

---

## 5. 备份、配对还原与并发防护状态机

为确保对约 207 MB 引擎文件的原地修补安全可逆，脚本实现了以下工程约束：

1. **前置备份状态机（`check_backup`）**：
   在执行任何写入前，脚本检查同目录下的 `<binary>.ctxunlock-backup` 及其侧车文件 `<binary>.ctxunlock-backup.json`，区分六种状态：
   - `missing`：备份不存在 → 先通过临时文件 + `fsync` + **`os.link`** 原子发布备份与侧车，复核变为 `usable` 后才允许继续修补；
   - `usable`：普通可读文件，SHA256 与当前原版二进制一致，且侧车记录一致 → 直接复用；
   - `wrong-build`（属于旧版本的备份）：默认以退出码 `3` 拒绝；显式使用 `patch --yes --refresh-backup` 时，为当前已通过结构校验的原版快照生成新备份与侧车，均在临时文件中写完并 `fsync` 后，再以 `os.replace` 原子替换旧备份，更新侧车并同步目录，复核为 `usable` 后才允许修补。仅保留最新构建的一份备份，不生成历史归档，也不自动清理旧工具留下的归档。
   - 备份与侧车的替换并非整体事务：先移除旧侧车，避免中断时新备份与旧元数据冲突；新备份替换失败时旧备份仍在，侧车替换失败时新备份已完整就位，但目标二进制均不修补。侧车缺失可按既有内容配对逻辑安全重试与还原。
   - `dangling`（悬空符号链接）、`unreadable`、`bad-meta`（侧车哈希不一致）仍以退出码 `3` 拒绝提交补丁；刷新操作也拒绝替换符号链接或非普通文件。
   - `--refresh-backup` 不绕过目标函数/指令窗口校验，不改变 `--strict-build` 行为；无 `--yes` 时仅预览，已修补目标不刷新备份。
2. **单快照决策与写前身份守卫（`_snapshot` & `_identity_changed`）**：
   每个命令只在启动时读取一次二进制文件内存快照。在即将调用 `atomic_write` 替换目标前，重新执行 `os.stat` 比对 `(st_ino, st_dev, st_size, st_mtime_ns)`；若期间软件包管理器升级替换了磁盘文件，脚本立即中止。
3. **单快照内容级配对还原（`cmd_restore` & `_pairs_with`）**：
   `restore` 仅读取一次备份文件字节到内存，后续原版状态校验、侧车核对、与当前安装二进制的配对检验（验证将备份的 8 字节站点替换为 `PATCH_PHYSICAL_MAX` 后其整文件 SHA256 是否严格等于当前目标文件）以及最终原子写回，全部基于**同一份内存字节**完成，杜绝二次读盘（TOCTOU）竞态。

### 退出码规范

| 退出码 | 含义 |
|---:|---|
| `0` | 操作成功，或目标已处于期望状态（重复 `patch` 已修补文件、重复 `restore` 已还原文件均幂等返回 `0`） |
| `1` | 状态校验不符（如对未修补二进制执行 `verify`、备份本身已被修补、还原时缺少备份） |
| `2` | 预览/干跑模式（执行 `patch` 或 `restore` 时未传 `--yes`，未写入任何文件）或命令行参数非法 |
| `3` | 故障闭合拒绝执行（符号/59 字节窗口不匹配、ELF 损坏、备份属于其他版本或不可用、检测到并发替换） |

---

## 6. 受控长会话 A/B 实测验证（`CL 1017595969`）

### 6.1 实验条件与核心结果对比

在 `antigravity 2.31.0-1`（`Built at CL: 1017595969`）上，使用 Google OAuth 原生通道，以 `--standalone` 模式独立拉起 `language_server`，通过本地 Connect/HTTPS 接口（`StartCascade` + `SendUserCascadeMessage`）驱动受控长对话，每轮追加 **80 KiB** 固定随机种子生成的英文单词填充文本，测试模型固定为 **`Gemini 3.8 Flash (High)`**（`MODEL_PLACEHOLDER_M318`）。两组实验除引擎是否应用 8 字节补丁外，其余参数完全一致：

| 观测指标 | 未修补基线（Pristine） | 应用 8 字节补丁后（Patched） |
|---|---:|---:|
| 引擎二进制 SHA256 | `e49711c4f7b2fa0e...` | `a1ceb2f206483527...` |
| 会话数据库前缀 | `36e5ea53…` | `fa19d7d5…` |
| **`max_context_tokens`（`maxctx` ①）** | **`256,000`** | **`983,040`**（**3.840×**） |
| SQLite `gen_metadata` 生成行数 | 23 行（22 轮提交，含压缩重生成） | 40 行（22 轮首测 + 18 轮同会话续跑） |
| **`steps` 表 `step_type = 23` 压缩步骤数** | **`1` 条**（位于 `steps idx=31`） | **`0` 条** |
| 是否触发自动摘要压缩 | **是**（第 15 行回落，`reason = 2`） | **否**（全程 40 行 `reason = 0`） |
| 本地诊断估算 `est` 峰值 | `426,910` | **`1,117,452`** |
| 会话末行 `est` | `188,871` | **`1,117,452`** |
| 单轮请求 HTTP 状态与耗时中位数 | 22/22 `HTTP 200`（中位数 `6.2s`） | 40/40 `HTTP 200`（首段 `7.5s` / 续跑 `10.2s`） |

### 6.2 逐轮实测数据对照表（基线 23 行 vs. 补丁后 40 行）

| DB 行 `idx` | 基线 `est` ② | 基线 `reason` | 基线 `maxctx` ① | 补丁后 `est` ② | 补丁后 `reason` | 补丁后 `maxctx` ① | 阶段说明 |
|---:|---:|---:|---:|---:|---:|---:|---|
| 0 | 41,428 | 0 | 256,000 | 41,429 | 0 | 983,040 | 会话首轮 |
| 1 | 69,104 | 0 | 256,000 | 69,198 | 0 | 983,040 | |
| 2 | 96,628 | 0 | 256,000 | 96,801 | 0 | 983,040 | |
| 3 | 124,139 | 0 | 256,000 | 124,377 | 0 | 983,040 | |
| 4 | 151,663 | 0 | 256,000 | 151,954 | 0 | 983,040 | |
| 5 | 179,190 | 0 | 256,000 | 179,508 | 0 | 983,040 | |
| 6 | 206,700 | 0 | 256,000 | 207,074 | 0 | 983,040 | |
| 7 | 234,221 | 0 | 256,000 | 234,637 | 0 | 983,040 | |
| 8 | 261,747 | 0 | 256,000 | 262,199 | 0 | 983,040 | |
| 9 | 289,275 | 0 | 256,000 | 289,759 | 0 | 983,040 | |
| 10 | 316,801 | 0 | 256,000 | 317,350 | 0 | 983,040 | |
| 11 | 344,328 | 0 | 256,000 | 344,909 | 0 | 983,040 | |
| 12 | 371,857 | 0 | 256,000 | 372,495 | 0 | 983,040 | |
| 13 | 399,384 | 0 | 256,000 | 400,131 | 0 | 983,040 | |
| **14** | **426,910** | **0** | **256,000** | **427,721** | **0** | **983,040** | **基线压缩前末行** |
| **15** | **19,162** | **2** | **256,000** | **455,311** | **0** | **983,040** | **基线触发压缩回落；补丁版继续线性增长** |
| 16 | 23,374 | 0 | 256,000 | 482,902 | 0 | 983,040 | |
| 17 | 51,140 | 0 | 256,000 | 510,513 | 0 | 983,040 | |
| 18 | 78,686 | 0 | 256,000 | 538,106 | 0 | 983,040 | |
| 19 | 106,232 | 0 | 256,000 | 565,696 | 0 | 983,040 | |
| 20 | 133,778 | 0 | 256,000 | 593,284 | 0 | 983,040 | |
| 21 | 161,324 | 0 | 256,000 | 620,878 | 0 | 983,040 | 补丁版首段 22 轮结束 |
| 22 | 188,871 | 0 | 256,000 | 648,468 | 0 | 983,040 | 基线 22 轮结束；补丁版进入续跑 |
| 23–29 | — | — | — | 676,055 → 841,574 | 0 | 983,040 | 补丁版每轮稳定递增约 27.6K `est` |
| 30–34 | — | — | — | 869,159 → 979,511 | 0 | 983,040 | 补丁版持续无压缩 |
| 35 | — | — | — | 1,007,101 | 0 | 983,040 | `DB est` 跨过 100 万诊断值 |
| 36 | — | — | — | 1,034,688 | 0 | 983,040 | |
| 37 | — | — | — | 1,062,275 | 0 | 983,040 | |
| 38 | — | — | — | 1,089,864 | 0 | 983,040 | |
| **39** | — | — | — | **1,117,452** | **0** | **983,040** | **补丁版第 40 轮结束（全程 0 压缩）** |

> **为什么第 39 行 `est = 1,117,452` 超过了 `maxctx = 983,040` 仍未触发压缩？**
> 如 [《原理与使用指南》](overview-and-guide.md) 第 1.2 节所述，`DB est` 是按字节近似算法事后生成的诊断值，在英文单词填充下约为服务端真实分词数的 **1.82–1.87 倍**。第 39 行的 `est = 1,117,452` 对应的真实混合计量约为 **60 万 tokens**，尚未触及 `983,040` 的新预算上限。因此本实验证实的是**客户端本地门禁已从 `256,000` 抬升至 `983,040`**，并非取消压缩机制本身。

---

## 7. 命令行接口参考

```bash
# 1. 只读自检：解析 Go 符号表、校验 59 字节上下文签名并打印摘要（不修改文件）
python3 antigravity_context_unlock.py self-test
python3 antigravity_context_unlock.py self-test --strict-build

# 2. 干跑预览补丁操作（不加 --yes 时不会创建备份或修改目标文件，返回退出码 2）
python3 antigravity_context_unlock.py patch

# 3. 执行原地修补（自动创建并校验 .ctxunlock-backup 与 .ctxunlock-backup.json）
sudo python3 antigravity_context_unlock.py patch --yes

# 4. 只读校验补丁状态与备份配对情况
python3 antigravity_context_unlock.py verify

# 5. 查看二进制内嵌的各模型家族默认 Checkpoint 预算表（支持按名称子串过滤）
python3 antigravity_context_unlock.py info
python3 antigravity_context_unlock.py info --model M124

# 6. 从配对的原版备份原子还原二进制文件
sudo python3 antigravity_context_unlock.py restore --yes
```
