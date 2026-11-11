# 技术报告：Google OAuth 原生通道上下文处理机制与实测数据

> **取证对象**：Antigravity 桌面端推理引擎 `/opt/Antigravity/resources/bin/language_server`（Linux x86-64，Go ELF64 PIE）。
> **版本锚点**：通道机制取证基于 `antigravity 2.29.1-1`（`Built at CL: 1015941558`，`196,043,152` 字节，`SHA256: c666de77661e557a893ca7a30d9f4b280857b1870d357b07b9fb761730edfc26`；下文反汇编地址以此构建为准）；补丁解锁验证基于 `antigravity 2.31.0-1`（`Built at CL: 1017595969`，见 [《二进制补丁与脚本实现详解》](binary-patch-internals.md)）。
> **测试通道**：Google 账号 OAuth 原生通道（`daily-cloudcode-pa.googleapis.com/v1internal:*`）。
> **覆盖模型**：`Gemini 3.8 Flash (High)`（`MODEL_PLACEHOLDER_M318`）、`Gemini 4 Argon (High)`（`MODEL_PLACEHOLDER_M417`）。
> **通俗导读**：如需快速了解核心结论与解锁用法，请参阅 [《原理与使用指南》](overview-and-guide.md)。

---

## 1. 术语与三种 Token 计量口径

分析桌面端原生通道的上下文行为时，必须严格区分同时存在的三种外部可见 Token 数值，以及引擎内部实际执行比较的混合计量值：

| 口径分类 | 字段名称与存储/协议位置 | 产生端与写入位置 | Flash / Argon 压缩转折点实测值 | 技术含义与边界 |
|---|---|---|---|---|
| **① 目录容量与本地预算** | `maxTokens` / `maxOutputTokens`<br>`CASCADE_USE_EXPERIMENT_CHECKPOINTER` → `max_token_limit`<br>SQLite `max_context_tokens` | 本地 `GetAvailableModels` 目录快照携带，`language_server` 读取构造本地预算 | `maxTokens = 1,048,576`<br>`maxOutputTokens = 65,536`<br>**`max_token_limit = 256,000`** | 配置层的上下文预算参数。仅保存在客户端本地配置与诊断表中，不会随主生成请求发送至云端。 |
| **② 客户端本地诊断估算**<br>（`DB est`） | SQLite `gen_metadata` → `ChatStartMetadata.ContextWindowMetadata`（`estimated_tokens_used` / `truncation_reason` / `max_context_tokens`） | `language_server` 本地 `DefaultSerializer.populateContextWindowMetadata`（`0x6f194e0`）构造落库 | 压缩前末行：**`438,119`** / **`425,381`**（`reason=0`）<br>压缩后首行：**`19,145`** / **`18,422`**（`reason=2`） | 事后写入数据库的按字节近似估算值。在英文填充测试下为服务端报告用量的 **`1.869×` / `1.816×`**，**并非触发压缩的即时水位线**。 |
| **③ 服务端 SSE 报告用量** | `v1internal:streamGenerateContent?alt=sse` 响应末尾 `usageMetadata.promptTokenCount` | Google 云端推理服务统计返回 | 压缩前末轮主请求：**`234,438`** / **`234,183`**<br>独立摘要请求：**`250,016`** / **`250,554`**<br>压缩后主请求：**`12,798`** / **`12,551`** | 服务端对当次请求统计的真实输入 Token 用量。 |

### 1.1 本地 SQLite `gen_metadata` 的 Protobuf 字段路径

会话数据库位于 `~/.gemini/antigravity/conversations/<uuid>.db`。其中 `gen_metadata` 表的 `data` 列为二进制 Protobuf 编码（可由 [`tools/inspect_session.py`](../tools/inspect_session.py) 直接只读解析）：

| 诊断字段 | Protobuf Wire 路径 | 说明 |
|---|---|---|
| `estimated_tokens_used` | `field 1 → field 9 → field 10 → field 1` | 本地诊断估算 Token 数（`est` ②） |
| `truncation_reason` | `field 1 → field 9 → field 10 → field 2` | `0 = UNSPECIFIED`（未压缩），`1 = PROMPT_CACHE_TTL_EXPIRED`，`2 = MAX_TOKEN_LIMIT`（`.rodata 0x4d16a7b`） |
| `token_breakdown` | `field 1 → field 9 → field 10 → field 3` | 本地估算分项明细 |
| `max_context_tokens` | `field 1 → field 9 → field 10 → field 4` | 当前生效的上下文预算上限（`maxctx` ①） |
| `model` | `field 1 → field 19` | 模型名称标识字符串（如 `gemini-3.8-flash`） |
| `labels`（`request_id` / `last_step_index` / `model_enum`） | `field 1 → field 20`（重复 KV：`field 1` 键，`field 2` 值） | 用于将网络请求与数据库生成行精确关联的步骤索引与枚举标签 |

### 1.2 引擎内部的真实触发算式：混合计量（Hybrid Accounting）

在受控实验中，压缩前最后一轮主请求的服务端 `promptTokenCount` 为 `234,438`（Flash）/ `234,183`（Argon），尚未达到 `256,000`，而紧随其后的下一轮却在发送主请求前触发了压缩。对转换器核心函数 `chatconverters.(*TrajectoryChatConverter).TrajectoryToChatMessagesToTokenLimitOrStepIndex`（`0x67b5840`）及辅助函数 `modelReportedPrefixTokens`（`0x67b3fc0`）的反汇编解释了这一现象（`0x67b7587..0x67b75ae`）：

```asm
67b7587: call 67b3fc0       ; 调用 modelReportedPrefixTokens 获取历史模型报告前缀 (rax)
67b759b: sub  edx, esi      ; 计算本轮新增本地估算增量 = 当前轨迹本地累计 (edx) - 历史基线 (esi)
67b759d: add  rdx, rax      ; 混合计量值 rdx = 新增本地估算增量 + 历史模型报告前缀
67b75ab: cmp  r9, rdx       ; 与有效上限 limit (r9 = 256,000) 无符号比较
67b75ae: jae  67b75f8       ; 若 limit >= rdx 则正常放行；仅当 rdx > limit (严格大于) 时进入截断分支
```

由于压缩检查发生在**新一轮用户消息已加入轨迹之后、发往云端之前**，引擎将“上一轮为止服务端已报告的 `InputTokens + CacheReadTokens + CacheWriteTokens + OutputTokens`”与“本轮新消息的本地估算增量”相加；一旦总和严格大于 `256,000`，即返回超限哨兵错误 `"could not convert a single message before hitting truncation"`，由 `checkpoint.shouldCheckpoint` 捕获并启动本地压缩。

---

## 2. 未修补状态下一次对话的完整六步生命周期

### 步骤 1：OAuth 鉴权与模型目录加载

引擎启动后读取 `~/.gemini/oauth_creds.json` 与 `~/.gemini/google_accounts.json`，依次请求：
1. `https://www.googleapis.com/oauth2/v3/tokeninfo`
2. `https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist`
3. `https://daily-cloudcode-pa.googleapis.com/v1internal:listExperiments`
4. `https://daily-cloudcode-pa.googleapis.com/v1internal:fetchUserInfo`
5. `https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels`
6. `https://aicode.googleapis.com/v1alpha:fetchConfig`

在引擎本地 RPC 接口 `GetAvailableModels` 导出的完整目录快照（共 26 个模型条目）中，各模型家族按模型携带独立的 `CASCADE_USE_EXPERIMENT_CHECKPOINTER` 策略 JSON：

| 模型显示名称 | 内部枚举标识 | `maxTokens` | 策略 `max_token_limit` | 策略 `strategy` | `is_sync` |
|---|---|---:|---:|---|---|
| **Gemini 4 Argon (High / Medium / Low)** | `M417` / `M418` / `M419` | `1,048,576` | **`256,000`** | `SAME_MODEL` | `true` |
| **Gemini 3.8 Flash (High / Medium / Low)** | `M318` / `M319` / `M320` | `1,048,576` | **`256,000`** | `SAME_MODEL` | `true` |
| Gemini 3.5 Flash Lite / 2.5 Pro / 2.5 Flash 等 | `M50` / `M198` / `M18` 等 | `1,048,576` | **`128,000`** | `SINGLE_PROMPT` | `false` |
| Claude Opus 5.5 / Sonnet 5.5（静态目录条目） | `M400`–`M405` | `1,000,000` | `256,000`（另含 `/claude-1m_840k` 变体 `840,000`） | `SAME_MODEL` | `true` |
| GPT-OSS 120B (Medium) | `MODEL_OPENAI_GPT_OSS_120B_MEDIUM` | `131,072` | **`80,000`** | `UNSPECIFIED` | `false` |

### 步骤 2：本地构造 `CheckpointConfig`（两层钳位与策略合并）

`cortex.(*CascadeManager).getCascadeConfig`（`0x738df40`）调用 `config.GetCascadeConversationalConfigWithExperiment`（`0x669c3a0`）按三阶段构造预算：
1. **本地默认下界钳位（`utils.GetCheckpointConfig`，`0x65154c0`）**：
   检查 `ModelInfo.ApiProvider`（偏移 `+0x30`）是否为 `3`、`24`（`0x18`，`API_PROVIDER_GOOGLE_GEMINI`）或 `26`。原生 Gemini 模型命中 `24`，先由 `GetDefaultCheckpointConfigForModel` 算出 `1,048,576 - 65,536 = 983,040`，再在 `0x65155e2..0x65155f0` 处被 `min(edx, 0x3e800)` 钳位为 **`256,000`**。
2. **实验策略合并（`applyFeatureProviderCheckpointOverrideConfig`，`0x669b9e0`）**：
   通过 `selectCheckpointExperimentKey`（`0x669b800`）选出策略键，解析 JSON 后由 `config.MergeConfigsDedup`（`0x66a32e0`）以非零字段覆盖默认配置（目标模型的策略值同样为 `256,000`）。
3. **模型物理上界保护（`utils.ClampCheckpointConfigForModelInfo`，`0x6515c20`）**：
   确保 `MaxTokenLimit` 不超过 `ctx - maxOutputTokens`（`983,040`）。（注：这正是 `antigravity_context_unlock.py` 施加 8 字节无条件物理上界写入的目标函数。）

### 步骤 3：压缩触发判定（`checkpoint.shouldCheckpoint`）

每轮发送主请求前，`checkpoint.MaybeCreateCheckpoint`（`0x6f43720`）调用 `checkpoint.shouldCheckpoint`（`0x6f43be0`）：
- 在 `TrajectoryChatConverter.TrajectoryToChatMessages`（`0x67b57c0`）的 `0x67b5813..0x67b5843` 处，读取 `plannerModelInfo.MaxTokens`（`[rdx+0x14] = 1,048,576`）与 `CheckpointConfig.MaxTokenLimit`（`256,000`）取较小值作为有效 `limit = 256,000`。（注：`CheckpointConfig` 的 `TokenThreshold = 50,000` 位于偏移 `+0xc0`，不参与此处的 `min` 运算。）
- 当混合计量超过 `256,000` 并返回截断哨兵错误时，`shouldCheckpoint` 在 `0x6f43cce` 处通过 `errors.Is` 识别该哨兵并返回 `true`。

### 步骤 4：压缩执行瞬间的事件序列

判定需要压缩后，客户端依次执行三步动作（此外在会话第 0 轮初始化时还会发送一条 `82,969 B`、`contents = 1` 的首轮基线 `checkpoint` 请求）：

| 模型 | 阶段顺序 | `requestType` | 请求体字节数 | `contents` 条数 | SSE `promptTokenCount` ③ | 本地 SQLite 记录 |
|---|---|---|---:|---:|---:|---|
| **Gemini 3.8 Flash** | ① 压缩前末轮主请求 | `agent` | `1,351,180 B` | 27 | **`234,438`** | `gen_metadata idx=13`：`est=438,119`, `reason=0` |
| | ② 独立摘要生成请求 | **`checkpoint`** | **`1,438,396 B`** | **30** | **`250,016`** | `steps idx=29`：写入 **`step_type=23`**（`826,428 B`） |
| | ③ 替换历史后瘦身主请求 | `agent` | **`58,375 B`** | **1** | **`12,798`** | `gen_metadata idx=14`：`est=19,145`, **`reason=2`** |
| **Gemini 4 Argon** | ① 压缩前末轮主请求 | `agent` | `1,283,262 B` | 29 | **`234,183`** | `gen_metadata idx=14`：`est=425,381`, `reason=0` |
| | ② 独立摘要生成请求 | **`checkpoint`** | **`1,370,117 B`** | **32** | **`250,554`** | `steps idx=31`：写入 **`step_type=23`**（`824,268 B`） |
| | ③ 替换历史后瘦身主请求 | `agent` | **`56,178 B`** | **1** | **`12,551`** | `gen_metadata idx=15`：`est=18,422`, **`reason=2`** |

### 步骤 5：HTTPS 主请求的线上结构（全树递归键扫描）

对捕获的全部 **50 个生成请求**（Flash：26 个 `agent` + 2 个 `checkpoint`；Argon：20 个 `agent` + 2 个 `checkpoint`）执行全深度 JSON 键树扫描：
- **顶层键恒为 6 个**：`project, requestId, request, model, userAgent, requestType`。
- **全树键集合并集**：Flash 主请求并集为 **94** 个键，Argon 主请求并集为 **93** 个键；`generationConfig` 恒为 `{"maxOutputTokens": 65536, "thinkingConfig": {"includeThoughts": true, "thinkingLevel": "HIGH"}}`。
- **压缩控制字段检索结果**：检索 `checkpoint_config`、`checkpointConfig`、`cascade_config`、`max_token_limit`、`maxTokenLimit`、`context_window`、`contextWindow`、`maxContextTokens`、`autoCompact` 及任何含 `compress` 的键名，**50/50 出现次数均为 0**。
- **`ContextWindowCompressionConfig` 核验**：二进制中虽包含该 Protobuf 类型定义，但其全部 4 个 Getter 函数在 `.text` 段的 `e8 rel32` 直接调用数为 **0**，且请求与 SSE 响应键树中均未出现相关字段。

### 步骤 6：遥测端点 `recordTrajectoryAnalytics` 暴露生效 `checkpointConfig`

桌面端引擎在会话过程中向 `https://daily-cloudcode-pa.googleapis.com/v1internal:recordTrajectoryAnalytics` 发送分析请求，其请求体直接序列化了内存中生效的 `checkpointConfig` 结构：

```json
{
  "checkpointConfig": {
    "checkpointModel": "MODEL_PLACEHOLDER_M50",
    "enableFallback": true,
    "enabled": true,
    "isSync": true,
    "maxOutputTokens": 32768,
    "maxOverheadRatio": 0.15,
    "maxTokenLimit": 256000,
    "maxUserRequests": 10,
    "sessionSummaryPromptOverride": "You have been working on the task described above..."
  },
  "checkpointIndex": 29,
  "errorOnTruncationWithoutCheckpoint": false
}
```

捕获的两组共 29 条遥测记录中，`checkpointConfig.maxTokenLimit` 取值集合恒为 `{256000}`，无需附加调试器即可从网络层证实内部生效预算。

---

## 3. 各阶段限制归属汇总表

| 阶段 | 参数或行为 | 实际控制端 | 具体函数或协议位置（`CL 1015941558`） | 验证依据 |
|---|---|---|---|---|
| 模型容量宣告 | `maxTokens = 1,048,576`, `maxOutputTokens = 65,536` | 本地目录快照携带 | `GetAvailableModels` 目录条目 | 目录快照 JSON |
| 按模型归档策略值 | `max_token_limit = 256,000`, `use_model_reported_token_count = true` | 目录快照携带，引擎本地消费 | `CASCADE_USE_EXPERIMENT_CHECKPOINTER` | 目录快照 + 遥测 `maxTokenLimit=256000` + SQLite `maxctx=256000` |
| 实验策略变体键选择 | 三级回落探测 | 引擎本地 | `config.selectCheckpointExperimentKey`（`0x669b800`） | 反汇编 + 枚举描述符 `0x4cd0d45` |
| 本地默认下界钳位 | `min(x, 256000)`（针对 `apiProvider` 3/24/26） | 引擎本地 | `utils.GetCheckpointConfig`（`0x65155e2..0x65155f0`） | 反汇编 `0x3e800` 比较与 `cmovb` |
| 模型容量上界保护 | `<= ctx - maxOutputTokens`；零值兜底 `max(0, ctx - 40000)` | 引擎本地 | `utils.ClampCheckpointConfigForModelInfo`（`0x6515c20`） | 反汇编 |
| 自动压缩触发判定 | 混合计量 `>` `min(MaxTokens, MaxTokenLimit)` | **引擎本地** | `checkpoint.shouldCheckpoint`（`0x6f43be0`）；比较点 `0x67b75ab` | 反汇编 + `steps step_type=23` |
| 压缩执行与历史替换 | 独立 `checkpoint` 请求 + 替换历史消息 | **引擎本地** | `checkpoint.MaybeCreateCheckpoint`（`0x6f43720`） | TLS 抓包序列 |
| 诊断元数据落库 | `estimated_tokens_used` / `truncation_reason` / `max_context_tokens` | **引擎本地构造** | `DefaultSerializer.populateContextWindowMetadata`（`0x6f194e0`） | 反汇编 + SSE 键树扫描 |

---

## 4. 受控长会话实测数据与历史会话统计

### 4.1 实验设计与 `requestId` 对齐方法

- **实验条件**：未修补 `language_server`（`CL 1015941558`），通过本地 HTTPS API（`StartCascade` + `SendUserCascadeMessage`）每轮追加 **80 KB** 固定随机种子（`random.Random(i * 7919)`）生成的英文单词填充文本，上游串联 `mitmproxy` 记录请求字节数、`contents` 条数与 SSE `usageMetadata.promptTokenCount`。
- **网络请求与数据库行的确定性关联公式**：
  原生通道主请求携带 `requestId: "agent/<cascadeId>/<ts>/<trajectoryId>/<N>"`，其中末尾步号 `<N>` 与 SQLite `gen_metadata` 标签 `last_step_index` 满足逐行等式 **`last_step_index = N - 1`**。（压缩轮因额外写入 `step_type = 23` 会使 `<N>` 发生跳变，故不能按固定等差步长推算。）`Gemini 4 Argon` 全部 20 条主请求均保存了 `requestId` 并实现 20/20 确定性对齐；`Gemini 3.8 Flash` 早期抓包未保存 `requestId`，按请求序列与字节/条数特征对齐。

### 4.2 `Gemini 3.8 Flash (High)` 逐轮实测表（会话 `b9ce47f0…`）

| 抓包序号 `#` | `requestType` | 请求体字节数 | `contents` 条数 | 服务端 SSE ③ | 本地 DB `est` ② | 偏差比 ②/③ | `reason` | `maxctx` ① |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 0 | `checkpoint`（首轮基线） | 82,969 | 1 | 14,753 | — | — | — | — |
| 1 | `agent` | 124,048 | 1 | 24,174 | 41,090 | 1.700 | 0 | 256,000 |
| 2 | `agent` | 206,706 | 3 | 38,932 | 93,191 | 2.394 | 0 | 256,000 |
| 3 | `agent` | 436,257 | 5 | 71,911 | 135,684 | 1.887 | 0 | 256,000 |
| 4 | `agent` | 519,434 | 7 | 86,742 | 163,183 | 1.881 | 0 | 256,000 |
| 5 | `agent` | 602,617 | 9 | 101,482 | 190,676 | 1.879 | 0 | 256,000 |
| 6 | `agent` | 685,775 | 11 | 116,249 | 218,165 | 1.877 | 0 | 256,000 |
| 7 | `agent` | 768,952 | 13 | 131,050 | 245,658 | 1.875 | 0 | 256,000 |
| 8 | `agent` | 852,113 | 15 | 145,839 | 273,149 | 1.873 | 0 | 256,000 |
| 9 | `agent` | 935,293 | 17 | 160,614 | 300,643 | 1.872 | 0 | 256,000 |
| 10 | `agent` | 1,018,480 | 19 | 175,323 | 328,138 | 1.872 | 0 | 256,000 |
| 11 | `agent` | 1,101,661 | 21 | 190,050 | 355,638 | 1.871 | 0 | 256,000 |
| 12 | `agent` | 1,184,847 | 23 | 204,889 | 383,133 | 1.870 | 0 | 256,000 |
| 13 | `agent` | 1,268,009 | 25 | 219,743 | 410,625 | 1.869 | 0 | 256,000 |
| **14** | **`agent`（压缩前末轮）** | **`1,351,180`** | **27** | **`234,438`** | **`438,119`** | **`1.869`** | **0** | **`256,000`** |
| **15** | **`checkpoint`（独立摘要）** | **`1,438,396`** | **30** | **`250,016`** | — | — | — | — |
| **16** | **`agent`（压缩后瘦身）** | **`58,375`** | **1** | **`12,798`** | **`19,145`** | `1.496` | **2** | **`256,000`** |
| 17 | `agent` | 147,087 | 3 | 28,346 | 47,403 | 1.672 | 0 | 256,000 |
| 18 | `agent` | 230,960 | 5 | 43,209 | 74,987 | 1.735 | 0 | 256,000 |
| 19 | `agent` | 314,156 | 7 | 57,980 | 102,487 | 1.768 | 0 | 256,000 |
| 20 | `agent` | 397,361 | 9 | 72,806 | 129,989 | 1.785 | 0 | 256,000 |
| 21 | `agent` | 480,565 | 11 | 87,691 | 157,490 | 1.796 | 0 | 256,000 |
| 22 | `agent` | 563,774 | 13 | 102,423 | 184,992 | 1.806 | 0 | 256,000 |
| 23 | `agent` | 646,991 | 15 | 117,198 | 212,495 | 1.813 | 0 | 256,000 |
| 24 | `agent` | 730,201 | 17 | 131,941 | 239,997 | 1.819 | 0 | 256,000 |
| 25 | `agent` | 813,431 | 19 | 146,747 | 267,499 | 1.823 | 0 | 256,000 |
| 26 | `agent` | 896,660 | 21 | 161,487 | 295,001 | 1.827 | 0 | 256,000 |
| *27* | *`agent`（会话终止未收 SSE）* | *979,891* | *23* | *—* | *322,503* | *—* | *0* | *256,000* |

### 4.3 `Gemini 4 Argon (High)` 逐轮实测表（会话 `b929077b…`）

| Wire 步号 `N` | `requestType` | 请求体字节数 | `contents` 条数 | 服务端 SSE ③ | 本地 DB `est` ② | 偏差比 ②/③ | `reason` | `maxctx` ① |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| — | `checkpoint`（首轮基线） | 82,969 | 1 | 14,753 | — | — | — | — |
| 1 | `agent` | 124,044 | 1 | 24,409 | 41,090 | 1.683 | 0 | 256,000 |
| 3 | `agent` | 206,870 | 3 | 39,389 | 68,536 | 1.740 | 0 | 256,000 |
| 5 | `agent` | 289,666 | 5 | 54,393 | 95,985 | 1.765 | 0 | 256,000 |
| 7 | `agent` | 372,463 | 7 | 69,854 | 123,434 | 1.767 | 0 | 256,000 |
| 9 | `agent` | 455,258 | 9 | 84,386 | 150,882 | 1.788 | 0 | 256,000 |
| 11 | `agent` | 538,054 | 11 | 99,384 | 178,330 | 1.794 | 0 | 256,000 |
| 13 | `agent` | 620,860 | 13 | 114,375 | 205,779 | 1.799 | 0 | 256,000 |
| 15 | `agent` | 703,658 | 15 | 129,366 | 233,228 | 1.803 | 0 | 256,000 |
| 17 | `agent` | 786,454 | 17 | 144,351 | 260,677 | 1.806 | 0 | 256,000 |
| 19 | `agent` | 869,253 | 19 | 159,956 | 288,127 | 1.801 | 0 | 256,000 |
| 21 | `agent` | 952,053 | 21 | 174,198 | 315,577 | 1.812 | 0 | 256,000 |
| 23 | `agent` | 1,034,856 | 23 | 189,246 | 343,028 | 1.813 | 0 | 256,000 |
| 25 | `agent` | 1,117,661 | 25 | 204,340 | 370,480 | 1.813 | 0 | 256,000 |
| 27 | `agent` | 1,200,462 | 27 | 219,218 | 397,931 | 1.815 | 0 | 256,000 |
| **29** | **`agent`（压缩前末轮）** | **`1,283,262`** | **29** | **`234,183`** | **`425,381`** | **`1.816`** | **0** | **`256,000`** |
| **31** | **`checkpoint`（独立摘要）** | **`1,370,117`** | **32** | **`250,554`** | — | — | — | — |
| **32** | **`agent`（压缩后瘦身）** | **`56,178`** | **1** | **`12,551`** | **`18,422`** | `1.468` | **2** | **`256,000`** |
| 34 | `agent` | 138,956 | 3 | 27,512 | 45,876 | 1.667 | 0 | 256,000 |
| 36 | `agent` | 221,728 | 5 | 42,503 | 73,328 | 1.725 | 0 | 256,000 |
| 38 | `agent` | 304,505 | 7 | 57,544 | 100,782 | 1.751 | 0 | 256,000 |
| 40 | `agent` | 387,277 | 9 | 72,638 | 128,234 | 1.765 | 0 | 256,000 |

### 4.4 历史真实长会话大样本验证（5,437 轮生成、41 次压缩周期）

对真实日常编程对话产生的超长会话数据库做只读扫描，同样观察到高度稳定的周期性自动压缩：

| 会话数据库前缀 | 累计 `gen_metadata` 行数 | 全程 `maxctx` ① | 触发压缩次数（`reason=2`） | 压缩前一行 `DB est` ② 实测范围 | 压缩当行 `DB est` ② 实测范围 |
|---|---:|---:|---:|---|---|
| `e07e5916…` | `3,379` 行 | `256,000` | **`28` 次** | **`240,503` – `255,990`** | **`22,459` – `25,074`** |
| `0b602ead…` | `2,058` 行 | `256,000` | **`13` 次** | **`252,807` – `255,968`** | **`19,929` – `23,858`** |

> **填充实验与日常对话的 `DB est` 比例差异说明**：日常编程对话包含大量代码符号、JSON 工具输出与中英文混合内容，其字节数与真实分词的换算比接近 `1.0–1.1`，因此压缩前 `DB est` 落在 `240K–256K`；而受控实验使用低信息密度的重复英文词填充，本地按字节估算显著高于真实分词，故 `DB est` 达到 `425K–438K` 时真实混合计数才跨过 `256,000`。

---

## 5. 专项逆向：`selectCheckpointExperimentKey` 与三级实验变体选择

`config.selectCheckpointExperimentKey`（`0x669b800..0x669b9e0`）由 `config.applyFeatureProviderCheckpointOverrideConfig`（`0x669ba6e`）唯一调用，负责按三级优先级探测模型的 Checkpoint 策略键：

1. **第一级探测（入参窗口后缀）**：若传入的窗口参数字符串非空（`0x669b842: test r8, r8`），将其与 `.rodata 0x46f06d6` 处的 `"context-window_"`（15 B）及 `<baseKey> + "/"` 拼接为 `<baseKey>/context-window_<arg>`（`0x669b88d`），向 Feature Provider 查询；命中则直接返回。
2. **第二级探测（全局特性开关变体）**：读取特性开关 `"checkpoint-variant"`（18 B 键名位于 `.rodata 0x4727b44`）的字符串值；若非空则拼接 `<baseKey>/<variant>`（例如 `"CASCADE_USE_EXPERIMENT_CHECKPOINTER/claude-1m_840k"`），向 Feature Provider 查询；命中则返回。
3. **第三级兜底（裸键）**：回落返回裸 `<baseKey>`（`0x669b961 / 0x669b973`）。

### `baseKey` 的 Protobuf 枚举描述符静态确证

在 `config` 包代码段中不存在直接加载 `"CASCADE_USE_EXPERIMENT_CHECKPOINTER"` 字面量的 `LEA` 指令。向上追踪调用方 `config.augmentConversationalConfigWithExperiment`（`0x66999f5`）：

```asm
66999f5: mov  eax, 0xf7                                        ; 枚举值 0xf7 == 247
66999fa: call codeium_common_go_proto.ExperimentKey.String      ; 0x5831940
```

在 `.rodata 0x4cd0d45` 的 Protobuf `EnumValueDescriptorProto` 表中读取枚举值 `247`（varint `f7 01`），其名称字段精确为 `0a 23 "CASCADE_USE_EXPERIMENT_CHECKPOINTER" 10 f7 01`，静态锁定 `baseKey = "CASCADE_USE_EXPERIMENT_CHECKPOINTER"`。

同时，引擎 `.rodata 0x9cdd558` 内嵌的 `58,622` 字节配置表定义了 7 个 `model_profiles`：覆盖 `Gemini 4 Argon` 的 `MODEL_PLACEHOLDER_M408` 与覆盖 `Gemini 3.8 Flash` 的 `MODEL_PLACEHOLDER_M124` 均仅含裸键 `"256000"`，无带 `/` 的高容量变体键。

---

## 6. 前端 `app.asar` 与引擎环境变量静态排查

1. **Electron 前端包排查**：按正确 payload 偏移（`291380`，经 PNG 文件头魔数校验）完整解析 `/opt/Antigravity/resources/app.asar` 的全部 1,097 个条目（750 个打包文件 + 347 个未打包条目）：`dist/services/settingsService.js` 仅含 3 个常规应用设置键；`dist/meter-*.js` 仅只读读取 `contextWindowMetadata` 渲染进度条；全包与引擎二进制中检索 `"900K"`（ASCII 与 UTF-16LE）命中数均为 **0**，`ContextWindowOption(s)` Getter 直接调用数为 **0**。
2. **引擎环境变量与 `256000` 立即数排查**：
   - 逐字节扫描 Checkpoint 决策链路的 12 个核心函数（`shouldCheckpoint`、`MaybeCreateCheckpoint`、`GetCheckpointConfig`、`ClampCheckpointConfigForModelInfo`、`selectCheckpointExperimentKey` 等），对 `os.Getenv` / `os.LookupEnv` 的直接 `e8 rel32` 调用数全部为 **0**。
   - 对整个 `.text` 段搜索小端字节 `00 e8 03 00`（`256000`）共命中 32 处；按真实指令边界反汇编核验后，仅 `utils.GetCheckpointConfig` 内的 **3 处**（`0x65155e2` 比较、`0x65155e8` 赋值、`0x651595a` 零容量兜底）是真正的 `256,000` 预算立即数，其余 29 处均为 `0x3e8`（`1000`）位移交界或 64 位掩码常数的跨字节重合。

---

## 7. 与 `antigravity-cli`（`agy` 1.5.1）原生通道异同对照与证据边界

### 7.1 核心异同对照

| 对比维度 | `antigravity-cli`（`agy` 1.5.1） | Antigravity 桌面端（`language_server`） |
|---|---|---|
| 自动压缩发起方与落库类型 | 客户端本地发起，SQLite `step_type = 23` | **相同**（客户端本地发起，`step_type = 23`） |
| 主生成请求是否含压缩控制字段 | 否（全树扫描 0 命中） | **相同**（50 个生成请求 0 命中） |
| 遥测接口暴露 `checkpointConfig` | 未见记录 | **存在**（`recordTrajectoryAnalytics` 含 `maxTokenLimit: 256000`） |
| 压缩后请求体缩减比例 | 缩减至原体积 `4.08%–4.23%` | **高度一致**（缩减至原体积 `4.32%–4.38%`） |
| 预置 UI 档位与 `settings.json` 通路 | 存在 `/model` 三档菜单与 `AGY_CLI_AUTO_COMPACT_OVERRIDE`（被门禁拦截） | **未发现**（无 UI 切换器，无对应环境变量） |
| 解锁补丁策略 | 20 字节打通 UI / 白名单 / `ContextWindowChoice` 持久化闭环 | **8 字节在 `ClampCheckpointConfigForModelInfo` 无条件写入 `MaxTokens - MaxOutputTokens`** |

### 7.2 证据边界声明

1. **云端目录原始响应体与本地快照区分**：目录分析基于引擎本地 `GetAvailableModels` RPC 快照（`127,777 B`），启动阶段云端 `v1internal:fetchAvailableModels`（响应 `19,758 B`）未单独留存完整原始报文。另外，由于本地默认钳位与目录策略对两个 Gemini 模型均给出 `256,000`，单凭结果值 `256,000` 不单独区分运行时究竟命中策略对象还是回退至同值默认。
2. **双模型表关联强度区分**：`Gemini 4 Argon` 的 20 条主请求具备 `requestId` 逐行确定性关联（`last_step_index = N - 1`）；`Gemini 3.8 Flash` 的 26 条主请求未记录 `requestId`，系按请求序列与长度特征重建。
3. **云端内部推理黑盒边界**：本文仅对客户端出站报文、SSE 响应键树与本地数据库行为作出结论，不对 Google 云端推理服务内部的缓存或注意力实现作越界断言。
