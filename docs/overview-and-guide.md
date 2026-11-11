# 原理与使用指南：Antigravity 桌面端的上下文压缩机制与解锁方案

> 本文档面向希望快速理解 Antigravity 桌面端（Electron 应用及其推理引擎 `language_server`）上下文限制成因、Token 计量口径、双通道差异以及 8 字节补丁原理的用户与开发者。底层反汇编地址、协议键树与逐轮抓包原始数据请参阅配套技术文档：
> - [《二进制补丁与脚本实现详解》（`binary-patch-internals.md`）](binary-patch-internals.md)
> - [《技术报告：Google OAuth 原生通道上下文机制与实测数据》（`mechanism-native-oauth.md`）](mechanism-native-oauth.md)
> - [《技术报告：企业网关与自定义模型通道上下文机制与实测数据》（`mechanism-enterprise-gateway.md`）](mechanism-enterprise-gateway.md)

---

## 1. 核心机制问答

### 1.1 长对话中的历史消息“被总结压缩”，是由云端服务端执行的还是由本地桌面端执行的？

**完全由本地桌面端推理引擎 `language_server` 主动发起，而非云端 API 在主请求上的硬性截断。**

Antigravity 桌面端采用“Electron 前端界面 + Go 本地推理编排引擎（`/opt/Antigravity/resources/bin/language_server`）”的双层架构。所有对话历史组装、上下文预算检查与请求发送均由本地 `language_server` 完成。当会话累积到预算上限时，客户端在本地按顺序执行三步操作：

```text
[用户提交新一轮消息]
        │
        ▼
  本地引擎检查：当前待发轨迹的混合 Token 计量 > CheckpointConfig.MaxTokenLimit ？
        │
        ├── 否（未超预算）──► 直接发送常规主生成请求（携带完整历史消息）
        │
        └── 是（超出预算）──► 触发本地自动压缩（Checkpointing）三步曲：
               1. 发送独立摘要请求：向模型端点发送一条延续摘要请求
                  （原生通道顶层带 requestType: "checkpoint"；
                   网关通道表现为 max_completion_tokens 从默认值降为 16384）
               2. 落库本地 Checkpoint：在 ~/.gemini/antigravity/conversations/<uuid>.db
                  的 steps 表写入一条 step_type = 23 的摘要步骤
               3. 替换历史并发出主请求：用刚生成的摘要替换此前数十轮旧消息，
                  再发送本轮真正的主请求（请求体积瞬间缩减约 95.6%–98.6%）
```

对捕获的全部主生成请求进行全深度 JSON 键名扫描，`checkpointConfig`、`maxTokenLimit`、`contextWindow` 等配置字段出现次数均为 **0**。而在原生通道中，客户端事后发往 `v1internal:recordTrajectoryAnalytics` 遥测接口的数据包里直接包含了内存中的 `checkpointConfig` 对象（未修补时显示 `"maxTokenLimit": 256000`），从网络层直观印证了该预算属于客户端本地状态。

---

### 1.2 为什么预算写着 `256,000`，本地数据库里的 `estimated_tokens_used` 却涨到了 `438,119`，而服务端返回的用量只有 `234,438`？

**因为系统中同时存在三套不同的 Token 账本，而真正决定是否触发压缩的是第四个内部“混合计量值”。**

以原生通道下 `Gemini 3.8 Flash (High)` 跨越压缩点的实测数据为例，三套外部可见数值的含义与关系如下：

| 计量口径 | 存储或协议位置 | 产生端 | 压缩前末轮实测值 | 真实含义与常见误区 |
|---|---|---|---:|---|
| **① 本地配置预算**<br>（`maxctx`） | SQLite `gen_metadata` → `max_context_tokens`；以及目录策略 `max_token_limit` | `language_server` 本地配置层 | **`256,000`**<br>*(模型宣告总容量为 `1,048,576`)* | 客户端配置层的上下文预算上限。整场对话恒定，不随主请求发送给服务端。 |
| **② 本地数据库诊断估算**<br>（`DB est`） | SQLite `gen_metadata` → `estimated_tokens_used` | `DefaultSerializer.populateContextWindowMetadata` 本地按字节近似构造 | **`438,119`**（`reason=0`）<br>压缩后首轮降至 **`19,145`**（`reason=2`） | **事后写入数据库的粗算诊断值**。在英文填充测试下比服务端真实分词高出 **82%–87%**；**它并非触发压缩的门禁水位线**，因此超过 `256,000` 甚至超过 `1,000,000`（网关或补丁后）均属正常。 |
| **③ 服务端 SSE 报告用量**<br>（`promptTokenCount`） | `streamGenerateContent?alt=sse` 响应末尾的 `usageMetadata.promptTokenCount` | 上游模型推理服务分词统计 | 压缩前主请求：**`234,438`**<br>独立摘要请求：**`250,016`**<br>压缩后主请求：**`12,798`** | 服务端对该次请求实际统计的输入 Token 数量。 |

既然压缩前最后一轮主请求的 SSE 用量是 `234,438`（尚未达到 `256,000`），为什么紧接着下一轮在发出主请求前就触发了压缩？反汇编 `TrajectoryToChatMessagesToTokenLimitOrStepIndex` 揭示了引擎在开启 `"use_model_reported_token_count": true` 时的**内部混合计量公式**：

$$\text{当前待发轨迹内部计数} = \underbrace{\text{上一轮为止的模型报告前缀}}_{\text{Input} + \text{CacheRead} + \text{CacheWrite} + \text{Output}} + \underbrace{(\text{当前本地累计估算} - \text{上一轮本地基线})}_{\text{本轮新增用户消息的本地估算增量}}$$

检查发生在**新一轮用户消息已经拼入对话轨迹之后、向服务端发出之前**。此时服务端尚未对新消息分词，引擎便将“已知的历史服务端报告用量前缀（约 23.4 万 + 输出 Token）”与“本轮新增消息的本地估算增量”相加；一旦总和**严格大于（`>`）有效上限 `256,000`**，转换器立即返回截断哨兵错误，触发 `checkpoint.shouldCheckpoint` 启动本地摘要压缩。

---

### 1.3 为什么桌面端不能像命令行 `agy` 那样改 `settings.json` 或设环境变量，而采用 8 字节补丁？

尽管桌面端 `language_server` 与命令行工具 `/usr/bin/agy` 同源演进，但两者在配置入口与门禁结构上存在显著差异：

1. **桌面端原生通道没有预置 UI 档位切换器或覆盖环境变量**：
   - 在命令行版 `agy` 中，二进制已实现 `/model` 菜单的 `[Tab] Context (256K / 512K / 900K)` 选择器、`~/.gemini/antigravity-cli/settings.json` 的 `"contextWindow"` 读取函数以及 `AGY_CLI_AUTO_COMPACT_OVERRIDE` 环境变量，只需修补门禁即可恢复持久化闭环。
   - 在桌面端中，完整扫描 Electron 前端 `app.asar` 的 1,097 个文件及引擎 Checkpoint 链路的 12 个核心函数后确认：前端仅包含只读展示上下文用量的进度条组件（`dist/meter-*.js`），没有窗口档位设置项；引擎侧也不读取 `AGY_CLI_AUTO_COMPACT_OVERRIDE` 或 `contextWindow` 字段。
2. **两道预算天花板叠加在 `CheckpointConfig` 构造链路上**：
   ```text
   cortex.(*CascadeManager).getCascadeConfig
    └─ config.GetCascadeConversationalConfigWithExperiment
        ├─ 1. resolveDefaultCheckpointConfig
        │      └─ utils.GetCheckpointConfig
        │           └──► [天花板 ①] 对 apiProvider == 3 / 24 / 26 执行 min(x, 256000)
        ├─ 2. applyFeatureProviderCheckpointOverrideConfig
        │      └─ config.MergeConfigsDedup
        │           └──► 合并目录实验策略 CASCADE_USE_EXPERIMENT_CHECKPOINTER
        │                （Gemini 3.8 Flash / 4 Argon 策略值均为 "max_token_limit": "256000"）
        └─ 3. clampAndValidateConfig
               └─ utils.ClampCheckpointConfigForModelInfo
                    └──► 计算模型物理上界 esi = MaxTokens - MaxOutputTokens（如 983,040）
                         • 原版逻辑：仅当 MaxTokenLimit > esi 时才写入 esi（保留 256,000）
                         • [8 字节补丁]：改为无条件将 esi 写入 MaxTokenLimit！
   ```
   由于第 2 步合并进来的实验策略同样携带 `"max_token_limit": "256000"`，只修改第 1 步的 `min(x, 256000)` 仍会被第 2 步打回 `256,000`。本仓库的 `antigravity_context_unlock.py` 选择在第 3 步 `utils.ClampCheckpointConfigForModelInfo` 将“条件上界截断”改为“无条件写入物理上界 `MaxTokens - MaxOutputTokens`”，仅用 **8 字节**便同时跨过了两道 `256,000` 限制，且自动适配不同模型的容量参数。

---

### 1.4 为什么桌面端接入“企业网关通道”时，不需要打补丁就已经有 `872,000` 预算？

这是桌面端与命令行版 `agy` 最核心的一处行为分歧：

- 在**命令行版 `agy`** 中，企业网关模型被当作普通自定义模型处理，在未修补状态下落入 `min(x, 256000)` 默认钳位，同样被锁死在 `256,000`。
- 在**Antigravity 桌面端**中，当通过 `~/.antigravity/settings.json`（配置 `gateway` 与 `models.listSource`）或 `AGY_LLM_GATEWAY_*` 环境变量接入企业网关时：
  1. 引擎将网关模型的 `apiProvider` 标记为 **`API_PROVIDER_OPENAI_VERTEX`（枚举值 `31`）**。
  2. 在 `utils.GetCheckpointConfig` 中，代码明确判断 `apiProvider` 是否等于 `3`、`24` 或 `26`；由于网关模型为 `31`，一条条件跳转直接**绕过了 `min(x, 256000)` 钳位分支**。
  3. 同时，网关目录条目不包含 `CASCADE_USE_EXPERIMENT_CHECKPOINTER` 的 256K 策略覆盖，引擎直接保留 `utils.GetDefaultCheckpointConfigForModel` 根据网关目录字段算出的默认预算：
     $$\text{MaxTokenLimit} = \max\big(0,\ \text{MaxTokens} - \max(40000,\ \text{MaxOutputTokens})\big)$$
     例如当网关目录声明 `maxTokens = 1,000,000`、`maxOutputTokens = 128,000` 时，桌面端默认即获得 **`872,000`** 的本地上下文预算（原生通道未修补时的 **3.406 倍**），且修改网关目录返回的容量字段即可免补丁调整该预算。

---

## 2. 全景横向对比：桌面端原生通道 vs. 桌面端企业网关 vs. 命令行 `agy`

| 对比维度 | 桌面端：Google OAuth 原生通道 | 桌面端：企业网关通道 | 命令行版：`antigravity-cli`（`agy`） |
|---|---|---|---|
| **核心二进制** | `language_server`（Go PIE） | `language_server`（Go PIE） | `/usr/bin/agy`（Go PIE） |
| **通信协议与端点** | HTTPS `daily-cloudcode-pa.googleapis.com/v1internal:*` | OpenAI `/v1/chat/completions` 或 GenAI `:streamGenerateContent` | 原生 `v1internal:*`；网关 `/v1beta/models/*` |
| **未修补默认预算（Gemini 3.8/4）** | **`256,000`** | **`872,000`**（以目录 `1M / 128K` 为例） | 原生与网关均为 **`256,000`** |
| **是否命中 `min(x, 256000)`** | 是（`apiProvider = 24`） | **否**（`apiProvider = 31` 跳过钳位） | 是 |
| **主请求是否含压缩控制字段** | 否（全树扫描 0 命中） | 否（180 个请求全树扫描 0 命中） | 否 |
| **独立摘要请求的协议特征** | 顶层 `requestType == "checkpoint"` | `max_completion_tokens` 降为 **`16384`** | 独立摘要生成请求 |
| **本地 SQLite 压缩记录类型** | `steps` 表 `step_type = 23` | `steps` 表 `step_type = 23` | `steps` 表 `step_type = 23` |
| **原生 UI 档位或环境变量覆盖** | 无 UI 切换器，无窗口覆盖环境变量 | 无独立开关，但**直接读取网关目录 `maxTokens` 计算** | 有 `/model` 三档菜单与环境变量（原版被门禁阻断） |
| **推荐扩容方式** | **运行本仓库 8 字节补丁**（提升至 `maxTokens - maxOutputTokens`，如 `983,040`） | **免补丁**：按上游模型真实容量配置网关目录 `maxTokens` | 运行 [`agy-context-unlock`](https://github.com/MatrixC7/agy-context-unlock) 20 字节补丁 |

---

## 3. 常见认知误区与客观边界说明

1. **误区：“抓包看到请求体达到 `1.35 MB`（或网关下 `3.49 MB`）且返回 `HTTP 200`，说明已经跑满了 `1.35M` / `3.49M` tokens！”**
   - **客观事实**：HTTP 请求体的**字节数（Bytes）不等于 Token 数**。实测原生通道 `1.35 MB` 的 JSON 请求体对应服务端 `promptTokenCount = 234,438` tokens；企业网关下 `3.49 MB` 的请求体对应服务端 `prompt_tokens = 625,067`（Gemini）至 `718,481`（DeepSeek）tokens。
2. **误区：“SQLite 数据库里的 `estimated_tokens_used` 就是触发压缩的阈值，超过 `maxctx` 没压缩说明预算失效了！”**
   - **客观事实**：`estimated_tokens_used` 是事后按字节近似算法写入数据库的诊断快照，在纯英文随机词填充下约为服务端真实分词的 **1.62–1.87 倍**。在补丁解锁后（`maxctx = 983,040`），连续运行 40 轮时 `estimated_tokens_used` 达到 `1,117,452` 而未触发压缩，正是因为对应的真实混合 Token 计量尚未触及 `983,040` 上限。
3. **误区：“打上补丁或调大网关目录 `maxTokens` 后，云端模型就能无限制接收任意长度的上下文！”**
   - **客观事实**：客户端补丁与目录调整**仅放宽本地客户端发起自动摘要的预算门禁**，不会改变云端推理引擎的物理上下文容量、单次超时限制或账号速率配额。若在网关目录中将某个物理上限仅 128K 的模型虚标为 `maxTokens = 2,000,000`，当真实输入超过 128K 时上游 API 将直接返回超限报错。因此，网关目录中的 `maxTokens` 应始终如实反映上游模型的真实物理容量。
4. **误区：“在桌面端环境变量中设置 `AGY_CLI_AUTO_COMPACT_OVERRIDE=900000` 也能生效！”**
   - **客观事实**：`AGY_CLI_AUTO_COMPACT_OVERRIDE` 是命令行版 `antigravity-cli`（`agy`）特有的环境变量，桌面端 `language_server` 二进制中不存在该字符串与读取逻辑。
5. **注意单条用户消息的 `192 KB` 独立截断机制**：
   - 无论会话总预算为 `256,000`、`872,000` 还是 `983,040`，桌面端引擎在 `TrajectoryConversionConfig.MaxTokensPerUserInputStep` 中默认设定单步用户输入上限为 `64,000`（按 `×3` 字节近似折算约 **`192,000` 字节**）。单次粘贴发送超过约 192 KB 的超长纯文本时，超出部分会在该条消息末尾附注 `<truncated ... bytes>`。这属于单步输入保护机制，与多轮历史累计触发的 `step_type = 23` 自动摘要互不干扰。
