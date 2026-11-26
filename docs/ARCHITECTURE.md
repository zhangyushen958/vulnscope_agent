# 系统架构与研发技术说明

## 1. 设计目标

建立一个以「单个函数检测」为最小隔离单位的 C/C++ 安全分析 Agent。研发中保留三层边界：

- **知识边界**：知识索引只包含指定的历史配对 CVE 数据集，任何案例导入都必须显式上传。
- **证据边界**：LLM 只看到当次函数、RAG 匹配和当前唯一快照的只读工具结果。
- **评价边界**：`target` 虽然是对应版本的路由标识，但不会暴露给 LLM；只有离线评测脚本才能将其作为真值使用。

## 2. 分层与依赖

```
浏览器（HTML / CSS / JS）
    │ REST / Server-Sent Events
    ▼
FastAPI 接口  ──────── SQLite 事件/报告持久化
    │
    ▼
DetectionService（一个样本一次 Agent 调用）
    ├── HistoricalKB ── JSONL 解析/验证 ── 本地 sklearn TF-IDF 向量
    ├── SnapshotProvider ── GitHub commits API ── codeload ZIP（已解析唯一 SHA）
    └── VulnerabilityAgent ── LangGraph StateGraph
          ├── retrieve ─► reason ◄──── execute
          │                     └─条件分支─► execute（调用模型选中的工具）
          └──────────────────────────────► END（submit_verdict）
```

## 3. Agent 状态机

### 3.1 `retrieve` 节点

初始检索由系统执行，保证先获取领域历史证据。按函数源码做局部向量查询，检索历史案例；排除与待测函数源码完全相同的知识样本，以及相同修复提交 URL 的案例，降低数据泄漏风险。记录案例 ID、CWE、项目和余弦综合分。历史案例可以成对完整提供（仅历史知识集允许）。

### 3.2 `reason` 节点

模型接收当前函数、历史案例（无当前样本的 label / commit URL）及先前工具观察。模型自由选择下列工具之一或多个：

| 工具 | 参数 | 使用场景 |
|---|---|---|
| `retrieve_more_cases` | `query`, `top_k` | 分析过程中要验证相似模式 |
| `search_code` | `symbol` | 追踪相关标识符与使用位置 |
| `find_callers` | `symbol` | 定位可能调用当前函数的位置 |
| `find_definitions` | `symbol` | 类型、宏、全局变量、辅助函数的候选定义 |
| `read_file` | `path`, `start_line`, `end_line` | 阅读具体证据行和辅助实现 |
| `submit_verdict` | `prediction`, `reason`, `confidence`, `evidence` | 终止本次分析 |

仓库工具仅当已被授权读取一个快照时才暴露。LLM 通过原生 tool_calls 自主决定是否继续研究；代码不强制每一轮按固定顺序调用工具。缺少真实工具选择时不会生成虚假报告。

### 3.3 `execute` 节点

执行 Agent 选择的工具，将输出作为 `role=tool` 的证据返回模型，构成真正的 **Reason→Act→Observe→Reason** 循环。`submit_verdict` 需要满足结构校验。事件同步记录到 SQLite，前端通过 SSE 逐条更新。最多 8 个模型推理轮次（可配置 2–20），最多 24 个工具调用。超过预算直接失败，不以随机或默认值填充预测。

### 3.4 条件路由

`reason → execute` 发生在有 tool calls 时；`execute → END` 仅当存在合法 `submit_verdict`；其余转回 `reason`。无 tool call 则请求模型改为 function calling。LangGraph 以 StateGraph 完成条件路由；无依赖的离线测试系统使用同一状态转换的兼容解释器。

## 4. RAG 实现细节

采用纯本地、无需联网下载模型的 **双索引稀疏向量混合检索**：

1. 函数代码（历史漏洞版与修复版拼接），使用字符 3–5gram TF-IDF，兼顾 C/C++ 符号差异和短代码片段。
2. 元信息（CVE 描述、commit message、CWE、project、file_name 与部分代码），使用单词 1–2gram TF-IDF。
3. 加权余弦相似度 `S = 0.72*S_code + 0.28*S_metadata`。
4. 返回 Top-K，含历史案例 ID、相似度、漏洞/修复代码摘录及元信息。Top-K 默认 4，最大 8。

TF-IDF 词表由历史数据本身拟合，**没有从外部安全知识库加载词典、CVE、向量或文本**。该方法可换成本地编码器，但替换时必须确保没有引入额外安全知识且要注明是否使用了模型先验。

知识导入完整过程：`字节输入 → UTF-8 JSONL 解析 → 逐条字段校验 → 严格配对 → 去重 → 两索引拟合 → 临时文件 → 原子替换`。任何解析或拟合失败保留旧版本，防止 UI 显示已入库但实际索引不可用。

## 5. 单版本快照原则

解析格式 `https://github.com/{owner}/{repo}/commit/{fix_sha}`：

- target = 1（漏洞版）：`GET https://api.github.com/repos/{owner}/{repo}/commits/{fix_sha}`，获取 `parents[0].sha`，然后只下载该 SHA 的 ZIP。
- target = 0（修复版）：获取当前提交的 canonical 40 位 SHA，下载该 SHA 的 ZIP。
- 单次检测绑定 `RepositoryTools(root=唯一SHA对应路径)`。代码只在这个 root 下查找源码，无切换提交工具，也没有仓库历史 API 接口。

合并提交默认取第一个父提交；测试集若有特殊合并提交约定应先核对，不能使用错误版本。快照下载时需联网访问 GitHub；工具层面没有 `git diff`、`git log`、`git show`、`git checkout`、全局文件读取或外部搜索。

## 6. 读仓库工具实现

- `search_code`：字面量匹配，单次至多 32 条结果，拒绝换行和超长查询。
- `find_callers`：基于标识符 `name(` 的有界近似查询，扫描至多 24 个候选调用位置；必须结合 `read_file` 排除定义和注释。
- `find_definitions`：定位某个标识符相关的定义/声明/使用，不能保证 AST 精确语义。
- `read_file`：只能读取受限后缀的源码，限制单文件 2MB、行范围最多 180 行；对路径进行 realpath 校验。

> 这里使用有界词法索引而非 Tree-sitter AST，是可复现的基础方案。为提高调用关系精度和减少误报，建议作为二期扩展接入 Tree-sitter，仅从同一版本的源码构建 AST。

## 7. 结果与事件结构

单条报告：

```json
{
  "idx": 123,
  "prediction": 1,
  "reason": "结合函数及上下文的详细分析理由……",
  "confidence": 0.73,
  "evidence": ["来源位置、相关代码及逻辑事实"],
  "trace": [
    {"kind":"knowledge", "title":"初始历史案例检索", "detail":{"matches":[]}},
    {"kind":"repository", "title":"Agent 按需读取仓库上下文", "detail":{"tool":"read_file"}}
  ],
  "repository_status": "available"
}
```

这里的内容和置信度只是**接口格式示意**，不是项目已跑出的真实结果。评测格式严格限于 `{"idx":..., "prediction":0/1}`。

## 8. 延迟与扩展

每项任务顺序处理，避免并行模型请求造成输入/输出混淆。SQLite 允许多个 HTTP 请求读取进度；SSE 带递增 ID，客户端可通过 `Last-Event-ID` 断线续传。长期大规模应用可将任务执行拆分到消息队列、加上用户隔离、并优化文件索引及 embedding 检索。单次请求对源码、数据、ZIP、工具调用次数均有上界。
