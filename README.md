# VulnScope Agent V3.0 · 阿里云百炼 DeepSeek + 课程数据集直读 + Web 评分

高级软件工程课程大作业：基于历史 CVE 数据 RAG 与按需仓库上下文的 C/C++ 函数漏洞检测智能体。

**本版可直接从项目 `dataset/` 目录读取 `knowledge.jsonl` 和 `test.jsonl`，不需要执行 `import_course_zip.py`。** 同时支持在前端单独上传这两个 JSONL 文件，检测结束后自动保存预测与完整报告到 `result/<任务ID>/`，并在「检测评分」页面按课程标准显示 P-C、P-V、P-B、P-R。

> **批量评测说明（提交快照）**：批量任务会在提交时保存 `result/<job_id>/submitted_dataset.jsonl`，评分严格使用本次提交的样本顺序与内容。上传 `demo.jsonl` 等子集时，无需覆盖 `dataset/test.jsonl`。详见 [`docs/SUBMITTED_DATASET_SCORING.md`](docs/SUBMITTED_DATASET_SCORING.md)。


## 1. 项目结构

```text
vulnscope-agent/
├── dataset/
│   ├── knowledge.jsonl       # 课程提供：7,578 条历史函数（漏洞/修复版）
│   ├── test.jsonl            # 课程提供：300 条检测样本（150 对）
│   └── evaluation.py        # 课程原始评分工具（仅用于验证）
├── result/
│   └── <job_id>/
│       ├── result.jsonl     # 任务全部成功时自动生成，可用于课程提交
│       ├── reports.json     # 完整检测记录及错误信息
│       └── score.json       # 点击前端评分时写入（按课程标准）
├── runtime/                 # SQLite、已构建知识索引、只读仓库快照
├── app/
│   ├── web.py               # Web API / 默认文件入口
│   ├── course_io.py         # 校验、读取、结果持久化、评分适配
│   ├── scoring.py           # 与课程评分脚本一致的相邻配对规则
│   ├── dataset_adapter.py   # 课程历史知识样本严格配对、拒绝异常
│   ├── rag.py               # 本地历史案例 TF-IDF 检索
│   ├── agent.py             # 自主工具调用与最终结论
│   ├── repository.py        # 单版本仓库快照与按需读取
│   ├── llm.py               # 阿里云百炼 / DeepSeek OpenAI-compatible 适配层
│   ├── service.py           # 独立任务、持久化与版本隔离
│   ├── store.py             # SQLite 任务事件与设置
│   └── static/              # Web 页面、模型选择、评分图表
├── tests/
├── scripts/start.sh
├── .env.example
└── requirements.txt
```

`result/` 在首次启动时自动创建。每次运行生成独立目录，不会因重复运行覆盖其他任务提交文件；失败任务只生成 `partial_predictions.jsonl`，不会伪装为完整 `result.jsonl`。

## 2. Ubuntu / Linux 启动

需要 Python 3.11+，项目文件需在可写目录中。

```bash
cd ~/vulnscope-agent
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

编辑 `.env`，填写你的 **阿里云百炼 API Key** 和业务空间地址（以下以华北2 / 北京为例）：

```dotenv
# 阿里云百炼 API
VULNSCOPE_LLM_API_KEY=你的百炼API_KEY
VULNSCOPE_LLM_BASE_URL=https://你的WorkspaceId.cn-beijing.maas.aliyuncs.com/compatible-mode/v1

# GitHub REST API 访问令牌：批量检测强烈建议配置
# 只需读取公开仓库的令牌权限；不要把令牌提交到 Git 或发给他人
VULNSCOPE_GITHUB_TOKEN=你的GitHub访问令牌

# 稳定性与资源预算
VULNSCOPE_MAX_AGENT_STEPS=16
VULNSCOPE_MAX_TOOL_CALLS=32
VULNSCOPE_BATCH_CONCURRENCY=1
VULNSCOPE_MAX_REPO_MB=1024
VULNSCOPE_MAX_REPO_ARCHIVE_MB=250

VULNSCOPE_DATASET_DIR=dataset
VULNSCOPE_RESULT_DIR=result
```

默认模型为 `deepseek-v4.1-flash-1017`。启动后可在网页「模型设置」中切换 **DeepSeek V4.1 Flash（1017）** 或 **DeepSeek V4 Pro**；无需在 `.env` 中额外设置模型名称。请确保 API Key 与 WorkspaceId 属于同一地域。

百炼模型 ID、请求参数与连接测试细节见 [`docs/ALIYUN_BAILIAN.md`](docs/ALIYUN_BAILIAN.md)。

启动：

```bash
bash scripts/start.sh
# 或者等价执行
python -m uvicorn app.web:app --host 127.0.0.1 --port 8000
```

打开浏览器：**http://127.0.0.1:8000**。脚本使用 `python -m uvicorn`，已修复之前在 Ubuntu 虚拟环境中出现的 `exec: uvicorn: 未找到` 环境路径问题；如仍报告 `No module named uvicorn`，请先重新安装 `requirements.txt`。

## 3. 推荐的完整使用流程

1. **领域知识库** → 点击 **「读取 dataset/knowledge.jsonl 构建」**。也可上传单独的 `knowledge.jsonl`（保留 JSONL 和 ZIP 上传的兼容能力）。首次完整索引构建需要几秒至数十秒，取决于机器性能。
2. **模型设置** → 选择 DeepSeek V4.1 Flash（1017）/ V4 Pro、思考模式与推理步数，并测试 API 工具调用。连接测试固定使用非思考模式和 `tool_choice=required`；实际 Agent 在非思考模式下也会强制至少调用一个工具，思考模式则遵循百炼限制使用 `auto`。API Key 只在服务端配置。
3. **批量任务** → 点击 **「使用 dataset/test.jsonl 检测」**，无需上传文件。也可选文件后点击 **「使用上传文件检测」**。默认课程测试集有 300 条，每条独立执行 Agent 分析。
4. **检测过程与报告** → 查看 SSE 实时工具日志和单函数报告，完成后结果自动落盘到 `result/<job_id>/`，也可下载 `result.jsonl` 和 `reports.json`。
5. **检测评分** → 选择已结束的批量任务，点击 **「计算 / 更新评分」**，查看四类配对统计、成对正确率、等级和惩罚，并在 `result/<job_id>/score.json` 找到同样数据。

**注意**：评分需要 `dataset/test.jsonl` 保持与提交任务时完全一致。系统记录了提交时的样本内容指纹，避免不一致的测试文件被错误配对评分。仅检测结束后开放评分；缺失预测的任务展示「暂定等级」，而不是正式成绩。

## 4. 数据格式（直接对齐当前课程数据）

### `dataset/knowledge.jsonl`

每行一个函数版本，通常相邻两条构成 `target=1`（漏洞版）和 `target=0`（修复版），字段包括：

```json
{"idx": 0, "target": 1, "func": "int ...", "func_hash": 123456, "commit_id": "...", "commit_url": "...", "cve": "CVE-...", "cve_desc": "...", "commit_message": "...", "cwe": "['CWE-310']", "project": "...", "file_name": "None"}
```

`cwe` 在实际数据里可表示为类似 Python 列表字符串；`file_name` 可能是字符串 `"None"`。导入时规范化空值，并**要求配对记录的 CVE、提交 ID、提交 URL 完全一致**。本次数据集：7,578 条候选记录 → 3,772 对元信息一致 → 剔除 3 对重复内容 → 3,769 个独立索引案例。17 对元信息冲突的相邻记录被拒绝而不猜测配对。

### `dataset/test.jsonl`

每行一个独立检测样本：

```json
{"idx": 194963, "commit_url": "https://github.com/.../commit/...", "target": 1, "func": "int ..."}
```

`target=1` 时仅允许获取修复提交**第一个父提交**的代码快照；`target=0` 时仅允许获取**修复提交自身版本**的代码快照。`target` 是仓库版本路由信息，**不会被放入 LLM 提示词、工具返回、RAG 查询或最终判定理由**；仓库工具按 Agent 自主请求时才获取快照。

### `result/<job_id>/result.jsonl`

仅在全任务成功时自动生成；每行严格包含课程提交字段：

```json
{"idx": 194963, "prediction": 0}
```

不要将 `reports.json` 或 `score.json` 当作课程的 `result.jsonl` 提交。

## 5. 课程评分与有效性

- **P-C**：漏洞版预测 1，修复版预测 0。
- **P-V**：两版均预测 1。
- **P-B**：两版均预测 0。
- **P-R**：漏洞版预测 0，修复版预测 1。

基础等级：P-C ≥ 30 为 A，25–29 为 B，20–24 为 C，低于 20 为 D；P-R > P-C / 2 时降一级（最低 D）。分母按课程全部配对数计算，缺失预测不会被擅自补全。

本项目评分接口按提供的课程脚本规则使用 **JSONL 相邻记录配对**，而不是仅通过 `commit_url` 推断配对。**只有评分器读取测试 `target` 真值**，Agent 推理不读取成对标签或测试集中另一版本。你也可以独立比较课程原始脚本：

```bash
python scripts/evaluate_course.py --truth dataset/test.jsonl --pred result/<任务ID>/result.jsonl
```

## 6. API

| 路径 | 方法 | 用途 |
|---|---|---|
| `/api/knowledge/import-local` | POST | 从 dataset/knowledge.jsonl 构建 RAG |
| `/api/knowledge/import` | POST multipart | 上传 JSONL/ZIP 构建 RAG |
| `/api/jobs/batch-local` | POST | 从 dataset/test.jsonl 创建批量任务 |
| `/api/jobs/batch` | POST multipart | 上传 JSONL/ZIP 创建批量任务 |
| `/api/jobs/single` | POST JSON | 单函数检测 |
| `/api/jobs/{id}` | GET | 查询任务和逐项报告 |
| `/api/jobs/{id}/events` | GET | SSE 实时分析日志 |
| `/api/jobs/{id}/download?format=result` | GET | 下载完整结果（缺失预测拒绝） |
| `/api/results` | GET | 最近任务列表 |
| `/api/jobs/{id}/score` | GET | 检测结束后按匹配的本地 test.jsonl 评分并保存 score.json |
| `/api/models` | GET | 当前阿里云百炼 DeepSeek 配置 |
| `/api/models/select` | POST | 修改新任务模型设置 |
| `/api/models/test` | POST | 发起真实百炼 DeepSeek 工具调用探针 |

## 7. 测试和边界

```bash
python -m pytest -q
node --check app/static/app.js  # 安装了 Node.js 时可执行
```

- 不调用外部搜索，不从网络获取额外 CVE 知识；仅按样本提交链接获取允许版本的源码。
- 历史 CVE 知识只来源于课程提供的 `knowledge.jsonl`。
- 批量推理逐样本执行，不提供其他版本函数或 Git diff。
- 评分只评价真实结果，不提供或伪造 300 条样本的预测成绩。
- 任务级模型配置固定；失败任务的状态和部分输出可追溯。
- **实际阿里云百炼 API 调用、Git 仓库下载和真实 300 条预测未在离线环境中执行**；仍需使用你自己的 API Key 和网络环境进行验收。

技术方案和设计讨论详见 `docs/ARCHITECTURE.md`、`docs/DATASET_COMPATIBILITY.md`、`docs/V3_DATASET_WORKFLOW.md`。

## V3.2：DeepSeek 兼容、并发检测、运行时日志

- **模型模式修复：** 阿里云百炼请求显式设置 `enable_thinking`；直接使用 DeepSeek 官方 API 时保留 `thinking.type` 兼容逻辑；思考模式保留每轮 `reasoning_content`，支持工具调用。
- **批量任务并发：** 默认 `VULNSCOPE_BATCH_CONCURRENCY=1`，范围 1–6；结果仍按输入顺序保存。GitHub codeload 429 或供应商限流时保持 1，不建议直接提高并发。
- **仓库 ZIP：** 大型仓库的非源码条目不会再触发过去 25,000 条上限，但仍保留压缩、解压大小和源码数量限制。
- **实时日志：** `result/<任务ID>/events.jsonl` 可在任务运行期间查看；SQLite 仍为主事件存储，任务结束后 `reports.json` 保存报告。
- **Agent 预算：** 默认最多 16 轮推理、32 次研究工具调用、每轮最多执行 2 个工具；最后两轮与研究工具预算尾部保留给 `submit_verdict`。超出单轮请求数时只执行前两个并向模型返回逐项错误，不再直接终止样本。
- **不调用工具：** 如模型返回格式严格正确的 JSON 判定，可直接接受；否则要求模型选择授权工具或提交结构化判定，不把普通文本猜成预测。
- **GitHub 限流：** 批量读取提交元数据建议在 `.env` 配置 `VULNSCOPE_GITHUB_TOKEN`。匿名 GitHub REST API 配额较低；认证令牌通常可将额度提升到每小时 5,000 次。达到限流后程序按响应头进入冷却期，不会持续重试。

详见 `docs/V3_2_STABILITY.md`。

### V3.3 网页清空并重新运行（无需重启）

「检测评分」页面可 **删除所选历史任务** 或 **清空全部历史任务与结果日志**；「领域知识库」页面可单独 **清空 RAG 索引**。清空结果后直接重新提交 `dataset/test.jsonl` 即可，保留 API Key、原始数据与历史案例知识库。运行中任务不可删除，清空前务必备份重要输出。详细使用方式及接口见 `docs/V3_3_CLEAR_RESET.md`。


### 大型 GitHub 仓库

如使用大型 C/C++ 仓库，可在 `.env` 中调整快照限制：`VULNSCOPE_MAX_REPO_MB=1024`（源码解压量，范围 10～1024 MiB）和 `VULNSCOPE_MAX_REPO_ARCHIVE_MB=250`（压缩包下载量，范围 10～512 MiB）。修改后重启服务生效。注意：已有 `.env` 会覆盖 `.env.example`；如果原来设置为 `512`，需要手动改为 `1024`。

详细的日志诊断、GitHub Token 配置和限流处理见 [`docs/LOG_AND_RATE_LIMIT_TROUBLESHOOTING.md`](docs/LOG_AND_RATE_LIMIT_TROUBLESHOOTING.md)。
