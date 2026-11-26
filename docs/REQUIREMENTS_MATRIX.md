# PPT 需求逐项对应与验收清单

本表来自用户上传的《3. 函数漏洞检测智能体工具.pptx》共 10 页。状态释义：**已实现**=源代码、界面或自动测试可核验；**待集成验证**=需要课程专属数据、真实仓库/模型环境才能完成；**增强方向**=PPT 给出的参考工具，非必须。

| PPT 页码 | 核心要求 | 工程实现 | 验收方式 | 状态 |
|---|---|---|---|---|
| 1、3 | 基于 LLM 的 C/C++ 单函数检测自主智能体 | `app/agent.py`、`app/llm.py` | `test_agent.py`，配置兼容模型执行单样本 | 已实现，真实效果待集成验证 |
| 3、5 | 历史 CVE 漏洞及修复案例构建领域知识库 | `app/rag.py` | 上传成对 JSONL，查看知识库数据量、检索记录 | 已实现；课程历史集未提供 |
| 5 | RAG 只能使用提供的数据集，不引入其他安全知识 | 索引仅由用户上传数据建立，无预置 CVE 语料 | 清空 runtime 后健康接口 `case_count=0` | 已实现；数据来源需用户保证 |
| 4 | 知识检索→初步分析→按需读仓库→报告 | `retrieve / reason / execute / END` 条件图 | 查 `test_agent_has_autonomous_repository_loop` | 已实现 |
| 4 | 证据不足时才读仓库 | LLM 自主选择，工具不在固定流水线调用 | 检查 Agent trace 是否发生 `repository` 事件 | 已实现 |
| 6 | 检索调用方、被调用方、全局变量、类型/宏定义 | `find_callers` / `find_definitions` / `search_code` / `read_file` | `test_repository.py` | 已实现（词法近似） |
| 6、8 | 漏洞样本只能读取父提交版本 | `SnapshotProvider._resolve_ref(target=1)` | `test_snapshot_parent_vs_fixed` | 已实现 |
| 6、8 | 修复样本只能读取修复提交后版本 | `SnapshotProvider._resolve_ref(target=0)` | `test_snapshot_parent_vs_fixed` | 已实现 |
| 6、8 | 不得提供 git diff、两版本变更 | ZIP 文件白名单、不含 git 工具/历史 API、单版本工具绑定 | `test_ignore_noncode_and_symlink` | 已实现 |
| 7 | 必须有图形化界面（不能只有 CLI） | `app/static/index.html`、`style.css`、`app.js` | 打开首页与功能标签 | 已实现 |
| 7 | 支持单样本及批量 `.jsonl` 输入 | `/api/jobs/single`、`/api/jobs/batch` | `test_api.py` | 已实现 |
| 7 | 报告包含 idx、0/1、理由与分析记录 | `DetectionReport`、SQLite、UI | 检查 `reports.json` 的四类要素 | 已实现 |
| 7 | 在 GUI 实时显示知识/仓库工具的记录 | SQLite trace + SSE + JS 时间线 | 运行任务时观察记录面板 | 已实现 |
| 8 | 150 对、共 300 条真实样本 | 批量输入可承载 300 条 | 上传课程提供的 300 条 JSONL | 待课程测试集 |
| 8 | 每次只输入一对中的一个 | 一个样本一次 agent.detect 独立上下文 | `test_no_test_label_or_commit_url_in_prompt` | 已实现；输入方需保证不合并函数 |
| 8 | 汇总 `result.jsonl`，每条 `idx`,`prediction` | 导出接口 `/download?format=result` | `test_single_job_end_to_end_and_export` | 已实现 |
| 9 | P-C/P-V/P-B/P-R 和成绩/惩罚规则 | `scripts/evaluate_pairs.py` | `test_evaluate.py` | 已实现；真实分数待数据 |
| 10 | 独立自主 Agent、不是简单固定 API 链 | LangGraph + LLM 原生 tools、循环路由 | 检查决策与工具调用轨迹 | 已实现；原生 LangGraph 需在完整依赖环境验证 |
| 10 | 禁止除目标仓库以外的网络搜索 | 仓库网络固定 GitHub API/codeload，模型仅为推理 API，无 Web 搜索工具 | URL 拒绝、工具授权测试 | 已实现 |
| 10 | Tree-sitter AST 提升解析精度 | 当前实现词法检索；可选二期替换 | 查看 `ARCHITECTURE.md` | 增强方向（非强制） |

## 正式提交前建议验收步骤

1. 确认从学校下载的 `history.jsonl` 真实字段，若与示例不同，补充字段映射后导入；不要混入额外安全知识。
2. 正式环境 `pip install -r requirements.txt`，确保 `langgraph_installed=true`。
3. 配置可用的支持 tool_calls 的 LLM，完成 UI 单条样本完整检索与报告。
4. 选一条有真实 GitHub 提交链接的样本，校验是否严格落在正确父/当前 SHA，确保 UI 仓库事件与 Agent 工具行为正常。
5. 上传 300 条测试集，确保完整导出且无失败行。
6. 用课程附带 `dataset/evaluate.py` 作为官方成绩计算依据；项目内脚本作为本地对照统计。
7. 导出 `reports.json` 和项目源代码作为研发与过程可追溯证据。
