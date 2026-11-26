# V3.2 稳定性修复及并发检测说明

## 故障诊断

1. `仓库归档文件条目过多`：之前将 GitHub ZIP 中包含的文档、图片、目录等也计入 25,000 上限，误拒绝大型仓库。现在元数据总条目上限 200,000、可提取源码文件数 50,000；仍严格检查单源码文件 2 MiB、全部源码解压体积（默认 1024 MiB，由 `VULNSCOPE_MAX_REPO_MB` 控制，范围 10～1024 MiB）、归档下载体积、单个 SHA 的唯一版本以及 Zip Slip / 符号链接。
2. `HTTP 400`：阿里云百炼接口通过 `enable_thinking` 显式启用或关闭思考模式；DeepSeek 官方接口使用 `thinking.type`。百炼非思考模式使用 `tool_choice: required`，思考模式使用 `auto`；完整回传 `reasoning_content`，没有工具调用时不加入空的 `tool_calls` 字段。保留 HTTP 状态和安全的 API 错误代码，不暴露密钥、提示词或服务端原始错误消息。
3. `模型未选择任何工具`：支持严格 JSON 模式的模型自主直接给出最终判定（必须包含 prediction、reason、confidence、evidence 并通过校验），否则提示重新使用工具或者输出合格 JSON；不擅自把文字猜成 0/1。默认 16 轮，最后两轮只允许 `submit_verdict`，防止研究工具持续消耗预算而没有结论。

## 并发性能

- 默认 `VULNSCOPE_BATCH_CONCURRENCY=1`，可设为 `1` 至 `6`。批量同任务在每个样本维度并发；每条检测的 Agent / 版本路由 / 模型消息分别隔离；报告按原输入顺序写入。
- 并发不会让**单个函数**中的连续推理工具调用并行。时间主要取决于 LLM 请求和仓库下载。建议先用 `deepseek-v4.1-flash-1017` + 非思考模式 + 并发 1 开始；GitHub codeload 或模型服务出现 HTTP 429 时不要提高并发。
- 每份独立任务仍有独立 Job ID，切换模型只影响之后提交的新任务。

## 日志持久化

- **主要存储：** `runtime/jobs.sqlite3` 中 `jobs`、`events`、`rows`，每次事件立即提交。
- **运行时文件：** `result/<job_id>/events.jsonl`，按事件到达顺序逐条追加，包含 `id`、`created`、`kind`、`data`；实时可用 `tail -f` 观察。文件写入失败不会中止主检测，SQLite 仍提供事件。
- **任务结束后：** `result/<job_id>/reports.json`；完整任务 `result.jsonl`，部分失败 `partial_predictions.jsonl`；评分后 `score.json`。
- 目录保留仓库读取的代码片段和分析证据，请妥善设置文件权限。默认不记录 API Key 或原始供应商错误响应。并发事件按时间交错，但都携带 `idx`，结果行仍按原输入顺序排列。

## Ubuntu 安装与运行

```bash
cd ~/vulnscope-agent
source .venv/bin/activate
python -m pip install -r requirements.txt
# .env：
# VULNSCOPE_BATCH_CONCURRENCY=1
# VULNSCOPE_GITHUB_TOKEN=你的GitHub访问令牌
# VULNSCOPE_MAX_AGENT_STEPS=16
# VULNSCOPE_MAX_TOOL_CALLS=32
# VULNSCOPE_MAX_REPO_MB=1024
# VULNSCOPE_MAX_REPO_ARCHIVE_MB=250
bash scripts/start.sh
```

网页里将推理模式选为「非思考模式」后，新任务的请求将明确关闭思考；已有任务不会被改变。不要在未验证权限的场景下把本地 API 暴露在公网。

无法仅凭 HTTP 400 的状态确定供应商实际拒绝原因；若故障持续，请保留完整的 HTTP 状态、接口错误**类型**以及失败样本 idx，不要分享 API Key 或完整提示词。该修复版测试使用 `httpx.MockTransport`，未使用你的真实 DeepSeek 凭证进行外网调用。
