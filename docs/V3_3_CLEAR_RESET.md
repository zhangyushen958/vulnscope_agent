# V3.3 前端清空与重新运行说明

## 网页入口

1. **检测评分 → 删除所选任务**：选择一条已结束批量任务，确认后删除该任务的 SQLite 记录及 `result/<job_id>/`（`result.jsonl`、`score.json`、`reports.json`、`events.jsonl`）。
2. **检测评分 → 清空全部历史任务与结果日志**：确认后删除所有已结束单样本与批量任务，以及它们的输出文件。之后可以在「批量任务」直接重新提交 `dataset/test.jsonl`，无需重启服务。
3. **领域知识库 → 清空当前 RAG 索引**：单独删除 `runtime/historical_cases.json` 和对应审计文件，清除内存索引。可立即点击「读取 dataset/knowledge.jsonl 构建」重建。

## 安全边界

- 清空操作不可撤销，请事先备份重要报告。
- **运行中或排队中的任务存在时，所有清空请求返回 HTTP 409**，防止后台线程向已清理任务写数据。需要等任务自然结束；此版本**不提供中止正在执行的模型 API 请求**。
- 清空结果 **不会清空 RAG、原始 dataset、快照缓存、.env 和模型配置**。清空 RAG **不会清空历史结果或原始数据**。
- 后端需要显式确认口令 `CLEAR_RESULTS` 或 `CLEAR_KNOWLEDGE`；前端二次确认。项目默认仅监听 `127.0.0.1`，不建议未经身份认证将管理接口开放到公网。
- 清空单个任务接口不接受目录路径，仅接受服务端生成的 32 位十六进制任务 ID。

## API

- `POST /api/results/clear`，请求 JSON：`{"confirm":"CLEAR_RESULTS"}`；可选 `job_id` 删除指定任务。
- `POST /api/knowledge/clear`，请求 JSON：`{"confirm":"CLEAR_KNOWLEDGE"}`。
- 对运行中的任务返回 `409`，任务不存在返回 `404`，参数错误返回 `422`。

## 升级注意

第一次替换到 V3.3 **需要停止旧服务并重新启动一次**，以加载新后端代码。以后每次重新运行检测仅使用网页清空按钮，无需重新启动 Python 服务。保留原有 `.env`、`runtime/`、`result/`、`dataset/`，以免升级时丢失历史结果和密钥。
