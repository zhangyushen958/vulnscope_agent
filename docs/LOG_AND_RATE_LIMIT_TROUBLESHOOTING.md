# 运行日志审查与稳定性修复说明

本文根据 `events.jsonl` 中 300 条样本的运行记录整理。日志包含样本索引、事件名称和错误消息，不包含 API Key。

## 1. 本次日志的基线

| 指标 | 数量 |
|---|---:|
| 样本总数 | 300 |
| 成功完成 | 39 |
| 失败样本 | 261 |
| 成功率 | 13% |

失败事件分类：

| 错误 | 次数 | 根因与处理 |
|---|---:|---|
| GitHub REST API `403 rate limit exceeded` | 188 | 匿名或超额度 GitHub API 请求；新增 GitHub Token 支持、响应头冷却和共享冷却状态 |
| Agent 工具调用次数超限 | 55 | 原工具调用上限过早中断；现在保留预算尾部用于提交结论，并可配置总工具预算 |
| 达到最大推理轮次 | 6 | 原推理轮数偏少且没有明确结论阶段；默认 16 轮，最后两轮只开放 `submit_verdict` |
| GitHub API `301 Moved Permanently` | 6 | GitHub REST API 仓库地址迁移；现在只跟随 `api.github.com` 同主机 HTTPS 重定向并缓存永久地址 |
| 单轮选择工具过多 | 4 | 原实现因单轮请求过多使整个样本失败；现在最多执行前 2 个，并向其余调用逐项返回错误 |
| GitHub codeload `429 Too Many Requests` | 2 | 仓库 ZIP 下载端点暂时限流；现在有界重试、尊重 `Retry-After`，默认批量并发降为 1 |

另有 35 条工具级警告：20 次 `find_definitions` 标识符格式错误、1 次 `find_callers` 标识符格式错误、5 次定义搜索触发源码预算、2 次代码搜索触发源码预算、2 次文件读取触发源码预算、3 次读取不存在的快照路径、1 次尝试读取非源码路径、1 次单字符搜索被旧校验拒绝。

## 2. GitHub REST API 403 与 codeload 429 必须分开看

日志中两类 HTTP 错误不是同一个服务：

- `https://api.github.com/repos/.../commits/...` 的 `403 rate limit exceeded` 是 GitHub REST API 提交元数据读取限流。
- `https://codeload.github.com/.../zip/...` 的 `429 Too Many Requests` 是仓库 ZIP 下载端点限流。
- 这两类都不是阿里云百炼 Chat Completions 的 429。

GitHub 官方说明：未认证 REST API 请求通常限制为每小时 60 次；使用个人访问令牌认证后，常规额度通常为每小时 5,000 次。达到主要限流时应根据 `x-ratelimit-reset` 等响应头等待重置；次级限流则应尊重 `Retry-After` 并采用退避策略。详见 GitHub 官方文档：<https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api>。

### 必须执行的配置

在 GitHub 账户生成一个访问令牌，仅授予读取所需仓库的最小权限。对于公开仓库，使用可读取公开仓库元数据的令牌即可。不要把令牌写进源码、前端文件、日志或提交到 Git。

编辑项目根目录 `.env`：

```dotenv
VULNSCOPE_GITHUB_TOKEN=你的GitHub访问令牌
VULNSCOPE_BATCH_CONCURRENCY=1
```

如果运行环境或数据集使用私有仓库，令牌必须对相应仓库具有读取权限。令牌只会用于 `api.github.com`；下载仓库 ZIP 的 `codeload.github.com` 请求不会携带令牌。

### 代码侧改动

- GitHub API `301/302/303/307/308` 只允许跟随 HTTPS `api.github.com` 同主机重定向，最多 5 次；永久重定向会缓存。
- GitHub API `403/429` 检查 `x-ratelimit-remaining`、`x-ratelimit-reset` 和 `Retry-After`。确认限流后设置共享冷却时间，避免批量任务中的每个样本继续发送必然失败的请求。
- codeload ZIP 使用流式下载，最多 3 次尝试；`Retry-After` 超过 30 秒时不在工作线程中长时间等待，而是明确提示稍后重跑。
- 默认批量并发为 1，降低对 codeload 的瞬时请求压力。

没有配置 `VULNSCOPE_GITHUB_TOKEN` 时，代码层无法突破 GitHub 的匿名配额；必须完成上述令牌配置并在限流窗口重置后重新提交失败样本。

## 3. “定义查询仅允许 C/C++ 标识符”

本次日志出现 `find_definitions` 20 次、`find_callers` 1 次。原因为模型有时把 `ns::func`、`obj.member`、`ptr->member`、函数调用或声明签名直接作为符号传入，而这两个工具只接受一个字面 C/C++ 标识符。

代码已经调整：

- 先识别函数声明/调用形式，提取函数名；
- 对命名空间、成员访问和模板限定名，只提取最后一个标识符；
- 对常见声明式表达式提取末尾有效标识符；
- `search_code` 支持 1～100 字符的单行字面量搜索；
- 无法安全解析的输入仍明确拒绝，不把任意自然语言或正则表达式当成代码查询。

Agent 提示词同时要求传入单个符号名，不重复执行相同失败查询。

## 4. 源码总量超过限制与文件读取失败

源码总量上限默认 `1024 MiB`，ZIP 下载上限默认 `250 MiB`，两者独立。配置：

```dotenv
VULNSCOPE_MAX_REPO_MB=1024
VULNSCOPE_MAX_REPO_ARCHIVE_MB=250
```

范围分别为 10～1024 MiB 和 10～512 MiB。**已经存在的 `.env` 会覆盖 `.env.example`**；如果此前是 `VULNSCOPE_MAX_REPO_MB=512`，必须手动改成 1024 并重启服务。

`read_file` 现在只读取已加载快照中索引到的 C/C++ 相对路径。模型猜测不存在的路径时，会返回相近路径建议并要求从 `search_code` / `find_definitions` 输出复制 `path`，而不是抛出文件系统原始异常。符号链接、路径穿越和非源码读取仍会被拒绝。

如果仓库源码超过 1024 MiB，程序仍会拒绝整个快照；不要无限提高硬上限。应后续采用按目录/符号定向下载或仓库树索引方案。

## 5. Agent 工具预算和最大推理轮次

默认参数如下：

```dotenv
VULNSCOPE_MAX_AGENT_STEPS=16
VULNSCOPE_MAX_TOOL_CALLS=32
VULNSCOPE_BATCH_CONCURRENCY=1
```

Agent 行为：

- 每轮最多执行 2 个工具调用；模型一次请求更多工具时，其余调用获得工具级错误响应，不再直接判定整条样本失败。
- 研究工具总预算默认 32 次；接近预算尾部时停止搜索，仅开放 `submit_verdict`。
- 最后两轮推理专门保留给最终结论。
- 仓库加载因限流、源码预算或文件问题失败后，不重复下载；Agent 进入结论阶段，使用当前函数与已获取的 RAG/工具证据。
- 仍然无法得到有效结构化结论时，样本保留失败，不生成虚假的 0/1 预测。

模型设置页保存的 `max_agent_steps` 会写入 SQLite，优先于 `.env` 的初始默认值。部署后请打开「模型设置」，确认最大推理步数为 16，再保存；旧任务不会被修改。

## 6. 部署操作顺序

1. 将新版代码包解压到部署目录。
2. 将旧项目 `.env` 复制到新项目，保留百炼 API Key 和 WorkspaceId；补充 `VULNSCOPE_GITHUB_TOKEN`。
3. 将 `VULNSCOPE_BATCH_CONCURRENCY` 设为 `1`、`VULNSCOPE_MAX_AGENT_STEPS` 设为 `16`、`VULNSCOPE_MAX_TOOL_CALLS` 设为 `32`、`VULNSCOPE_MAX_REPO_MB` 设为 `1024`。
4. 停止旧服务后重新启动：`bash scripts/start.sh`。
5. 浏览器执行 `Ctrl+Shift+R`，在模型设置中保存 16 轮配置。
6. 重新提交之前失败的样本。已完成/失败的历史任务不会自动重跑或篡改。

查看服务日志：

```bash
tail -f logs/server.log
```

查看任务事件：

```bash
tail -f result/<job_id>/events.jsonl
```

注意日志可能包含仓库路径、代码片段或错误上下文；共享日志前请先检查并脱敏。绝不要分享百炼 API Key 或 GitHub Token。
