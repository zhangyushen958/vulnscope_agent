# 阿里云百炼 DeepSeek 接入配置

本项目使用阿里云百炼的 OpenAI 兼容 Chat Completions 接口。API Key 仅保存在服务端 `.env` 中，不会返回给网页或写入模型提示词。

## `.env` 配置

以华北2（北京）为例：

```dotenv
VULNSCOPE_LLM_API_KEY=你的百炼API_KEY
VULNSCOPE_LLM_BASE_URL=https://你的WorkspaceId.cn-beijing.maas.aliyuncs.com/compatible-mode/v1
```

请将 `你的WorkspaceId` 替换为百炼控制台中对应地域的业务空间 ID。API Key 与 WorkspaceId 必须属于相同地域。其他地域需要使用该地域对应的 Base URL。

## 支持的模型

| 网页显示名称 | 百炼请求中的 model 值 | 默认选择 |
|---|---|---|
| DeepSeek V4.1 Flash（1017） | `deepseek-v4.1-flash-1017` | 是 |
| DeepSeek V4 Pro | `deepseek-v4-pro` | 否 |

模型通过网页顶部的「模型设置」选择，保存后只影响新提交的任务。无需在 `.env` 中设置 `VULNSCOPE_LLM_MODEL`。

注意：DeepSeek 官方 API 文档将 V4.1 Flash（1017）对应的官方接口模型名写作 `deepseek-flash`；本项目连接的是阿里云百炼，因此按百炼文档使用 `deepseek-v4.1-flash-1017`。两者不能混作同一个供应商的请求模型 ID。

## 请求协议

项目请求地址为：

```text
{VULNSCOPE_LLM_BASE_URL}/chat/completions
```

请求使用 `Authorization: Bearer <API_KEY>`，并使用 OpenAI 兼容的 `messages`、`tools` 和 `tool_choice` 字段。思考模式通过百炼支持的 `enable_thinking: true/false` 显式控制。

### 工具调用策略（重要）

- **API 连接测试**固定使用 `enable_thinking: false` 和 `tool_choice: "required"`，并只提供 `submit_verdict` 一个工具。这样测试验证的是工具调用能力，而不是让模型自行判断是否需要工具。
- **实际 Agent 检测**在非思考模式下默认使用 `tool_choice: "required"`，确保每轮决策至少返回一个工具调用，符合 Agent 的工具驱动流程。
- **思考模式**使用 `tool_choice: "auto"`。百炼文档说明思考模式不支持 `required` 或指定函数的强制调用方式，因此模型可能自主决定不调用工具；如需更稳定的工具调用，建议选择「非思考模式」。
- 客户端同时兼容 `tool_calls` 与旧式单函数 `function_call` 响应，并统一转换为 Agent 可处理的工具调用结构。

如果显示“API 已连接，但未返回工具调用”，请确认使用了本次修复版，重启后端并强制刷新浏览器缓存；如果实际任务仍不触发工具调用，先将推理模式设为「非思考模式」后重试。

## 启动与验证

```bash
cp .env.example .env
# 编辑 .env，填入自己的百炼 API Key 和 WorkspaceId
bash scripts/start.sh
```

打开 `http://127.0.0.1:8000`，进入「模型设置」，选择模型并点击「测试真实 API 工具调用」。真实 API 测试会产生少量模型调用费用；离线单元测试不会使用真实 API Key。


## GitHub 仓库访问令牌（批量检测需要）

读取课程样本对应的提交元数据使用 GitHub REST API，下载源码 ZIP 使用 `codeload.github.com`。这与百炼 API Key 是两套独立凭据。批量检测建议在 `.env` 另行配置：

```dotenv
VULNSCOPE_GITHUB_TOKEN=你的GitHub访问令牌
VULNSCOPE_BATCH_CONCURRENCY=1
```

未认证的 GitHub REST API 请求通常只有每小时 60 次配额；认证令牌通常可获得每小时 5,000 次常规配额。令牌应只授予读取所需仓库的最小权限，保存在服务端 `.env`，不要放入浏览器、源码或日志。访问令牌不会发送到 `codeload.github.com`。

## 大型仓库源码大小限制

仓库快照采用两个独立的安全预算，避免把压缩包大小与解压后的 C/C++ 源码量混为一个限制：

```dotenv
# 解压后允许提取的 C/C++ 源码总量，默认 1024 MiB，允许 10～1024 MiB
VULNSCOPE_MAX_REPO_MB=1024

# GitHub ZIP 压缩包下载上限，默认 250 MiB，允许 10～512 MiB
VULNSCOPE_MAX_REPO_ARCHIVE_MB=250
```

如果任务事件中提示“仓库源码总量超过限制”，可先在 `.env` 中把 `VULNSCOPE_MAX_REPO_MB` 调到 `768` 或 `1024`，保存后重启服务。若提示压缩包下载超限，则调高 `VULNSCOPE_MAX_REPO_ARCHIVE_MB`。两项均有硬上限，防止大型仓库下载或解压耗尽磁盘空间；下载的 ZIP 以临时磁盘文件流式处理，不会再把整个压缩包同时保存在 Python 内存中。

仓库源码大小限制只针对允许提取的 C/C++ 源码文件，不会把 README、图片、文档等非源码文件计入源码预算。单个源码文件仍限制为 2 MiB，源码文件数量与 ZIP 条目数也有独立安全上限。
