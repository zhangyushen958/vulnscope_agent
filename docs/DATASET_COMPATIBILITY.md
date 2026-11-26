# 课程数据集兼容审查与验证记录

## 审查基线

本环境只实际获取到 `VulnScope_Agent_完整项目源码.zip` (V1) 和课程上传的 `dataset.zip`；先前会话中提到的 V2 ZIP 未挂载。因此本版本由已验证 V1 源码重构数据输入接口，并重新实现阿里云百炼 DeepSeek 模型配置和任务隔离，**不能声称它与先前 V2 完全相同**。

## 数据审查（已实际读取，不是预测）

| 数据 | 记录数 | 特征 |
|---|---:|---|
| `dataset/knowledge.jsonl` | 7,578 | 每两条拟配一对，`target=1,0`，`cwe` 为数组，部分 `file_name='None'` |
| `dataset/test.jsonl` | 300 | 150 对，`idx,commit_url,target,func` |
| `dataset/evaluation.py` | 官方脚本 | **按相邻记录配对**，按 idx 匹配结果，允许部分预测 |
| `dataset/result（示例）.jsonl` | 2 | `idx`、`prediction` 两个整数字段 |

历史数据的 3,789 个相邻拟配对中：
- 3,772 对通过 `target`、`commit_id`、`commit_url`、`cve` 一致性校验。
- 17 对提交标识或 CVE 不一致，**不进入 RAG**，原始起始行号见 `runtime/historical_cases.audit.json`。
- 剩余 3,772 对中有 3 个完全重复的函数对，去重后 **3,769 个知识库条目**。
- 源函数中有超过 20,000 字符的条目。RAG 的索引文档采用每端前 4,000 字符截断保证索引速度；持久化案例展示保留每端最多 20,000 字符。这是资源/上下文限制，非完整代码级训练。

测试集还存在两个相邻样本 commit URL 不一致的位置（第 126、134 对）。**检测仍逐样本独立执行**；评分完全按照官方相邻配对，不按 URL 重新分组。测试集中有一条 `git.qemu.org` 历史 URL，在源码仓库工具中只为此特定别名、固定项目、固定 SHA 形式提供 GitHub 镜像映射，不开放其他主机。

## 课程红线

- 历史库只有 `knowledge.jsonl`，绝不包含 `test.jsonl` 记录。
- `target` 只供选择对应版本（1：父提交，0：修复提交）。LLM 输入中没有 target、commit URL、git diff 或另一测试函数。
- Agent 要求单样本独立调用，并按需访问单版本快照；不提供任意网页或 CVE 搜索。
- 课程测试集只作为输入与离线评测依据，**不能把 target 作为预测标签复制成 result.jsonl**。

## 操作步骤

安装依赖并设置 `.env` 的阿里云百炼 API Key 和 WorkspaceId后：

```bash
python scripts/import_course_zip.py /path/to/dataset.zip --validate-only
python scripts/import_course_zip.py /path/to/dataset.zip
bash scripts/start.sh
```

也可从 Web 的「领域知识库」上传 **原始 `dataset.zip`**，系统只读取其中的历史 `knowledge.jsonl`；再于「批量任务」上传相同 ZIP，系统只读取 `test.jsonl` 并提交 300 个独立检测任务。需先配置支持工具调用的真实阿里云百炼 API Key；无密钥时绝不会伪造结果。

生成 `result.jsonl` 后，**优先使用课程原始 evaluator**：

```bash
python /path/to/dataset/evaluation.py --dataset /path/to/dataset/test.jsonl --result result.jsonl
```

本项目另附 `scripts/evaluate_course.py`，与官方脚本的相邻配对与部分结果逻辑一致。旧 `scripts/evaluate_pairs.py` 为旧数据格式保留，**不应用于这次课程数据的最终评分**。

## 本地验证说明

完整知识库使用原始上传数据已实际构建，约 6 秒（当前测试机器条件），得到 3,769 条去重案例；完成 300 条测试输入验证。`scripts/evaluate_course.py` 的 P-C/P-V/P-B/P-R 分类结果与压缩包内官方 `evaluation.py` 用**人工构造的格式校验预测文件**对照一致，这**不是漏洞检测成绩**。真实阿里云百炼 API 调用及真实 300 条模型检测尚未执行。
