# 任务提交数据集快照与成对评分

## 问题

此前批量任务评分会在任务结束后重新读取 `dataset/test.jsonl`，并将当前文件摘要与任务提交时的摘要比较。对于通过网页上传的子集（例如 `demo.jsonl`），当前本地 `dataset/test.jsonl` 往往仍是完整的 300 条测试集，因此两者不同，评分接口会错误地拒绝该任务。

## 当前行为

- 所有 `mode=batch` 任务在开始执行前，都会将经过 `DetectionInput` 规范化的提交样本原样顺序保存到 `result/<job_id>/submitted_dataset.jsonl`。
- 同时将快照内容的 SHA-256 摘要保存在 SQLite 的 `runtime_settings` 中。
- 任务评分只读取该任务自己的 `submitted_dataset.jsonl`，并重新计算摘要；摘要不一致、文件缺失/损坏或样本缺少 `target=0/1` 标签时拒绝评分。
- 不再将上传的 `demo.jsonl` 与无关的 `dataset/test.jsonl` 比较，也不会在评分时重新组织或重新配对样本。
- 配对顺序严格沿用任务提交时 JSONL 的行顺序；每两个相邻样本必须包含一个 `target=1` 和一个 `target=0`，符合课程评测脚本规则。
- `target` 只用于任务级版本路由和任务完成后的评分，不会被加入模型提示词。

## 使用 demo.jsonl

在网页选择批量任务并上传 `demo.jsonl`。任务完成后进入评分页面即可评分；不需要把 60 条记录覆盖到 `dataset/test.jsonl`。

输出目录会多出：

```text
result/<job_id>/
├── submitted_dataset.jsonl  # 本次实际提交的数据集快照
├── reports.json
├── result.jsonl             # 任务全部成功时生成
├── events.jsonl
└── score.json
```

`submitted_dataset.jsonl` 是评分依据。若该文件被手动修改，摘要校验会拒绝评分，防止错配或篡改。

## 旧任务兼容

在此版本之前创建、且没有 `submitted_dataset.jsonl` 的批量任务，仍尝试使用旧的本地测试集摘要校验。旧版上传子集任务如果无法证明提交内容，评分会拒绝；请重新上传 `demo.jsonl` 运行。新版本创建的批量任务不受此限制。

本版本随包附带 `dataset/demo.jsonl`（从正式 `test.jsonl` 按原始相邻配对抽取的 30 对、60 条记录），可直接在网页批量上传中选择该文件进行小规模验证。
