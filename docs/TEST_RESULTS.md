# Local verification

- 68 automated pytest cases passed.
- `app/` statement coverage 88%, locally measured with pytest-cov.
- Frontend JavaScript passed `node --check`.
- Python sources passed `compileall`, shell startup syntax passed `bash -n`.
- The supplied 300 test entries passed Pydantic input validation and strict commit URL parsing.
- The supplied 7,578 knowledge records were indexed into 3,769 distinct cases in local dry-run.
- Course evaluator statistics were compared to the exact `evaluation.py` script included in `dataset.zip` with a synthetic result solely to verify classification consistency; those statistics are **not** model evaluation outcomes.
- 阿里云百炼模型网络调用未执行 and no real predictions were generated; to assess model accuracy 真实百炼 API Key、正确的 WorkspaceId 和可联网运行环境 are required.
