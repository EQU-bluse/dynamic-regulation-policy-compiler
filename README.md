# Dynamic Regulation Policy Compiler

把版本化法规和机构规则编译为确定性的后端决策策略，面向需要可追溯决策的服务端系统。

## 环境与启动

需要 Python 3.12+。

```bash
python -m pip install -e ".[dev]"
uvicorn regulation_policy_compiler.app:app --host 0.0.0.0 --port 8000
pytest
```

## 公开接口

- `GET /health`：返回 `{"status":"ok"}`，用于进程健康检查。
- `regulation_policy_compiler.policy.evaluate(at, facts, rules)`：在 UTC 秒时间 `at` 按事实 `facts` 评估版本化规则，返回 `(decision, trace)`；无匹配时为 `(None, [])`。
- `regulation_policy_compiler.history.DecisionHistory(path)`：把决策记录持久化到 UTF-8 紧凑 JSON 文件（缺则创建），记录按 `(id, at)` 排序、原子写入。
  - `record(record_id, at, facts, rules)`：校验、选版与排序规则同 `evaluate`，存盘并返回记录；无匹配时 `decision=null, trace=[], basis=null`，否则 `basis` 为胜出规则的有序快照。
  - `replay(record_id, at)`：返回 `id` 相同且 `at <= 入参 at` 的最近一条记录副本（不重算），无则抛出 `KeyError`。

## 当前限制

规则编译的冲突解释接口与 HTTP 决策接口尚未实现；法规版本、规则评估、历史持久化与回放已可用。
