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
- `regulation_policy_compiler.policy.evaluate(at, facts, rules)`：对版本化规则做确定性求值，返回 `(decision, trace)`。
- `regulation_policy_compiler.history.DecisionHistory(path)`：把决策记录持久化到 UTF-8 紧凑 JSON 文件（仅含按 `(id, at)` 升序的 `records` 数组，原子写入）。`record(record_id, at, facts, rules)` 复用 `evaluate` 的校验、选版与排序，存并返回含 `id, at, decision, trace, basis` 的记录；`replay(record_id, at)` 返回该 id 在不晚于 `at` 的最近一条记录副本，无则 `KeyError`。

## 当前限制

规则编译、冲突处理与决策解释的 HTTP 接口尚未实现。
