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
- `regulation_policy_compiler.policy.compile_rules(at, rules)`：复用 `evaluate` 的校验、`[from,to)` 生效选取、每 `(source,id)` 取最高 `ver` 与排序，返回深副本 `{"at","rules","conflicts"}`；`conflicts` 按排序下标 `i<j` 列出结果不同且 `when` 条件可同时成立的规则对（前项为 winner）。
- `POST /rules/compile`：请求体为恰含 `at,rules` 的 JSON 对象；非法请求响应 422 `{"detail":"invalid request"}`，成功返回 UTF-8 紧凑 JSON（非 ASCII 不转义、无末尾换行）。
- `POST /explanations`：请求体为恰含 `at,facts,rules` 的 JSON 对象，校验与 `evaluate` 相同；非法请求响应 422 `{"detail":"invalid request"}`。成功时对同一输入调用 `evaluate` 与 `compile_rules`，返回依次含 `at,decision,trace,basis,conflicts` 的 UTF-8 紧凑 JSON（非 ASCII 不转义、无末尾换行）；`basis` 为胜出规则的深副本（无匹配为 `null`），`conflicts` 仅保留涉及胜出规则的冲突项。该接口不读写历史。
- `regulation_policy_compiler.history.DecisionHistory(path)`：把决策记录持久化到 UTF-8 紧凑 JSON 文件（仅含按 `(id, at)` 升序的 `records` 数组，原子写入）。`record(record_id, at, facts, rules)` 复用 `evaluate` 的校验、选版与排序，存并返回含 `id, at, decision, trace, basis` 的记录；`replay(record_id, at)` 返回该 id 在不晚于 `at` 的最近一条记录副本，无则 `KeyError`。
