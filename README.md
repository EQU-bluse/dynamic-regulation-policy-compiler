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
- `regulation_policy_compiler.policy.policy_delta(from_at, to_at, rules)`：`from_at`、`to_at` 须为合法 UTC 秒且 `from_at<=to_at`，`rules` 校验同 `compile_rules`，任一非法抛 `ValueError` 且不改输入。分别编译两时点并以 `(source,id)` 标识入选规则，返回深副本，顶层键序 `from,to,rules,conflicts`。`rules` 仅含 `added`（仅后有）、`removed`（仅前有）、`updated`（均有但完整值不同），相同者省略，按 `source` 的 `law`、`org` 顺序及 `id` Unicode 码点升序；项键序 `source,id,kind,before,after`，`before`/`after` 为对应编译规则快照或 `null`。`conflicts` 键序 `added,removed`，以 `winner` 数组后接 `loser` 数组的六元值为身份，`added` 按后时点编译冲突原序列出仅后有项，`removed` 按前时点原序列出仅前有项；冲突项键序 `winner,loser`。无差异时 `rules=[]` 且 `conflicts` 两数组均空。
- `regulation_policy_compiler.policy.policy_schedule(start, end, rules)`：`start`、`end` 须为合法 UTC 秒且 `start<=end`，`rules` 校验同 `compile_rules`，任一非法抛 `ValueError` 且不改输入。候选时点为 `start` 及规则中落在 `(start,end]` 的 `from` 与非空 `to`，去重升序后逐点调用 `compile_rules`；首点必保留，后续计算 `policy_delta(上一保留点时间, 当前候选时间, rules)`，仅当其 `rules=[]` 且 `conflicts` 的 `added`、`removed` 均为空时丢弃，否则保留。返回深副本，顶层键序 `start,end,points`；点键序 `at,rules,conflicts,delta`，`rules`、`conflicts` 取该时点 `compile_rules` 同名值并保持逐层契约；首点 `delta=null`，后续点 `delta` 为上述 `policy_delta` 的完整结果。
- `POST /rules/schedule`：请求体为恰含 `start,end,rules` 的 JSON 对象；解析失败、非对象、键集错误或 `ValueError` 响应 422 `{"detail":"invalid request"}`，成功返回 UTF-8 紧凑 JSON（非 ASCII 不转义、无末尾换行），不读写历史。
- `POST /explanations`：请求体为恰含 `at,facts,rules` 的 JSON 对象（校验同 `evaluate`）；成功返回顶层键 `at,decision,trace,basis,conflicts`，其中 `basis` 为胜出规则的深副本（无匹配时为 `null`），`conflicts` 仅保留编译结果中涉及该胜出规则的项并保持原顺序。非法请求响应 422 `{"detail":"invalid request"}`，不读写历史。
- `regulation_policy_compiler.policy.decision_timeline(start, end, facts, rules)`：`start`、`end` 须为合法 UTC 秒且 `start<=end`，`facts`、`rules` 校验同 `explain`，任一非法抛 `ValueError` 且不改输入。候选时点为 `start` 及规则中落在 `(start,end]` 的 `from` 与非空 `to`，去重升序后逐点调用 `explain`；首点保留，后续仅保留相对上一保留点有变化的点。返回深副本，顶层键序 `start,end,points`；点键序 `at,decision,trace,basis,conflicts,changes`，前五项取对应 `explain` 值，首点 `changes=[]`，后续按 `decision,trace,basis,conflicts` 顺序列出变化字段。
- `POST /decision-timeline`：请求体为恰含 `start,end,facts,rules` 的 JSON 对象；解析失败、非对象、键集错误或 `ValueError` 响应 422 `{"detail":"invalid request"}`，成功返回 UTF-8 紧凑 JSON（非 ASCII 不转义、无末尾换行），不读写历史。
- `regulation_policy_compiler.policy.decision_impact(from_at, to_at, cases, rules)`：`from_at`、`to_at` 须为合法 UTC 秒且 `from_at<=to_at`，`rules` 校验同 `compile_rules`；`cases` 为列表，项恰含 `id,facts`，`id` 为非空且在列表内唯一的字符串，`facts` 校验同 `explain`，空 `cases` 合法；任一非法抛 `ValueError` 且不改输入。返回深副本，顶层键序 `from,to,policy,cases`；`policy` 为 `policy_delta` 完整结果；`cases` 按 `id` Unicode 码点升序，项键序 `id,changes,before,after`，`before`/`after` 为两时点 `explain` 完整结果，`changes` 按 `decision,trace,basis,conflicts` 顺序列出两快照间不同的字段（无差异为空）。
- `POST /decision-impact`：请求体为恰含 `from,to,cases,rules` 的 JSON 对象；解析失败、非对象、键集错误或 `ValueError` 响应 422 `{"detail":"invalid request"}`，成功返回 UTF-8 紧凑 JSON（非 ASCII 不转义、无末尾换行），不读写历史。
- `regulation_policy_compiler.history.DecisionHistory(path)`：把决策记录持久化到 UTF-8 紧凑 JSON 文件（仅含按 `(id, at)` 升序的 `records` 数组，原子写入）。`record(record_id, at, facts, rules)` 复用 `evaluate` 的校验、选版与排序，存并返回含 `id, at, decision, trace, basis` 的记录；`replay(record_id, at)` 返回该 id 在不晚于 `at` 的最近一条记录副本，无则 `KeyError`；`evolution(record_id, start, end)` 只读已存快照，返回同 id 且 `at` 落在闭区间 `[start,end]` 内并按 `at` 升序的记录（无则 `KeyError`），不重算、不写盘、不改状态；`record_id` 须为非空字符串，`start`、`end` 须为合法 UTC 秒且 `start<=end`，否则 `ValueError`。返回深副本，键序 `id,start,end,entries`；entries 项键序 `at,decision,trace,basis,changes`，前四项沿用记录契约，`changes` 按 `decision,trace,basis` 顺序列出相对紧邻前项不同的字段（首项为 `[]`）。`audit(record_id, start, end)` 的参数校验、闭区间选择、`at` 升序、深副本、只读语义及 `ValueError`/`KeyError` 行为同 `evolution`；返回深副本键序 `id,start,end,root,entries`，entries 项键序 `at,decision,trace,basis,previous,digest`，前四项沿用记录契约。令 C 为当前项仅含 `at,decision,trace,basis` 且按此键序序列化的 UTF-8 紧凑 JSON 字节（非 ASCII 不转义、无末尾换行）；首项 `previous` 为 64 个 ASCII 字符 `0`，后项取前项 `digest`；`digest` 为 `previous` 的 ASCII 字节紧接 C 所得 SHA-256 小写十六进制，`root` 取末项 `digest`。各历史方法返回及落盘的 `basis` 键序统一为 `id,ver,source,priority,from,to,when,result`，非空 `when` 键按 Unicode 码点升序；读取旧文件不会改写其内容。
- `GET /decisions/{record_id}/evolution?start=...&end=...`：查询参数须恰含一次 `start` 和一次 `end` 且无其他参数；先校验路径与查询再检查历史。成功按方法契约返回 UTF-8 紧凑 JSON（非 ASCII 不转义、无末尾换行）；非法路径/查询或时间逆序响应 422 `{"detail":"invalid request"}`；区间内无记录响应 404 `{"detail":"record not found"}`；历史未配置或读写失败响应 503 `{"detail":"history unavailable"}`。
- `GET /decisions/{record_id}/audit?start=...&end=...`：查询约束、校验顺序、成功 JSON 口径及 422/404/503 状态与 `detail` 体均同 `/decisions/{record_id}/evolution`，成功返回 `audit` 方法契约的哈希链审计结果。
- `regulation_policy_compiler.history.verify_audit(report, expected)`：纯函数校验审计报告，不访问历史或文件、不改输入。`report` 恰含 `id,start,end,root,entries`，`id` 为非空字符串，`start`/`end` 为合法 UTC 秒且 `start<=end`，`entries` 为非空数组且项 `at` 严格递增并落在闭区间内；项恰含 `at,decision,trace,basis,previous,digest`，前四项沿用 audit 契约，`root`/`previous`/`digest` 为 64 位小写十六进制字符串。`expected` 恰含 `id,start,end,root` 并同法校验；上述非法均抛 `ValueError`，对应字段不同返回 `False`。规范化 `basis` 及 `when` 键序后按 `audit` 定义的 `C`、UTF-8、SHA-256 逐项重算：首项 `previous` 为 64 个 `0`，后项等于前项 `digest`；链、`digest` 或 `root` 校验失败返回 `False`，否则返回 `True`。
- `POST /audits/verify`：请求体为恰含 `report,expected` 的 JSON 对象；解析失败、非对象、键集错误或 `ValueError` 响应 422 `{"detail":"invalid request"}`，成功返回 `{"valid":bool}` 的 UTF-8 紧凑 JSON（非 ASCII 不转义、无末尾换行）。
