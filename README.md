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

## 当前限制

初始基线只包含可运行的服务骨架和健康检查；法规版本、规则编译、冲突处理、历史回放与决策解释接口尚未实现。
