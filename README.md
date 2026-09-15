# Source Diff Engine

Source Diff Engine 是一个独立的源码 diff 审计系统。它接收 old/new 文件或目录，提取可追踪的变更单元，分析行为影响、安全风险和攻击面变化，并输出稳定的 JSON/Markdown 结果供人工复核或后续自动化使用。

系统支持 Python、Java 和 PHP。静态分析始终是基础能力；LLM 只作为可选后端，不能覆盖或删除静态证据。结果是审计线索，不等同于漏洞确认或 CVSS 评分。

## 运行入口

项目根目录中的 `main.py` 是日常使用入口。通常不需要重复填写 `--config`，默认配置为
`configs/config.example.json`：

```powershell
python main.py doctor --llm-mode off
python main.py smoke --llm-mode off
python main.py run tests/fixtures/basic --old_file old.py --new_file new.py --llm-mode off
```

目录 diff 示例：

```powershell
python main.py run . `
  --old_root old_src --new_root new_src --language auto `
  --workers 4 --retry-failed-files 1 --llm-mode off
```

`python -m source_diff_engine.main ...` 是内部和自动化入口，适合测试包结构、从其他目录调用，
或在已经配置 `PYTHONPATH` / 已安装包的环境中使用：

```powershell
python -m source_diff_engine.main doctor --llm-mode off
```

`source-diff-engine` console entrypoint 可以保留作为便利入口，但不是项目的主要使用方式。

## 配置

配置样例位于 `configs/config.example.json`。不提供 `--config` 时，CLI 和服务层默认使用该文件。真实配置可复制到本地路径，但不要提交 `config.json`、令牌或其他密钥。

LLM 密钥只从显式配置或以下环境变量读取：

```powershell
$env:LLM_API_KEY = "your-token"
# 或 OPENAI_API_KEY / ANTHROPIC_AUTH_TOKEN
```

LLM 模式：

- `off`：完全离线静态分析。
- `try`：尝试调用 LLM，失败时保留静态结果并回退。
- `required`：LLM 预检或调用失败时返回错误。

分析 profile 包括 `generic`、`security`、`security-strict`、`api-surface` 和 `behavior-review`。显式 `--llm-mode` 会覆盖 profile 的默认模式。

## 运行

单文件 diff：

```powershell
python main.py run tests/fixtures/basic `
  --old_file old.py --new_file new.py --language auto --llm-mode off
```

目录模式支持扩展名、目录和 glob 过滤，文件大小限制，并提供 checkpoint、resume、失败重试、并发执行和质量门禁。高风险 review pass 需要显式启用，不会自动运行。

环境检查和离线 smoke：

```powershell
python main.py doctor --llm-mode off
python main.py smoke --llm-mode off --output-root .tmp/smoke --run-id current
```

## 输出

每次运行写入 `<output-root>/<run-id>/`。稳定的顶层结果包括：

- `summary.json`、`summary.md`
- `overview.json`、`detailed.json`
- `high_risk_index.json`
- `failed_pairs.json`
- `meta.json`

目录运行还会记录跳过文件、失败文件、分析质量、checkpoint 和高风险复核队列。逐文件结果位于 `pairs/` 下。输出协议当前为 schema 3.0，核心字段包含 `primary_conclusion`、`analysis_axes`、`change_intent`、`behavioral_impact`、`interface_impact`、`security_impact`、`attack_surface_impact` 和 `evidence`。

校验已有运行结果：

```powershell
python scripts/verify_run_consistency.py .tmp/smoke/current
```

## 开发与限制

运行测试：

```powershell
pytest -q
python -m compileall src tests scripts
```

当前静态分析重点是 source、guard、sink 和条件链证据。`observed`、`inferred`、`partial`、`missing` 等证据状态应结合上下文理解；单独命中 sink 不代表确认漏洞。跨函数、跨文件和 AST 级分析仍是后续增强方向。
