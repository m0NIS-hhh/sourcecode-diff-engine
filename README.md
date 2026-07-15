# Source Diff Engine

Source Diff Engine 是一个源代码 diff 分析工具。它面向审计辅助场景：给定 old/new 文件或目录，提取变更单元，评估变更影响、安全风险、新增攻击面，并输出需要人工复核的高风险队列。

默认策略是静态分析优先，LLM 只作为可选复核能力。工具不会自动证明漏洞成立，输出结果应作为人工审计线索。

## 核心分析逻辑

分析流程分为三部分：

1. 判断修改是否为漏洞修复。
   如果变更是内存泄露、后台 bug、性能调优等与安全无关的内容，不深入做安全链路分析，评分为 0-2 分。  
   如果变更表现为安全漏洞修复，例如增加过滤、限制输入长度、增加认证条件、删除危险函数或危险代码，则进入安全复核，评分为 5-10 分，并给出完整的 source -> guard -> sink 条件链。

2. 判断新增代码是否引入新漏洞。
   对新增代码中的 source、sink、guard、条件链进行识别，输出潜在漏洞类型、风险分数、证据和人工复核建议。

3. 判断新增代码是否带来新增攻击面。
   先识别新增对象，例如文件、函数、接口、命令处理器、配置入口或业务功能，再评估是否形成新的可达入口、权限边界变化或潜在漏洞面。

## 安装

```powershell
pip install -r requirements.txt
```

或安装为命令行工具：

```powershell
pip install .
```

安装后可使用 `source-diff-engine`。未安装时也可以直接运行 `python main.py`。

固定测试样例位于 `tests/fixtures/basic`。根目录下的 `test_projects` 仅作为旧命令兼容样例保留，不再作为测试 fixture 主入口。

## LLM 配置

密钥按优先级从以下环境变量读取：

```powershell
$env:LLM_API_KEY = "your-token"
# or
$env:OPENAI_API_KEY = "your-token"
# or
$env:ANTHROPIC_AUTH_TOKEN = "your-token"
```

其他参数如 `base_url`、`model`、`api_style` 可在 `config.json` 中配置。发布和测试时应使用 `config.json.example`，不要提交本地真实配置。

LLM 模式：

- `off`: 完全静态分析。
- `try`: 尝试 LLM 预检，失败则回退静态分析。
- `required`: LLM 预检失败即报错。

## 命令

Skill 包装入口会自动生成或使用 run id、执行分析、执行输出一致性校验，并写出适合 Codex 读取的 `codex_summary.json`：

```bash
python scripts/run_skill_diff.py --data-folder tests/fixtures/basic --old-file old.py --new-file new.py --language auto --profile security --llm-mode off
python scripts/run_skill_diff.py --data-folder . --old-root old_src --new-root new_src --language auto --profile security --llm-mode try
```

安装 console entrypoint 后也可以使用：

```bash
source-diff-skill-run --data-folder tests/fixtures/basic --old-file old.py --new-file new.py --language auto --profile security --llm-mode off
```

单文件分析：

```bash
python main.py run tests/fixtures/basic --old_file old.py --new_file new.py --language auto
python main.py run tests/fixtures/basic --old_file old.java --new_file new.java --language java
python main.py run tests/fixtures/basic --old_file old.php --new_file new.php --language php
```

目录分析：

```bash
python main.py run . --old_root old_src --new_root new_src --language auto
python main.py run . --old_root old_src --new_root new_src --language auto --output-root artifacts/outputs --run-id demo_run
```

目录模式默认只收集 `.py`、`.java`、`.php`，并跳过 `.git`、`node_modules`、`target`、`build`、`dist`、`.venv`、`vendor`、`__pycache__` 等目录，以及二进制文件、常见生成文件和超过 1 MiB 的文件。可通过以下参数调整：

```bash
python main.py run . --old_root old_src --new_root new_src --include-ext .py --include-ext .java --exclude-dir vendor --exclude-glob "*.generated.java" --max-file-size-bytes 2097152
```

环境诊断：

```bash
python main.py doctor --config config.json.example --llm-mode off
```

离线 smoke：

```bash
python main.py smoke --config config.json.example --llm-mode off
```

## 输出

每次运行写入 `<output-root>/<run-id>/`。常见顶层产物：

- `meta.json`
- `summary.json`
- `summary.md`
- `results.json`
- `detailed.json`
- `overview.json`
- `init_overview.json`
- `failed_pairs.json`
- `high_risk_index.json`
- `codex_summary.json`，仅由 `scripts/run_skill_diff.py` 包装入口生成

逐文件产物位于 `pairs/<relative-path>/`，包括 `summary.json`、`results.json`、`units.json` 和 `diff.patch`。

目录模式的 `overview.json`、`init_overview.json` 和 `detailed.json` 会记录 `skipped_files`、`skipped_file_count`、`skipped_by_reason`，用于区分扩展名未包含、排除目录、排除 glob、大文件、二进制文件等 skip reason。

`summary.md` 面向人工快速浏览，会汇总分析质量、文件和单元数量、高风险单元、解码/读取问题、跳过文件原因，以及高风险复核队列规模。

当前输出契约使用 `schema_version = 3.0`。稳定字段包括 `primary_conclusion`、`analysis_axes`、`change_intent`、`behavioral_impact`、`interface_impact`、`security_impact`、`attack_surface_impact` 和 `evidence`。

## 验证

运行测试：

```bash
pytest -q
```

验证一次 smoke 输出的一致性：

```bash
python main.py smoke --config config.json.example --llm-mode off --output-root artifacts/assessment --run-id smoke_assessment
python scripts/verify_run_consistency.py artifacts/assessment/smoke_assessment
```

## Profile 与默认 LLM 策略

- `generic` / `api-surface` / `behavior-review` 默认 `llm_mode=off`
- `security` 默认 `llm_mode=try`
- `security-strict` 默认 `llm_mode=required`
- 显式传入 `--llm-mode` 时优先级最高，会覆盖 profile 默认值。
