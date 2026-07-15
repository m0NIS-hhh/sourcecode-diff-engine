# Source Diff Skill 改进计划

本文记录将当前 Source Diff Engine 整理为完整源码 diff skill 的改进计划。当前项目已经具备可运行 CLI、目录分析、skill wrapper、结构化输出和测试套件；后续目标是提升工程结构、输出协议稳定性、审计可靠性和 skill 发布质量。

## 目标定位

项目应定位为源码变更审计辅助 skill，用于分析 old/new 文件或目录差异，生成安全修复、新增漏洞风险和新增攻击面的结构化复核队列。

需要明确边界：

- 该工具不自动证明漏洞可利用。
- 高风险结果应被视为人工复核线索。
- `risk_score` 是排序分，不是 CVSS，也不是漏洞确认分。
- `evidence_status=inferred` 或 `review_required=true` 的结果必须明确提醒复核。
- 不应把单独 sink、入口上下文或关键字命中直接报告为已确认漏洞。

## 建议目录结构

建议把项目拆成三层：

- `engine`：源码 diff 分析库和 CLI。
- `sourcecode-diff-skill`：skill 说明、包装脚本和输出协议。
- `tests/docs/fixtures`：测试、样例、文档和评估集。

推荐结构：

```text
sourcecodediff/
  README.md
  pyproject.toml
  requirements.txt
  uv.lock
  config.json.example
  .gitignore

  src/
    source_diff_engine/
      __init__.py
      main.py
      app_service.py
      config_loader.py
      logger_config.py

      analysis/
        __init__.py
        pipeline.py
        profiles.py
        tools.py
        domains/
          __init__.py
          generic.py
          security.py
          behavior.py
          attack_surface.py

      pipeline/
        __init__.py
        results.py
        fix_assessment.py
        new_vuln.py
        attack_surface.py

      preprocess/
        __init__.py
        source_preprocessor.py

      directory/
        __init__.py
        runner.py
        manifest.py
        outputs.py
        quality.py
        review.py
        runtime.py

      output/
        __init__.py
        schema.py
        writer.py

      llm/
        __init__.py
        client.py
        prompt_builder.py
        prompts.yaml

  sourcecode-diff-skill/
    SKILL.md
    README.md
    scripts/
      run_skill_diff.py
      verify_run_consistency.py
      run_high_risk_review_pass.py
      check_llm_connectivity.py
    examples/
      single_file.md
      directory.md
      security_review.md
      api_surface.md

  tests/
    fixtures/
      python/
      java/
      php/
      regression/
      false_positive/
      false_negative/
    test_*.py

  docs/
    architecture.md
    output_schema.md
    analysis_profiles.md
    reliability_model.md
    packaging_skill.md
    known_limitations.md
    source_diff_skill_improvement_plan.md

  artifacts/
    .gitkeep
```

当前根目录中的 `analysis_*.py`、`pipeline_*.py`、`directory_*.py`、`output_*.py`、`llm_client.py`、`preprocessor.py` 等模块应逐步收进 `src/source_diff_engine/`。`SKILL.md` 和 skill 专用脚本应移入 `sourcecode-diff-skill/`，让库代码和 skill 包边界清晰。

## 阶段一：工程目录整理

优先级：最高。

任务：

1. 创建 `src/source_diff_engine/` 包结构。
2. 移动核心模块：
   - `main.py` -> `src/source_diff_engine/main.py`
   - `analysis_pipeline.py` -> `src/source_diff_engine/analysis/pipeline.py`
   - `analysis_profiles.py` -> `src/source_diff_engine/analysis/profiles.py`
   - `analysis_tools.py` -> `src/source_diff_engine/analysis/tools.py`
   - `analysis_domain_*.py` -> `src/source_diff_engine/analysis/domains/`
   - `pipeline_*.py` -> `src/source_diff_engine/pipeline/`
   - `preprocessor.py` -> `src/source_diff_engine/preprocess/source_preprocessor.py`
   - `directory_*.py` -> `src/source_diff_engine/directory/`
   - `output_*.py` -> `src/source_diff_engine/output/`
   - `llm_client.py`、`prompt_builder.py`、`prompts.yaml` -> `src/source_diff_engine/llm/`
3. 更新所有 import。
4. 更新 `pyproject.toml` 的 entrypoints：

   ```toml
   [project.scripts]
   source-diff-engine = "source_diff_engine.main:main"
   source-diff-skill-run = "sourcecode-diff-skill.scripts.run_skill_diff:main"
   ```

5. 将 `test_projects/` 改为 `tests/fixtures/`，更新测试引用。
6. 保留根目录只放项目元数据、README、配置样例和顶层目录。

验收标准：

- `pytest -q` 全部通过。
- `python -m source_diff_engine.main smoke --config config.json.example --llm-mode off` 可运行。
- 安装后 `source-diff-engine smoke ...` 可运行。
- `source-diff-skill-run ...` 可生成 `summary.json`。

## 阶段二：Skill 包产品化

优先级：最高。

任务：

1. 将当前 `SKILL.md` 移入 `sourcecode-diff-skill/SKILL.md` 并重写为严格操作手册。
2. 明确输入：
   - 单文件：`old_file` 和 `new_file`。
   - 目录：`old_root` 和 `new_root`。
   - `language=auto|python|java|php`。
   - `profile=generic|security|security-strict|api-surface|behavior-review`。
   - `llm_mode=off|try|required`。
3. 固定 skill 标准工作流：
   - 必要时运行 `doctor`。
   - 使用 wrapper 执行分析。
   - 执行输出一致性校验。
   - 优先读取 `summary.json`。
   - 需要证据时读取 `summary.md`、`high_risk_index.json`、`detailed.json`。
4. 增加强制报告规则：
   - 不把 `inferred` 报告成 confirmed。
   - 高风险项必须说明 source/sink/guard 是否完整。
   - `review_required=true` 必须写入用户总结。
   - 必须报告 skipped files 和 failed pairs。
5. 增加 `sourcecode-diff-skill/README.md`，说明安装、调用和输出读取方式。

验收标准：

- LLM 根据 `SKILL.md` 能独立完成单文件和目录 diff。
- wrapper 输出中 `summary.json` 字段稳定。
- skill 文档包含误用边界和禁止事项。

## 阶段三：输出协议稳定化

优先级：高。

`summary.json` 应作为 LLM 主入口，保持小而稳定。建议稳定字段：

```json
{
  "ok": true,
  "schema_version": "3.0",
  "mode": "single_file",
  "analysis_profile": "security",
  "analysis_quality": "valid",
  "llm_enabled": false,
  "total_files_analyzed": 1,
  "total_units": 1,
  "failed_file_count": 0,
  "skipped_file_count": 0,
  "high_risk_unit_count": 1,
  "quality_issues": [],
  "top_findings": [
    {
      "rel_path": "src/a.py",
      "artifact": "src/a.py:10",
      "risk_score": 8.2,
      "vulnerability_type": "SSRF风险",
      "change_type": "新增代码",
      "evidence_status": "observed",
      "review_required": true
    }
  ],
  "artifact_paths": {}
}
```

任务：

1. 文档化 `analysis_quality` 枚举：
   - `valid`
   - `invalid`
   - `no_changes`
   - `unknown`
2. 文档化 `evidence_status` 枚举：
   - `observed`
   - `inferred`
   - `partial`
   - `not_applicable`
   - `missing`
3. 明确 `risk_score` 是审计排序分。
4. 明确 `summary.md` 面向人工阅读，`detailed.json` 面向深度证据追溯。
5. 增加 schema 兼容测试，避免破坏 `summary.json` 稳定字段。

验收标准：

- `scripts/verify_run_consistency.py` 能验证 run 级和 pair 级计数一致。
- `tests/test_skill_wrapper.py` 覆盖关键字段。
- `docs/output_schema.md` 描述稳定字段和枚举。

## 阶段四：可靠性增强

优先级：高。

当前静态分析主要依赖关键字、简单 taint、source/sink/guard 信号和符号上下文加权。后续需要重点降低误报和漏报。

降低误报：

- 识别 `subprocess.run([...], shell=False)` 并降低命令注入风险。
- 识别 SQL 参数化查询并降低 SQL 注入风险。
- 识别路径 `resolve/normalize/startswith(base)` 等防护链。
- 区分真正 sanitization 和普通字符串处理。
- 对 `@Validated`、Spring Validator、权限注解做专门识别。
- guard 不仅收集，还要判断是否覆盖 source 到 sink。

降低漏报：

- 增加同文件 helper 调用追踪。
- 增加跨 hunk 上下文。
- 识别 Flask、FastAPI、Django、Spring MVC、JAX-RS、PHP controller/router 入口。
- 识别配置文件新增路由、权限和功能开关。
- 扩展 sink：
  - SSRF
  - 任意文件读写
  - 文件上传
  - 模板注入
  - 反序列化
  - LDAP/XPath/NoSQL injection
  - 反射和动态加载

证据质量分级：

- `observed_complete_chain`：明确 source、sink、guard 或缺失 guard。
- `observed_partial_chain`：source/sink/guard 不完整。
- `inferred_chain`：基于模式推断。
- `sink_only`：只有 sink，不应升高为漏洞。
- `context_only`：只有入口上下文，不应升高为漏洞。

验收标准：

- 新增 false positive 回归样例。
- 新增 false negative 回归样例。
- 高风险项必须包含明确 source/sink 证据或明确 manual review reason。

## 阶段五：评估集建设

优先级：高。

建议建立真实回归样例结构：

```text
tests/fixtures/regression/
  python/
    cmdi_positive/
    cmdi_false_positive_shell_false/
    sqli_param_query_safe/
    path_traversal_fixed/
  java/
    spring_ssrf_positive/
    spring_auth_guarded_safe/
    file_upload_traversal/
  php/
    cmdi_positive/
    sqli_escaped/
```

每个 case：

```text
case_name/
  old/
  new/
  expected.json
  README.md
```

`expected.json` 示例：

```json
{
  "profile": "security",
  "expected_high_risk_min": 1,
  "expected_vulnerability_types": ["SSRF风险"],
  "must_review": true,
  "expected_evidence_status": "observed"
}
```

验收标准：

- 有覆盖 Python、Java、PHP 的正例和反例。
- CI 中运行回归评估。
- 输出变化需要显式更新 expected。

## 阶段六：LLM 模式治理

优先级：中高。

原则：静态优先，LLM 只做复核和补充，不覆盖证据事实。

任务：

1. 保留 `off/try/required`：
   - `off`：完全静态。
   - `try`：可用则复核，不可用则降级。
   - `required`：LLM 不可用则失败。
2. 在输出中记录：
   - model
   - base_url
   - api_style
   - request_count
   - preflight 状态
   - fallback reason
3. LLM 输出继续强制 schema normalize。
4. 高风险 LLM review pass 默认关闭，避免大目录运行成本失控。
5. LLM 结果只增加候选或复核意见，不应删除静态证据。

验收标准：

- `llm_mode=off` 下所有测试可通过。
- `llm_mode=try` 在无 key 或网络失败时可静态降级。
- `llm_mode=required` 在不可用时明确失败。

## 阶段七：文档和编码清理

优先级：中。

当前部分中文文档在终端输出中存在乱码风险，需要统一编码和职责。

任务：

1. 确认所有 `.md/.txt/.yaml/.py` 使用 UTF-8。
2. 将 `核心逻辑.txt` 合并进 `docs/architecture.md`。
3. 将 `项目说明文档.md` 合并进 `README.md` 或 `docs/architecture.md`。
4. README 保持面向快速使用：
   - 快速开始
   - 单文件分析
   - 目录分析
   - Profile 说明
   - LLM 配置
   - 输出说明
   - 限制与误用风险
5. 新增 `docs/known_limitations.md`，明确工具不能当自动漏洞证明器。

验收标准：

- 文档在 PowerShell 和常见编辑器中不乱码。
- README 与 `SKILL.md` 不重复过多。
- 用户能从 README 完成首次运行。

## 阶段八：发布清理和质量门禁

优先级：中。

`.gitignore` 应覆盖：

```gitignore
artifacts/
outputs/
logs/
__pycache__/
.pytest_cache/
.venv/
.env
config.json
*.log
*.tmp
```

发布前必须排除：

- `artifacts/`
- `outputs/`
- 本地 `config.json`
- LLM token
- 临时测试输出
- 大型二进制或反编译产物
- 本地缓存

建议新增脚本：

```text
scripts/package_skill.py
scripts/check_release_clean.py
```

检查内容：

- `sourcecode-diff-skill/SKILL.md` 存在。
- `config.json` 不存在或未被纳入发布包。
- `config.json.example` 存在。
- 没有 artifacts 和本地输出。
- `pytest -q` 通过。
- `doctor --llm-mode off` 通过。
- wrapper smoke 通过。

验收标准：

- 可以生成干净 skill 发布包。
- 发布包只包含必要代码、说明、脚本、配置样例和 fixtures。

## 推荐实施顺序

1. 整理目录结构和 import，保持测试全绿。
2. 固化 `summary.json` schema。
3. 重写 `sourcecode-diff-skill/SKILL.md` 和 README。
4. 建立真实 regression fixtures。
5. 增强静态规则的误报控制。
6. 增加跨文件、框架入口和配置入口能力。
7. 做 skill 发布脚本和 release clean 检查。

## 当前已验证基线

在当前项目状态下已验证：

```powershell
pytest -q
python main.py smoke --config config.json.example --llm-mode off --output-root artifacts\assessment --run-id smoke_assessment_eval
python scripts\run_skill_diff.py --data-folder tests\fixtures\basic --old-file old.py --new-file new.py --language auto --profile security --llm-mode off --output-root artifacts\skill_eval --run-id wrapper_eval
python main.py doctor --config config.json.example --llm-mode off --output-root artifacts\doctor_eval
```

结果：

- 测试：`128 passed`。
- smoke：通过。
- wrapper：通过，并生成 `summary.json`。
- doctor：通过。

后续每个阶段完成后都应重新运行以上基线命令。
