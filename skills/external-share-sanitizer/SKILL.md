---
name: external-share-sanitizer
description: Review and sanitize explicitly scoped files before sharing them with providers, customers, the public, or an open-source audience. Use for credential, source/provider, user-identity, request-ID, path, metadata, and minimal-reproduction leakage checks; do not use as a generic code-security audit or as proof that a file is safe.
metadata:
  short-description: Sanitize files before external sharing
---

# 外发资料脱敏

生成独立的脱敏副本、变更清单和有证据边界的就绪结论。保留原件，不把“扫描无匹配”表述成已经证明安全。

## 边界

- 必须明确输入文件或范围较小的待交付目录。不得默认扫描整个 Vault、仓库、用户主目录、文件系统根目录或无关附件集合。
- 原件一律只读。只写入用户指定的新位置或命名明确的同级副本，不静默覆盖原文件。
- 默认不在评论、报告、变更清单或命令中重复检测到的凭据、Cookie、Authorization、签名 URL 或用户提供的额外比对字符串。
- 如果用户在当前会话已经提供真实值，并明确要求生成可直接执行的命令，可在适用环境规则允许时按其要求处理；不得把真实值写入报告、变更清单、将被 Git 跟踪的文件或提交历史。没有这一明确要求时使用环境变量或独立比对文件。
- 自动扫描只是初筛，不是脱敏证明。退出码 0 只表示受支持内容没有命中当前规则。
- 默认不发送、上传或发布。若用户当前请求已经明确授权相应外部动作，应先完成脱敏、复扫和人工语义审查，再把已确认的脱敏副本交给相应发送/上传/发布步骤；本 Skill 不把已获授权的后续步骤永久禁止。
- 如工作区有 `AGENTS.md`，沿用其中适用的授权、凭据和 Git 规则；没有该文件也可按本 Skill 的边界运行，不默认获得外发或修改权限。

## 工作流

1. **明确披露对象。** 记录接收方、用途、精确文件范围，以及为了复现问题必须保留的事实。
2. **盘点格式但不扩大范围。** 区分可扫描的文本、Office Open XML 与 PDF、图片、媒体、压缩包、数据库、未知格式。
3. **执行确定性初筛。** 只对明确文件或小型待交付目录运行 `scripts/scan_sensitive.py`。额外比对字符串优先通过环境变量或独立文件传入，并把该文件放在交付包之外。只有确认进程参数可以承载该值时才使用 `--extra-string`。
4. **人工检查语义泄露。** 阅读 [references/review-checklist.md](references/review-checklist.md)，判断供应商、客户/用户、资源标识、业务背景、错误指纹、文件名、文档属性及证据是否超过最小必要范围。
5. **创建脱敏副本。** 在保留诊断价值的前提下移除或一致替换非必要标识。布局或内嵌媒体重要时，使用对应的文档、表格、演示文稿、PDF 或视觉工作流；普通文本写入新文件。
6. **生成变更清单。** 记录相对位置、类别、动作、原因、保留证据、未决不确定性与不支持内容，绝不写入被移除的真实值。
7. **复扫与复审。** 只扫描脱敏后的待交付物。存在不支持或跳过内容时，结果仍为不完整，必须走对应格式的人工审查。
8. **给出有限结论。** 使用 `needs changes`、`ready for human review` 或 `blocked`。不能仅因脚本无发现就标记为安全。
9. **按授权交接后续动作。** 没有明确外发授权时停在人工审阅；已有明确授权时，把经过确认的脱敏副本交给相应外部操作步骤，并保持原有接收方和范围不变。

## 扫描器

使用明确目标运行：

```text
python <skill-directory>/scripts/scan_sensitive.py <explicit-file-or-small-directory>
```

常用参数：

```text
--json
--extra-string <user-provided-comparison-string>
--extra-strings-file <one-string-per-line-file>
--extra-string-env <environment-variable-name>
--max-files <count>
--max-bytes-per-file <bytes>
--max-total-bytes <bytes>
```

退出码：

- `0`：完整扫描的受支持内容未命中规则；不代表获准外发。
- `1`：检测到一个或多个发现；不打印匹配值。若状态为 `FINDINGS_AND_INCOMPLETE`，同时还存在未扫描内容。
- `2`：没有已检测发现，但因不支持格式、链接、访问错误、无效包或范围限制而扫描不完整。

自动化调用方必须读取 `status` 和 `unscanned_count`，不能只根据退出码判断覆盖是否完整。

扫描器读取普通文本，以及 `.docx`、`.xlsx`、`.pptx` 包内的 XML。它不能可靠检查 PDF 页面、图片、音视频、Office 内嵌二进制、数据库、任意压缩包或未知格式。此类内容必须转入对应格式的 Skill/工作流，并在验证前列为未审查项。

## 必须交付

- 新路径下的脱敏副本。
- 不含敏感值的变更清单。
- 扫描结果与精确范围。
- 语义审查发现，以及必要时的责任/归因不确定性。
- 不支持或尚未审查的内容。
- 最终有限结论与剩余人工检查。
