---
name: model-benchmark-report
description: 规划 LLM API 性能测试、指导已安装测试工具执行或离线分析结果，生成证据化报告。适用于 benchmark、正式/复测、TTFT、延迟、错误率、缓存专项；不内置模型请求执行器，不用于仅检查免费连通性。
---

# Model Benchmark Report

让测试矩阵、费用授权、指标口径、原始证据和最终结论保持一致。本 Skill 提供流程、指标口径和模板，不包含请求执行器。计划与已有结果分析可独立进行；真实测试必须先找到并核对用户选用的测试工具。

## 授权边界

- **计划与离线模式**：检查工具、编写配置、生成命令、分析已有结果。只有在文档或代码已证实不会访问网络时，才执行工具的预检、重分析或报告命令；命令名为 `dry-run` 本身不是无网络证据。
- **免费连通模式**：不以 `smoke` 或最小生成请求代替免费检查。只执行已证明不计费、不创建资源的只读操作；如果已安装 `provider-api-intake`，可使用它完成接入核对。
- **正式实测模式**：任何 `run`、Chat/Messages/Responses、视频输入或并发测试都会产生真实请求，只有用户在当前任务中明确要求实际执行且预算/范围清楚时才运行。仅提供 Key 不等于授权消耗。

生成命令、测试配置或 Postman 不需要人为阻断开关；是否执行由当前任务授权决定。

## 工作流

1. 用 [assets/benchmark-plan-template.md](assets/benchmark-plan-template.md) 固化测试对象、协议、模型、输入、流式、并发、样本、预算和停止阈值。
2. 对模型能力、价格、usage/cache 字段和协议语义读取当前官方资料；未知项保持未知。
3. 读取 [references/benchmark-toolkit.md](references/benchmark-toolkit.md)，核对用户选定工具的来源、版本、参数、离线模式和预算控制。没有可用工具时完成计划或离线分析，明确尚不能执行真实测试。不要修改业务项目来适配一次测试。
4. provider 配置只保存环境变量名，不保存 Key。用户本会话提供了 Key 且要求可直接执行命令时，在命令中按其要求原样填入；不要把真实值写入 Git 跟踪文件或最终报告。
5. 实际运行前先完成无网络的配置解析，记录预计请求数与最坏预算，包括预热、失败和重试。不能建立可执行的费用/请求停止边界时，不开始正式测试。`smoke` 仍是真实推理，不属于免费连通。
6. 正式执行时先最小样本，再扩大矩阵；达到费用、错误率、时间或连续失败阈值立即停止。
7. 保存 manifest、已脱敏 raw、normalized 与 report；异常值需要复测或明确标为未确认，不得删除不利样本。
8. 按 [references/metrics-and-evidence.md](references/metrics-and-evidence.md) 解释 TTFT、分位数、双错误率和缓存语义。缓存字段语义未知时输出 N/A，不猜百分比。
9. 用 [assets/benchmark-report-template.md](assets/benchmark-report-template.md) 形成报告，区分实测事实、推断、未测试和证据不足。

## 可复用资产

- [assets/provider-config-template.json](assets/provider-config-template.json)：无密钥的工具无关接入信息示例，必须映射到实际工具 schema。
- [assets/profile-template.json](assets/profile-template.json)：工具无关测试计划示例，预算和执行授权默认为未确认，不能直接传入任意 CLI。
- [assets/benchmark-plan-template.md](assets/benchmark-plan-template.md)：执行前计划与授权记录。
- [assets/benchmark-report-template.md](assets/benchmark-report-template.md)：最终证据化报告。

## 停止条件

- 没有当前任务的实际付费测试授权，或预算/最大请求数不明确。
- 模型、协议、目标环境或 provider 配置不能唯一确定。
- 真实 Key 将进入 Git 跟踪文件、日志或对外报告。
- 连续鉴权/协议失败，错误率超过计划阈值，或实际请求数偏离计划。
- usage/cache 字段缺失或语义未知，却要求输出精确缓存命中率。
- 只有成功状态，没有流式事件、用量或原始证据支撑指标。

停止后仍可离线分析已有结果、修正配置、生成命令和列出恢复条件；不要把“工具测试通过”写成“供应商性能通过”。
