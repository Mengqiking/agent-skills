# Agent Skills

Reusable agent skills for everyday engineering workflows. The first collection covers API onboarding, evidence-based model benchmarking, and reviewing files before external sharing.

可分别安装、逐步扩展的 Agent 工作流集合。当前包含三个 Skill，后续可以加入代码修改、排障、部署或学习复盘等流程。

## 当前技能

| Skill | 用途 | 随包能力 |
| --- | --- | --- |
| [provider-api-intake](skills/provider-api-intake/SKILL.md) | 接入核对、免费连通性、curl/Postman 交付 | 流程、事实表、评审模板 |
| [model-benchmark-report](skills/model-benchmark-report/SKILL.md) | 测试计划、TTFT/缓存/错误率、已有结果分析 | 流程、指标说明、工具无关模板；不内置请求执行器 |
| [external-share-sanitizer](skills/external-share-sanitizer/SKILL.md) | 外发文件初筛、语义审查、脱敏副本 | 只读扫描器、行为测试、审查清单 |

适合支持 `SKILL.md` 的 agent 环境；`agents/openai.yaml` 提供 Codex 展示信息和隐式调用设置。Skill 提供指引，不是权限隔离或强制执行系统，不会自行获得 API、文件系统或网络访问权限。

## 安装

需要 Python 3.10+。安装器、检查脚本和扫描器只使用标准库，不需要 API Key。Git 用于克隆，也可以下载 ZIP 后解压。

```sh
git clone https://github.com/Mengqiking/agent-skills.git
cd agent-skills
python scripts/install.py
```

Windows PowerShell、macOS 和 Linux 使用相同的 Python 命令；若只有 `python3`，将命令中的 `python` 换成 `python3`。

默认复制到 `~/.agents/skills/`。也可只安装一个或指定其他客户端的技能目录：

```sh
python scripts/install.py --skill external-share-sanitizer
python scripts/install.py --dest /path/to/agent/skills
```

安装前会检查全部目标；遇到任意同名目录或链接会停止，**不会覆盖已有 Skill**。已有版本请先自行备份并比较；安装器没有自动升级或删除功能。复制后按客户端方式刷新技能或开始新会话。安装位置参考 [OpenAI 官方说明](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills)。

也可以手动复制 `skills/` 下需要的完整文件夹到客户端支持的技能目录。

## 使用

通常直接描述需求即可；客户端需已发现相应 Skill，自动选择并非每次都能保证。需要明确指定时，在请求中加上 `$provider-api-intake`、`$model-benchmark-report` 或 `$external-share-sanitizer`。

| 你可以这样说 | 预期产物 |
| --- | --- |
| “看看这个供应商怎么接入，只做不扣费检查，帮我生成 Postman。” | 接入事实表、已执行/未执行清单、Collection 和风险说明 |
| “分析这个结果目录，看看延迟和缓存，不重新请求模型。” | 基于已有证据的报告、异常与证据缺口 |
| “测试这个模型，预算 20 元，最多 10 次请求。” | 先核对执行器、价格和请求上限，再按授权执行；缺工具或预算证据时只交付计划 |
| “这些日志要发给供应商，生成脱敏副本和删改清单。” | 新目录中的副本、初筛结果、语义审查和剩余人工检查 |

前两个 Skill 可以单独安装。没有另一个 Skill 时，会保留当前流程的边界并说明缺失能力。

性能测试 Skill 的 JSON 是**计划模板**，不是任意 benchmark CLI 可直接执行的配置。真实测试需使用用户选定、已核对的工具。本项目不打包私有测试引擎、供应商专用规范或真实测试结果。HTTP 200 和免费模型列表查询都不能证明推理可用。

## 单独使用扫描器

从仓库根目录运行，目标必须是明确文件或一个较小的待交付目录：

```sh
python skills/external-share-sanitizer/scripts/scan_sensitive.py /path/to/share-package --json
```

- 扫描器只读，不自动修改或发送文件，不打印匹配到的敏感值。
- 支持普通文本和 Office Open XML 内的文本 XML；PDF、图片、音视频、嵌入对象、数据库和未知格式需要对应工具或人工审查。
- 拒绝主目录、磁盘根目录、仓库/Vault 根目录以及符号链接或 Windows reparse point。请选择具体交付目录。
- 退出码 `0`：受支持内容无命中；`1`：有发现，可能同时不完整；`2`：无已检测发现但扫描不完整。自动化必须同时读取 `status` 和 `unscanned_count`。
- “无命中”不是安全证明。身份、业务上下文、版权和授权还需语义审查。

测试文件含明显标记为 `SYNTHETIC_*` 的人工样例，扫描这些源代码可能命中规则，这是测试素材，不应把整份测试文件加入全局忽略列表。

## 验证

以下均为离线检查，不调用模型、不产生 API 费用：

```sh
python scripts/validate.py
python -m unittest discover -s tests -v
python -m unittest discover -s skills/external-share-sanitizer/scripts -p "test_*.py" -v
```

GitHub Actions 配置覆盖 Windows、Linux、macOS 和 Python 3.10/3.12。配置矩阵不等于已经验证，实际结果以对应 commit 的 Actions 状态为准。Windows 若不允许创建符号链接，对应测试会明确跳过。

## 贡献与许可证

欢迎提交最小可复现案例、离线测试和可复用流程。新增技能放在 `skills/<skill-name>/`，完善入口、触发范围、所需资源与行为测试，再更新上方目录。请使用虚构数据与 `example.invalid` 域名，不提交凭据、客户日志或无权公开的资料。

本项目按 [MIT License](LICENSE) 发布。许可覆盖本仓库的说明和辅助代码，不授予第三方模型、服务、商标、数据或文档的权利。未捆绑第三方 Python 实现；Python 标准库和 CI 中使用的官方 Actions 不包含在发布源码内。带入第三方内容前需确认许可并保留所需声明。
