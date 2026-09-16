# warden-action

[English](README.md)

`warden-action` 通过[源蜥安全分析平台](https://cybersec.antgroup.com/)执行仓库安全与开源许可证检查，同时提供 GitHub Action 和 Node.js 命令行工具。

## 功能范围

源蜥提供开放式安全基础设施，其 YASA 分析引擎基于 UAST、数据流、指针和污点分析实现统一多语言程序分析。

本项目接入当前已公开的源蜥仓库 API，提供以下能力：

- 获取组件漏洞及依赖链路；
- 展示源蜥返回的可达性与修复信息；
- 检查组件许可证风险和项目许可证冲突；
- 根据可配置策略决定 CI 是否失败；
- 支持 Pull Request、push 和本地 Git 仓库使用场景。

扫描目标必须是公开的 GitHub 或 Gitee 仓库。本工具将仓库地址和分支提交给源蜥，不上传本地文件，也不执行仓库代码。

## GitHub Action

在**源蜥 > 团队管理 > 访问令牌**中创建令牌，并保存为 GitHub 仓库 Secret `YUANXI_TOKEN`。

### Pull Request

对于 `pull_request` 和 `pull_request_target` 事件，Action 从 `pull_request.head` 获取 PR 来源仓库和来源分支，不会扫描目标分支或 GitHub 临时生成的 merge ref。

同一仓库分支创建的 PR 使用 `pull_request`：

```yaml
name: Warden

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: oss-infra/warden-action@main
        with:
          token: ${{ secrets.YUANXI_TOKEN }}
          scan_type: all
          fail_on_severity: high
          fail_on_license_conflict: true
```

GitHub 不会向 fork 发起的 `pull_request` 工作流提供仓库 Secrets。如需扫描公开 fork 的 PR，应使用 `pull_request_target`：

```yaml
name: Warden

on:
  pull_request_target:
    types: [opened, synchronize, reopened]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: oss-infra/warden-action@main
        with:
          token: ${{ secrets.YUANXI_TOKEN }}
          scan_type: all
```

> [!WARNING]
> 本 Action 不会 checkout 或执行 PR 代码。使用 `pull_request_target` 时，不要在同一个 job 中增加执行不可信 PR 代码的步骤。

### Push

对于 push 事件，Action 自动扫描事件仓库和实际推送分支：

```yaml
on:
  push:
    branches: [main]
```

### 输入参数

| 参数                       | 必填 | 默认值                          | 说明                                                     |
| -------------------------- | ---- | ------------------------------- | -------------------------------------------------------- |
| `token`                    | 是   |                                 | 源蜥访问令牌                                             |
| `scan_type`                | 否   | `all`                           | `security`、`licenses` 或 `all`；兼容 `stc`、`sca`       |
| `repository`               | 否   | 事件仓库                        | 公开 Git 仓库地址                                        |
| `branch`                   | 否   | 事件分支                        | 待扫描分支                                               |
| `project_name`             | 否   | 自动生成                        | 稳定的源蜥项目名，长度 1-30 个字符                       |
| `fail_on_severity`         | 否   | `high`                          | `warning`、`low`、`medium`、`high`、`critical` 或 `none` |
| `fail_on_license_conflict` | 否   | `true`                          | 发现项目与组件许可证冲突时失败                           |
| `fail_on_license_risk`     | 否   | `false`                         | 发现风险组件许可证时失败                                 |
| `timeout_seconds`          | 否   | `1200`                          | 扫描超时时间                                             |
| `poll_interval_seconds`    | 否   | `10`                            | 状态查询间隔                                             |
| `api_base_url`             | 否   | `https://cybersec.antgroup.com` | 源蜥 API 地址                                            |
| `debug`                    | 否   | `false`                         | 输出脱敏请求及完整响应内容                               |

GitHub/Gitee HTTPS 地址会自动转换为源蜥要求的 `.git` 形式。显式传入 `repository`、`branch` 和 `project_name` 可覆盖事件解析结果。

### 输出参数

| 参数                | 说明                 |
| ------------------- | -------------------- |
| `result`            | `PASSED` 或 `FAILED` |
| `status`            | 源蜥最终扫描状态     |
| `project_id`        | 源蜥项目 ID          |
| `scan_id`           | 源蜥扫描任务 ID      |
| `share_link`        | 源蜥返回的报告链接   |
| `vulnerabilities`   | 漏洞数量             |
| `license_risks`     | 风险组件许可证数量   |
| `license_conflicts` | 项目许可证冲突数量   |
| `json`              | 结构化 JSON 扫描报告 |

策略不通过或运行异常都会使 Action step 失败。

`json` 输出包含带版本号的 `target`、`scan`、`result`、`summary` 和 `details` 字段。为扫描步骤设置 `id` 后，可在后续 webhook 步骤中通过 `${{ steps.warden.outputs.json }}` 获取报告。项目内置的 `.github/workflows/warden.yml` 会在推送时扫描本项目，也支持手动指定公开仓库地址和分支；运行前请配置仓库 Secret `YUANXI_TOKEN`。

## 命令行工具

需要 Node.js 24 或更高版本，并且当前 Git 仓库应配置公开的 GitHub/Gitee 远程地址。

```bash
pnpm install
cp .env.example .env
# 在 .env 中设置 YUANXI_TOKEN。
pnpm warden --scan-type all --fail-on-severity high
```

CLI 自动加载 `.env`，支持 `YUANXI_TOKEN` 或 `WARDEN_TOKEN`。默认从当前 Git 仓库读取远程地址和分支。

```bash
pnpm warden \
  --repository https://github.com/example/project.git \
  --branch main \
  --scan-type security \
  --json
```

退出码：

- `0`：策略通过；
- `1`：策略未通过；
- `2`：配置、网络、API、扫描失败或超时错误。

执行 `pnpm warden --help` 查看全部参数。

## 默认策略

默认情况下，高危和严重漏洞以及任意项目许可证冲突会导致扫描失败。风险组件许可证只报告，不会导致失败；可通过 `fail_on_license_risk` 开启拦截。

## 开发

```bash
git clone git@github.com:oss-infra/warden-action.git
cd warden-action
pnpm install
pnpm typecheck
pnpm test
pnpm build
```

源码与测试均使用严格模式 TypeScript。`dist/index.js` 是 GitHub Action 的打包入口，`dist/cli/index.js` 是 CLI 的打包入口。修改 `src/` 后必须重新构建两者。

当前示例使用 `@main`，首次推送后即可运行。发布 `v1` 标签后，建议使用方固定到 `oss-infra/warden-action@v1`。

## 参考资料

- [源蜥安全分析平台](https://cybersec.antgroup.com/)
- [YASA Engine](https://github.com/antgroup/YASA-Engine)

当前源蜥 API 要求通过查询参数传递令牌。GitHub 会屏蔽配置的令牌，请勿在 CI 中启用 HTTP 请求跟踪。
