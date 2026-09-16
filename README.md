# warden-action

[简体中文](README_CN.md)

`warden-action` runs repository security and open-source license checks through the [Yuanxi security analysis platform](https://cybersec.antgroup.com/). It is available as both a GitHub Action and a Node.js CLI.

## What It Does

Yuanxi provides open security infrastructure backed by program analysis technology. Its YASA engine describes unified multi-language analysis using UAST, data-flow, pointer, and taint analysis.

This project integrates the currently documented Yuanxi repository APIs and provides:

- vulnerability and dependency-path results;
- reachability and remediation information returned by Yuanxi;
- component license risks and project license conflicts;
- configurable CI failure policies;
- pull request, push, and local Git checkout workflows.

The scanner accepts public GitHub or Gitee repository URLs. It submits a repository and branch to Yuanxi; it does not upload local files or execute repository code.

## GitHub Action

Create an access token in **Yuanxi > Team management > Access tokens**, then save it as the GitHub repository secret `YUANXI_TOKEN`.

### Pull Requests

For `pull_request` and `pull_request_target`, the Action scans the source repository and source branch from `pull_request.head`. It does not scan the base branch or GitHub's temporary merge ref.

Use `pull_request` for branches in the same repository:

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

GitHub does not expose repository secrets to fork-based `pull_request` workflows. To scan public fork pull requests, use `pull_request_target`:

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
> This Action does not check out or execute pull request code. When using `pull_request_target`, do not add steps that execute untrusted pull request code in the same job.

### Pushes

For a push event, the Action scans the event repository and pushed branch:

```yaml
on:
  push:
    branches: [main]
```

### Inputs

| Input                      | Required | Default                         | Description                                               |
| -------------------------- | -------- | ------------------------------- | --------------------------------------------------------- |
| `token`                    | yes      |                                 | Yuanxi access token                                       |
| `scan_type`                | no       | `all`                           | `security`, `licenses`, or `all`; aliases: `stc`, `sca`   |
| `repository`               | no       | event repository                | Public Git repository URL                                 |
| `branch`                   | no       | event branch                    | Branch to scan                                            |
| `project_name`             | no       | generated                       | Stable Yuanxi project name, 1-30 characters               |
| `fail_on_severity`         | no       | `high`                          | `warning`, `low`, `medium`, `high`, `critical`, or `none` |
| `fail_on_license_conflict` | no       | `true`                          | Fail on project/component license conflicts               |
| `fail_on_license_risk`     | no       | `false`                         | Fail on components marked as license risks                |
| `timeout_seconds`          | no       | `1200`                          | Scan timeout                                              |
| `poll_interval_seconds`    | no       | `10`                            | Status polling interval                                   |
| `api_base_url`             | no       | `https://cybersec.antgroup.com` | Yuanxi API origin                                         |
| `debug`                    | no       | `false`                         | Log redacted requests and complete response payloads      |

GitHub and Gitee HTTPS URLs are normalized to the `.git` form expected by Yuanxi. Explicit `repository`, `branch`, and `project_name` inputs override event-derived values.

### Outputs

| Output              | Description                    |
| ------------------- | ------------------------------ |
| `result`            | `PASSED` or `FAILED`           |
| `status`            | Final Yuanxi scan status       |
| `project_id`        | Yuanxi project ID              |
| `scan_id`           | Yuanxi scan task ID            |
| `share_link`        | Report link returned by Yuanxi |
| `vulnerabilities`   | Vulnerability count            |
| `license_risks`     | Risky component-license count  |
| `license_conflicts` | Project license-conflict count |
| `json`              | Structured JSON report         |

Policy violations and operational errors fail the Action step.

The `json` output contains versioned `target`, `scan`, `result`, `summary`, and `details` fields. Give the scan step an `id` and pass `${{ steps.warden.outputs.json }}` to a later webhook step. The included `.github/workflows/warden.yml` scans this project on pushes and supports manually overriding the public repository URL and branch; configure the `YUANXI_TOKEN` repository secret before running it.

## CLI

Node.js 20 or later and a Git checkout with a public GitHub/Gitee remote are required.

```bash
pnpm install
cp .env.example .env
# Set YUANXI_TOKEN in .env.
pnpm warden --scan-type all --fail-on-severity high
```

The CLI loads `.env` and accepts `YUANXI_TOKEN` or `WARDEN_TOKEN`. By default it reads the repository URL and branch from the current Git checkout.

```bash
pnpm warden \
  --repository https://github.com/example/project.git \
  --branch main \
  --scan-type security \
  --json
```

Exit codes:

- `0`: policy passed;
- `1`: policy failed;
- `2`: configuration, network, API, scan, or timeout error.

Run `pnpm warden --help` for all options.

## Policy Defaults

By default, `high` and `critical` vulnerabilities and any project license conflict fail the scan. Component license-risk flags are reported but do not fail unless `fail_on_license_risk` is enabled.

## Development

```bash
git clone git@github.com:oss-infra/warden-action.git
cd warden-action
pnpm install
pnpm test
pnpm build
```

`dist/index.js` is the bundled GitHub Action entry point and must be rebuilt after changes under `src/`.

The examples use `@main` so they work after the initial push. After publishing the `v1` tag, consumers should pin the Action to `oss-infra/warden-action@v1`.

## References

- [Yuanxi security analysis platform](https://cybersec.antgroup.com/)
- [YASA Engine](https://github.com/antgroup/YASA-Engine)

The token is transmitted as an API query parameter because the current Yuanxi API requires it. GitHub masks the configured token in Action logs; avoid enabling HTTP request tracing in CI.
