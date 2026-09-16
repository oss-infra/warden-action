import { buildConfig } from "./config";
import {
  licenseRiskMessage,
  structuredReport,
  summary,
  vulnerabilityMessage,
} from "./format";
import { resolveGitHubTarget, type GitHubContext } from "./github-context";
import { run } from "./run";

export function githubDefaults(context: GitHubContext) {
  return resolveGitHubTarget(context);
}

export async function main(): Promise<void> {
  const core = await import("@actions/core");
  const github = await import("@actions/github");
  try {
    const defaults = githubDefaults(github.context as GitHubContext);
    const config = buildConfig({
      token: core.getInput("token", { required: true }),
      scanType: core.getInput("scan_type"),
      repository: core.getInput("repository") || defaults.repository,
      branch: core.getInput("branch") || defaults.branch,
      projectName: core.getInput("project_name"),
      failOnSeverity: core.getInput("fail_on_severity"),
      failOnLicenseConflict: core.getInput("fail_on_license_conflict"),
      failOnLicenseRisk: core.getInput("fail_on_license_risk"),
      timeoutSeconds: core.getInput("timeout_seconds"),
      pollIntervalSeconds: core.getInput("poll_interval_seconds"),
      baseUrl: core.getInput("api_base_url"),
      debug: core.getInput("debug"),
    });
    core.setSecret(config.token);
    core.info(
      `Starting ${config.scanType} scan for ${config.repository}#${config.branch}`,
    );
    const outcome = await run(config, {
      onStatus: (status) => core.info(`Scan status: ${status}`),
      onDebug: (message) => core.info(`[debug] ${message}`),
    });

    for (const item of outcome.results.vulnerabilities.slice(0, 20)) {
      const message = vulnerabilityMessage(item);
      if (outcome.policy.blockingVulnerabilities.includes(item))
        core.error(message);
      else core.warning(message);
    }
    for (const item of outcome.policy.licenseRisks.slice(0, 20)) {
      const message = licenseRiskMessage(item);
      if (config.failOnLicenseRisk) core.error(message);
      else core.warning(message);
    }
    for (const item of outcome.policy.licenseConflicts.slice(0, 20)) {
      const message = `License conflict: ${item.projectLicense || "?"} / ${item.sbomLicense || "?"}${item.explanation ? ` | ${item.explanation}` : ""}`;
      if (config.failOnLicenseConflict) core.error(message);
      else core.warning(message);
    }

    core.setOutput("result", outcome.policy.failed ? "FAILED" : "PASSED");
    core.setOutput("status", outcome.results.status);
    core.setOutput("project_id", outcome.results.projectId);
    core.setOutput("scan_id", outcome.results.scanId);
    core.setOutput("share_link", outcome.results.shareLink);
    core.setOutput("vulnerabilities", outcome.results.vulnerabilities.length);
    core.setOutput("license_risks", outcome.policy.licenseRisks.length);
    core.setOutput("license_conflicts", outcome.policy.licenseConflicts.length);
    core.setOutput(
      "json",
      JSON.stringify(structuredReport(config, outcome.results, outcome.policy)),
    );
    await core.summary
      .addCodeBlock(summary(outcome.results, outcome.policy))
      .write();
    if (outcome.policy.failed) core.setFailed("Warden policy check failed");
  } catch (error) {
    core.setOutput("result", "FAILED");
    core.setFailed(error instanceof Error ? error.message : String(error));
  }
}

void main();
