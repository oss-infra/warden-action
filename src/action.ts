import { buildConfig, parseBoolean } from "./config";
import {
  licenseConflictMessage,
  licenseRiskMessage,
  resultLabel,
  structuredReport,
  summary,
  vulnerabilityMessage,
} from "./format";
import { resolveGitHubTarget, type GitHubTarget } from "./github-context";
import { severityScore } from "./policy";
import { run } from "./run";

// GitHub shows only a limited number of annotations per step.
const MAX_ANNOTATIONS = 20;

export async function main(): Promise<void> {
  const core = await import("@actions/core");
  const github = await import("@actions/github");
  try {
    const repositoryInput = core.getInput("repository");
    const branchInput = core.getInput("branch");
    // Explicit inputs make the action usable on events without a branch (tags, schedule).
    const defaults: Partial<GitHubTarget> =
      repositoryInput && branchInput
        ? {}
        : resolveGitHubTarget({
            eventName: github.context.eventName,
            ref: github.context.ref,
            serverUrl: github.context.serverUrl,
            payload: github.context.payload,
            ...(process.env.GITHUB_REPOSITORY
              ? { repositoryName: process.env.GITHUB_REPOSITORY }
              : {}),
          });
    const enforcePolicy = parseBoolean(
      core.getInput("enforce_policy"),
      "enforce-policy",
      true,
    );
    const config = buildConfig({
      token: core.getInput("token", { required: true }),
      scanType: core.getInput("scan_type"),
      repository: repositoryInput || defaults.repository,
      branch: branchInput || defaults.branch,
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
    const { results, policy } = await run(config, {
      onStatus: (status) => core.info(`Scan status: ${status}`),
      onDebug: (message) => core.info(`[debug] ${message}`),
    });

    const annotate = (message: string, blocking: boolean) =>
      enforcePolicy && blocking ? core.error(message) : core.warning(message);
    const blocking = new Set(policy.blockingVulnerabilities);
    const bySeverity = [...results.vulnerabilities].sort(
      (a, b) => severityScore(b) - severityScore(a),
    );
    for (const item of bySeverity.slice(0, MAX_ANNOTATIONS))
      annotate(vulnerabilityMessage(item), blocking.has(item));
    for (const item of policy.licenseRisks.slice(0, MAX_ANNOTATIONS))
      annotate(licenseRiskMessage(item), config.failOnLicenseRisk);
    for (const item of policy.licenseConflicts.slice(0, MAX_ANNOTATIONS))
      annotate(licenseConflictMessage(item), config.failOnLicenseConflict);

    core.setOutput("result", resultLabel(policy));
    core.setOutput("status", results.status);
    core.setOutput("project_id", results.projectId);
    core.setOutput("scan_id", results.scanId);
    core.setOutput("share_link", results.shareLink);
    core.setOutput("vulnerabilities", results.vulnerabilities.length);
    core.setOutput("license_risks", policy.licenseRisks.length);
    core.setOutput("license_conflicts", policy.licenseConflicts.length);
    core.setOutput(
      "json",
      JSON.stringify(structuredReport(config, results, policy)),
    );
    await core.summary.addCodeBlock(summary(results, policy)).write();
    if (enforcePolicy && policy.failed)
      core.setFailed("Warden policy check failed");
  } catch (error) {
    core.setOutput("result", "FAILED");
    core.setFailed(error instanceof Error ? error.message : String(error));
  }
}

void main();
