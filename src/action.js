"use strict";

const { buildConfig } = require("./config");
const { structuredReport, summary, vulnerabilityMessage } = require("./format");
const { resolveGitHubTarget } = require("./github-context");
const { run } = require("./run");

function githubDefaults(context) {
  return resolveGitHubTarget(context);
}

async function main() {
  const core = await import("@actions/core");
  const github = await import("@actions/github");
  try {
    const defaults = githubDefaults(github.context);
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
    });
    core.setSecret(config.token);
    core.info(
      `Starting ${config.scanType} scan for ${config.repository}#${config.branch}`,
    );
    const outcome = await run(config, {
      onStatus: (status) => core.info(`Scan status: ${status}`),
    });

    for (const item of outcome.results.vulnerabilities.slice(0, 20)) {
      const message = vulnerabilityMessage(item);
      if (outcome.policy.blockingVulnerabilities.includes(item))
        core.error(message);
      else core.warning(message);
    }
    for (const item of outcome.policy.licenseConflicts.slice(0, 20)) {
      core.warning(
        `License conflict: ${item.projectLicense || "?"} / ${item.sbomLicense || "?"}${item.explanation ? ` | ${item.explanation}` : ""}`,
      );
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

main();

module.exports = { githubDefaults, main };
