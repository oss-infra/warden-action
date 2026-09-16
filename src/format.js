"use strict";

function vulnerabilityMessage(item) {
  const proof = item.vulDependenceProofs?.[0];
  const details = [
    item.subject || item.cveNo || `Vulnerability ${item.id}`,
    `severity=${item.rank || "unknown"}`,
  ];
  if (proof?.vulComponent)
    details.push(
      `component=${proof.vulComponent}@${proof.vulCurrentVersion || "?"}`,
    );
  if (proof?.vulFixVersion) details.push(`fix=${proof.vulFixVersion}`);
  return details.join(" | ");
}

function summary(results, policy) {
  return [
    `Result: ${policy.failed ? "FAILED" : "PASSED"}`,
    `Vulnerabilities: ${results.vulnerabilities.length} (${policy.blockingVulnerabilities.length} blocking)`,
    `License risks: ${policy.licenseRisks.length}`,
    `License conflicts: ${policy.licenseConflicts.length}`,
    results.shareLink ? `Report: ${results.shareLink}` : null,
  ]
    .filter(Boolean)
    .join("\n");
}

function structuredReport(config, results, policy) {
  return {
    schemaVersion: "1.0",
    target: {
      repository: config.repository,
      branch: config.branch,
      scanType: config.scanType,
    },
    scan: {
      status: results.status,
      projectName: results.projectName,
      projectId: results.projectId,
      scanId: results.scanId,
      shareLink: results.shareLink,
    },
    result: policy.failed ? "FAILED" : "PASSED",
    summary: {
      vulnerabilities: results.vulnerabilities.length,
      blockingVulnerabilities: policy.blockingVulnerabilities.length,
      licenseRisks: policy.licenseRisks.length,
      licenseConflicts: policy.licenseConflicts.length,
    },
    details: {
      vulnerabilities: results.vulnerabilities,
      blockingVulnerabilities: policy.blockingVulnerabilities,
      licenseRisks: policy.licenseRisks,
      licenseConflicts: policy.licenseConflicts,
    },
  };
}

module.exports = { structuredReport, summary, vulnerabilityMessage };
