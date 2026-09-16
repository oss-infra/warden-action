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

module.exports = { summary, vulnerabilityMessage };
