"use strict";

const SEVERITY = {
  警告: 1,
  warning: 1,
  低危: 2,
  low: 2,
  中危: 3,
  medium: 3,
  高危: 4,
  high: 4,
  严重: 5,
  critical: 5,
  none: Number.POSITIVE_INFINITY,
};

function normalizeThreshold(value = "high") {
  const key = String(value).trim().toLowerCase();
  if (!(key in SEVERITY)) {
    throw new Error(`Invalid fail-on severity: ${value}`);
  }
  return key;
}

function evaluatePolicy(results, options = {}) {
  const threshold = normalizeThreshold(options.failOnSeverity);
  const thresholdValue = SEVERITY[threshold];
  const blockingVulnerabilities = results.vulnerabilities.filter(
    (item) => (SEVERITY[item.rank] || 0) >= thresholdValue,
  );
  const licenseRisks = results.licenses.filter(
    (item) => item.isRisk === true || item.isRisk === "true",
  );
  const licenseConflicts = results.licenseConflicts;
  const failed =
    blockingVulnerabilities.length > 0 ||
    (options.failOnLicenseRisk && licenseRisks.length > 0) ||
    (options.failOnLicenseConflict && licenseConflicts.length > 0);

  return { failed, blockingVulnerabilities, licenseRisks, licenseConflicts };
}

module.exports = { evaluatePolicy, normalizeThreshold };
