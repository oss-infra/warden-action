"use strict";

function parseBoolean(value, name) {
  if (typeof value === "boolean") return value;
  if (value === undefined || value === "") return false;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${name} must be true or false`);
}

function parsePositiveNumber(value, name, defaultValue) {
  const number =
    value === undefined || value === "" ? defaultValue : Number(value);
  if (!Number.isFinite(number) || number <= 0)
    throw new Error(`${name} must be a positive number`);
  return number;
}

function buildConfig(values) {
  if (!values.token) throw new Error("token is required");
  if (!values.repository) throw new Error("repository is required");
  if (!values.branch) throw new Error("branch is required");
  return {
    token: values.token,
    baseUrl: values.baseUrl || "https://cybersec.antgroup.com",
    repository: values.repository,
    branch: values.branch,
    projectName: values.projectName || "",
    scanType: values.scanType || "all",
    failOnSeverity: values.failOnSeverity || "high",
    failOnLicenseConflict:
      values.failOnLicenseConflict === undefined
        ? true
        : parseBoolean(
            values.failOnLicenseConflict,
            "fail-on-license-conflict",
          ),
    failOnLicenseRisk: parseBoolean(
      values.failOnLicenseRisk,
      "fail-on-license-risk",
    ),
    timeoutMs:
      parsePositiveNumber(values.timeoutSeconds, "timeout-seconds", 1200) *
      1000,
    pollIntervalMs:
      parsePositiveNumber(
        values.pollIntervalSeconds,
        "poll-interval-seconds",
        10,
      ) * 1000,
  };
}

module.exports = { buildConfig, parseBoolean, parsePositiveNumber };
