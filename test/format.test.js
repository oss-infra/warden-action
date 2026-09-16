"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { structuredReport } = require("../src/format");

test("builds a stable structured report for downstream integrations", () => {
  const vulnerability = { id: 1, rank: "高危" };
  const licenseRisk = { name: "example", isRisk: "true" };
  const conflict = { projectLicense: "MIT", sbomLicense: "GPL-3.0" };
  const report = structuredReport(
    {
      repository: "https://github.com/acme/project.git",
      branch: "release",
      scanType: "all",
    },
    {
      status: "扫描完成",
      projectName: "project-release",
      projectId: "project-1",
      scanId: "scan-1",
      shareLink: "https://example.test/report",
      vulnerabilities: [vulnerability],
    },
    {
      failed: true,
      blockingVulnerabilities: [vulnerability],
      licenseRisks: [licenseRisk],
      licenseConflicts: [conflict],
    },
  );

  assert.deepEqual(report, {
    schemaVersion: "1.0",
    target: {
      repository: "https://github.com/acme/project.git",
      branch: "release",
      scanType: "all",
    },
    scan: {
      status: "扫描完成",
      projectName: "project-release",
      projectId: "project-1",
      scanId: "scan-1",
      shareLink: "https://example.test/report",
    },
    result: "FAILED",
    summary: {
      vulnerabilities: 1,
      blockingVulnerabilities: 1,
      licenseRisks: 1,
      licenseConflicts: 1,
    },
    details: {
      vulnerabilities: [vulnerability],
      blockingVulnerabilities: [vulnerability],
      licenseRisks: [licenseRisk],
      licenseConflicts: [conflict],
    },
  });
});
