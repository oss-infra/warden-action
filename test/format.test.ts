import assert from "node:assert/strict";
import test from "node:test";
import { licenseRiskMessage, structuredReport } from "../src/format";

test("formats license risks for action annotations", () => {
  assert.equal(
    licenseRiskMessage({ name: "dotenv", version: "17.4.2", isRisk: "true" }),
    "License risk: dotenv@17.4.2 | license=unknown",
  );
});

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
      projectPackage: "JAVA(Maven)",
      licensePackage: "maven",
      vulnerabilities: [vulnerability],
      licenses: [licenseRisk],
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
      projectPackage: "JAVA(Maven)",
      licensePackage: "maven",
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
      licenses: [licenseRisk],
      blockingVulnerabilities: [vulnerability],
      licenseRisks: [licenseRisk],
      licenseConflicts: [conflict],
    },
  });
});
