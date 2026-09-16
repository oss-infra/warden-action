import assert from "node:assert/strict";
import test from "node:test";
import { run } from "../src/run";
import type { ScanConfig, ScannerClient } from "../src/types";

test("run combines scanner results with policy evaluation", async () => {
  const client: ScannerClient = {
    createScan: async () => ({ scanId: "scan-1", projectId: "project-1" }),
    getStatus: async () => ({ status: "扫描完成" }),
    getVulnerabilities: async () => ({
      totalPages: 1,
      itemList: [{ rank: "高危" }],
    }),
    getLicenses: async () => ({
      totalPages: 1,
      sbomLicense: [],
      projectLicenseConflict: [],
    }),
  };
  const config: ScanConfig = {
    token: "token",
    baseUrl: "https://scanner.example",
    repository: "https://github.com/acme/project.git",
    branch: "main",
    projectName: "project-main",
    scanType: "all",
    debug: false,
    failOnSeverity: "high",
    failOnLicenseConflict: true,
    failOnLicenseRisk: false,
    timeoutMs: 100,
    pollIntervalMs: 1,
  };

  const outcome = await run(config, { client, sleep: async () => {} });

  assert.equal(outcome.results.scanId, "scan-1");
  assert.equal(outcome.policy.failed, true);
  assert.equal(outcome.policy.blockingVulnerabilities.length, 1);
});