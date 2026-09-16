import assert from "node:assert/strict";
import test from "node:test";
import {
  collectLicensePages,
  isCountedVulnerability,
  makeProjectName,
  normalizeRepository,
  runScan,
  validateProjectName,
  waitForScan,
} from "../src/scanner";
import type { ScannerClient } from "../src/types";

test("runs one scan and retrieves both result types", async () => {
  const calls: Array<[string, unknown]> = [];
  const client: ScannerClient = {
    createScan: async (input) => {
      calls.push(["create", input]);
      return { scanId: "scan-1", projectId: "repo-1" };
    },
    getStatus: async () => ({
      status: "扫描完成",
      projectPackage: "JAVA(Maven)",
      shareLink: "https://example.test/report",
    }),
    getVulnerabilities: async () => ({
      totalPages: 1,
      itemList: [{ rank: "高危" }],
    }),
    getLicenses: async () => ({
      packageName: "maven",
      sbomLicense: [{ isRisk: true }],
      projectLicenseConflict: [{ sbomLicense: "GPL" }],
    }),
  };
  const result = await runScan(
    client,
    {
      repository: "https://github.com/acme/example.git",
      branch: "main",
      projectName: "",
      scanType: "all",
      timeoutMs: 100,
      pollIntervalMs: 1,
    },
    { sleep: async () => {} },
  );

  assert.equal(calls.length, 1);
  assert.equal(result.projectId, "repo-1");
  assert.equal(result.projectPackage, "JAVA(Maven)");
  assert.equal(result.licensePackage, "maven");
  assert.equal(result.vulnerabilities.length, 1);
  assert.equal(result.licenses.length, 1);
  assert.equal(result.licenseConflicts.length, 1);
});

test("throws when polling reaches a failed state", async () => {
  const client: Pick<ScannerClient, "getStatus"> = {
    getStatus: async () => ({ status: "扫描失败" }),
  };
  await assert.rejects(
    waitForScan(client, "scan-1", {
      timeoutMs: 100,
      pollIntervalMs: 1,
      sleep: async () => {},
    }),
    /Scan failed/,
  );
});

test("does not count resolved, false-positive, or ignored vulnerabilities", () => {
  const vulnerabilities = [
    { id: 1, status: "待处置" as const },
    { id: 2, status: "已修复" as const },
    { id: 3, status: "误报" as const },
    { id: 4, status: "忽略" as const },
    { id: 5 },
  ];

  assert.deepEqual(vulnerabilities.filter(isCountedVulnerability), [
    vulnerabilities[0],
    vulnerabilities[4],
  ]);
});

test("collects all vulnerability pages before excluding statuses", async () => {
  const requestedPages: number[] = [];
  const client: ScannerClient = {
    createScan: async () => ({ scanId: "scan-1", projectId: "repo-1" }),
    getStatus: async () => ({ status: "扫描完成" }),
    getVulnerabilities: async (_repoId, page, size) => {
      requestedPages.push(page);
      return page === 1
        ? {
            itemList: Array.from({ length: size }, () => ({
              status: "已修复" as const,
            })),
          }
        : { itemList: [{ status: "待处置" as const }] };
    },
    getLicenses: async () => ({}),
  };

  const result = await runScan(
    client,
    {
      repository: "https://github.com/acme/example.git",
      branch: "main",
      projectName: "example-main",
      scanType: "security",
      timeoutMs: 100,
      pollIntervalMs: 1,
    },
    { sleep: async () => {} },
  );

  assert.deepEqual(requestedPages, [1, 2]);
  assert.deepEqual(result.vulnerabilities, [{ status: "待处置" }]);
});

test("paginates license responses when totalPages is omitted", async () => {
  const requestedPages: number[] = [];
  const client: Pick<ScannerClient, "getLicenses"> = {
    getLicenses: async (_repoId, page, size) => {
      requestedPages.push(page);
      return page === 1
        ? {
            sbomLicense: Array.from({ length: size }, () => ({
              isRisk: false,
            })),
            projectLicenseConflict: [],
          }
        : {
            sbomLicense: [{ isRisk: true }],
            projectLicenseConflict: [{ sbomLicense: "GPL" }],
          };
    },
  };
  const result = await collectLicensePages(client, "repo-1", 2);
  assert.deepEqual(requestedPages, [1, 2]);
  assert.equal(result.licenses.length, 3);
  assert.equal(result.licenseConflicts.length, 1);
});

test("deduplicates license conflicts repeated across response pages", async () => {
  const conflict = {
    namespace: "npm",
    name: "example",
    version: "1.0.0",
    projectLicense: "MIT",
    sbomLicense: "GPL-3.0",
  };
  const client: Pick<ScannerClient, "getLicenses"> = {
    getLicenses: async (_repoId, page) => ({
      totalPages: 2,
      sbomLicense: [{ name: `component-${page}`, isRisk: false }],
      projectLicenseConflict: [conflict],
    }),
  };

  const result = await collectLicensePages(client, "repo-1", 1);

  assert.equal(result.licenses.length, 2);
  assert.deepEqual(result.licenseConflicts, [conflict]);
});

test("generated project names are stable and fit the API limit", () => {
  const name = makeProjectName(
    "https://github.com/acme/a-very-long-repository-name.git",
    "feature/a-long-branch",
  );
  assert.ok(name.length <= 30);
  assert.equal(
    name,
    makeProjectName(
      "https://github.com/acme/a-very-long-repository-name.git",
      "feature/a-long-branch",
    ),
  );
});

test("normalizes public GitHub and Gitee HTTPS repository URLs", () => {
  assert.equal(
    normalizeRepository("https://github.com/example/project"),
    "https://github.com/example/project.git",
  );
  assert.equal(
    normalizeRepository("https://gitee.com/example/project.git"),
    "https://gitee.com/example/project.git",
  );
  assert.equal(
    normalizeRepository("git@github.com:example/project.git"),
    "git@github.com:example/project.git",
  );
});

test("rejects explicit project names beyond the API limit", () => {
  assert.throws(
    () => validateProjectName("x".repeat(31)),
    /1 to 30 characters/,
  );
});
