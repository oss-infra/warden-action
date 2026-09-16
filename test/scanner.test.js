"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  collectLicensePages,
  makeProjectName,
  normalizeRepository,
  runScan,
  validateProjectName,
  waitForScan,
} = require("../src/scanner");

test("runs one scan and retrieves both result types", async () => {
  const calls = [];
  const client = {
    createScan: async (input) => {
      calls.push(["create", input]);
      return { scanId: "scan-1", projectId: "repo-1" };
    },
    getStatus: async () => ({
      status: "扫描完成",
      shareLink: "https://example.test/report",
    }),
    getVulnerabilities: async () => ({
      totalPages: 1,
      itemList: [{ rank: "高危" }],
    }),
    getLicenses: async () => ({
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
  assert.equal(result.vulnerabilities.length, 1);
  assert.equal(result.licenses.length, 1);
  assert.equal(result.licenseConflicts.length, 1);
});

test("throws when polling reaches a failed state", async () => {
  const client = { getStatus: async () => ({ status: "扫描失败" }) };
  await assert.rejects(
    waitForScan(client, "scan-1", {
      timeoutMs: 100,
      pollIntervalMs: 1,
      sleep: async () => {},
    }),
    /Scan failed/,
  );
});

test("paginates license responses when totalPages is omitted", async () => {
  const requestedPages = [];
  const client = {
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
