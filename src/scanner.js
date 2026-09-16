"use strict";

const crypto = require("node:crypto");

const COMPLETE_STATUS = "扫描完成";
const FAILED_STATUS = "扫描失败";

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function normalizeScanType(value = "all") {
  const aliases = { stc: "security", sca: "licenses" };
  const normalized = aliases[value] || value;
  if (!["security", "licenses", "all"].includes(normalized)) {
    throw new Error(`Invalid scan type: ${value}`);
  }
  return normalized;
}

function normalizeRepository(repository) {
  const value = repository.trim().replace(/\/$/, "");
  if (
    /^https?:\/\/(?:www\.)?(?:github\.com|gitee\.com)\//i.test(value) &&
    !value.endsWith(".git")
  ) {
    return `${value}.git`;
  }
  return value;
}

function makeProjectName(repository, branch) {
  const repositoryName =
    repository
      .replace(/\.git$/, "")
      .split(/[/:]/)
      .pop() || "repository";
  const readable = `${repositoryName}-${branch}`.replace(
    /[^a-zA-Z0-9\u3400-\u9fff]/g,
    "-",
  );
  if (readable.length <= 30) return readable;
  const hash = crypto
    .createHash("sha256")
    .update(`${repository}:${branch}`)
    .digest("hex")
    .slice(0, 7);
  return `${readable.slice(0, 22)}-${hash}`;
}

function validateProjectName(projectName) {
  const length = Array.from(projectName).length;
  if (length < 1 || length > 30)
    throw new Error("project-name must contain 1 to 30 characters");
  return projectName;
}

async function collectPages(fetchPage, selectItems, pageSize = 300) {
  const items = [];
  for (let page = 1; ; page += 1) {
    const data = await fetchPage(page, pageSize);
    const pageItems = selectItems(data) || [];
    items.push(...pageItems);
    const hasTotalPages = Number.isFinite(Number(data.totalPages));
    if (
      (hasTotalPages && page >= Number(data.totalPages)) ||
      (!hasTotalPages && pageItems.length < pageSize)
    )
      break;
  }
  return items;
}

async function collectLicensePages(client, repoId, pageSize = 300) {
  const licenses = [];
  const licenseConflicts = [];
  for (let page = 1; ; page += 1) {
    const data = await client.getLicenses(repoId, page, pageSize);
    const pageLicenses = data.sbomLicense || [];
    const pageConflicts = data.projectLicenseConflict || [];
    licenses.push(...pageLicenses);
    licenseConflicts.push(...pageConflicts);
    const hasTotalPages = Number.isFinite(Number(data.totalPages));
    const pageIsShort =
      pageLicenses.length < pageSize && pageConflicts.length < pageSize;
    if (
      (hasTotalPages && page >= Number(data.totalPages)) ||
      (!hasTotalPages && pageIsShort)
    )
      break;
  }
  return { licenses, licenseConflicts };
}

async function waitForScan(client, scanId, options) {
  const startedAt = Date.now();
  let statusData;
  while (Date.now() - startedAt <= options.timeoutMs) {
    statusData = await client.getStatus(scanId);
    options.onStatus?.(statusData.status);
    if (statusData.status === COMPLETE_STATUS) return statusData;
    if (
      statusData.status === FAILED_STATUS ||
      String(statusData.status).includes("失败")
    ) {
      throw new Error(`Scan failed: ${statusData.status}`);
    }
    await options.sleep(options.pollIntervalMs);
  }
  throw new Error(
    `Scan timed out after ${Math.ceil(options.timeoutMs / 1000)} seconds (last status: ${statusData?.status || "unknown"})`,
  );
}

async function runScan(client, input, hooks = {}) {
  const scanType = normalizeScanType(input.scanType);
  const repository = normalizeRepository(input.repository);
  const projectName = validateProjectName(
    input.projectName || makeProjectName(repository, input.branch),
  );
  const task = await client.createScan({
    projectName,
    repository,
    branch: input.branch,
  });
  if (!task?.scanId || !task?.projectId)
    throw new Error("Yuanxi did not return scanId and projectId");

  const status = await waitForScan(client, task.scanId, {
    timeoutMs: input.timeoutMs,
    pollIntervalMs: input.pollIntervalMs,
    sleep: hooks.sleep || sleep,
    onStatus: hooks.onStatus,
  });

  const results = { vulnerabilities: [], licenses: [], licenseConflicts: [] };
  if (scanType === "security" || scanType === "all") {
    results.vulnerabilities = await collectPages(
      (page, size) => client.getVulnerabilities(task.projectId, page, size),
      (data) => data.itemList,
    );
  }
  if (scanType === "licenses" || scanType === "all") {
    const licenseData = await collectLicensePages(client, task.projectId);
    results.licenses = licenseData.licenses;
    results.licenseConflicts = licenseData.licenseConflicts;
  }

  return {
    ...results,
    projectName,
    projectId: task.projectId,
    scanId: task.scanId,
    status: status.status,
    shareLink: status.shareLink || "",
  };
}

module.exports = {
  COMPLETE_STATUS,
  collectLicensePages,
  collectPages,
  makeProjectName,
  normalizeRepository,
  normalizeScanType,
  runScan,
  validateProjectName,
  waitForScan,
};
