import crypto from "node:crypto";
import type {
  License,
  LicenseConflict,
  PageData,
  ScanConfig,
  ScannerClient,
  ScanResults,
  ScanStatus,
  Vulnerability,
  VulnerabilityStatus,
} from "./types";

export const COMPLETE_STATUS = "扫描完成";
const FAILED_STATUS = "扫描失败";
const EXCLUDED_VULNERABILITY_STATUSES = new Set<VulnerabilityStatus>([
  "已修复",
  "误报",
  "忽略",
]);

export function isCountedVulnerability(item: Vulnerability): boolean {
  return !(
    item.status &&
    EXCLUDED_VULNERABILITY_STATUSES.has(item.status as VulnerabilityStatus)
  );
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export function normalizeRepository(repository: string): string {
  const value = repository.trim().replace(/\/$/, "");
  if (
    /^https?:\/\/(?:www\.)?(?:github\.com|gitee\.com)\//i.test(value) &&
    !value.endsWith(".git")
  ) {
    return `${value}.git`;
  }
  return value;
}

export function makeProjectName(repository: string, branch: string): string {
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

export function validateProjectName(projectName: string): string {
  const length = Array.from(projectName).length;
  if (length < 1 || length > 30)
    throw new Error("project-name must contain 1 to 30 characters");
  return projectName;
}

export async function collectPages<T>(
  fetchPage: (page: number, size: number) => Promise<PageData<T>>,
  selectItems: (data: PageData<T>) => T[],
  pageSize = 300,
): Promise<T[]> {
  const items: T[] = [];
  for (let page = 1; ; page += 1) {
    const data = await fetchPage(page, pageSize);
    const pageItems = selectItems(data);
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

export async function collectLicensePages(
  client: Pick<ScannerClient, "getLicenses">,
  repoId: string,
  pageSize = 300,
): Promise<{
  licenses: License[];
  licenseConflicts: LicenseConflict[];
  licensePackage: string;
}> {
  const licenses: License[] = [];
  const licenseConflicts: LicenseConflict[] = [];
  const seenConflicts = new Set<string>();
  let licensePackage = "";
  for (let page = 1; ; page += 1) {
    const data = await client.getLicenses(repoId, page, pageSize);
    licensePackage ||= data.packageName ?? data.package ?? "";
    const pageLicenses = data.sbomLicense ?? [];
    const pageConflicts = data.projectLicenseConflict ?? [];
    licenses.push(...pageLicenses);
    for (const conflict of pageConflicts) {
      const key = JSON.stringify(conflict);
      if (!seenConflicts.has(key)) {
        seenConflicts.add(key);
        licenseConflicts.push(conflict);
      }
    }
    const hasTotalPages = Number.isFinite(Number(data.totalPages));
    const pageIsShort =
      pageLicenses.length < pageSize && pageConflicts.length < pageSize;
    if (
      (hasTotalPages && page >= Number(data.totalPages)) ||
      (!hasTotalPages && pageIsShort)
    )
      break;
  }
  return { licenses, licenseConflicts, licensePackage };
}

interface WaitOptions {
  timeoutMs: number;
  pollIntervalMs: number;
  sleep: (milliseconds: number) => Promise<void>;
  onStatus?: (status: string) => void;
}

export async function waitForScan(
  client: Pick<ScannerClient, "getStatus">,
  scanId: string,
  options: WaitOptions,
): Promise<ScanStatus> {
  const startedAt = Date.now();
  let statusData: ScanStatus | undefined;
  while (Date.now() - startedAt <= options.timeoutMs) {
    statusData = await client.getStatus(scanId);
    options.onStatus?.(statusData.status);
    if (statusData.status === COMPLETE_STATUS) return statusData;
    if (
      statusData.status === FAILED_STATUS ||
      statusData.status.includes("失败")
    ) {
      throw new Error(`Scan failed: ${statusData.status}`);
    }
    await options.sleep(options.pollIntervalMs);
  }
  throw new Error(
    `Scan timed out after ${Math.ceil(options.timeoutMs / 1000)} seconds (last status: ${statusData?.status ?? "unknown"})`,
  );
}

export type ScanInput = Pick<
  ScanConfig,
  | "repository"
  | "branch"
  | "projectName"
  | "scanType"
  | "timeoutMs"
  | "pollIntervalMs"
>;

interface ScanHooks {
  sleep?: (milliseconds: number) => Promise<void>;
  onStatus?: (status: string) => void;
}

export async function runScan(
  client: ScannerClient,
  input: ScanInput,
  hooks: ScanHooks = {},
): Promise<ScanResults> {
  const repository = normalizeRepository(input.repository);
  const projectName = validateProjectName(
    input.projectName || makeProjectName(repository, input.branch),
  );
  const task = await client.createScan({
    projectName,
    repository,
    branch: input.branch,
  });
  if (!task.scanId || !task.projectId)
    throw new Error("Yuanxi did not return scanId and projectId");
  const scanId = task.scanId;
  const projectId = task.projectId;

  const status = await waitForScan(client, scanId, {
    timeoutMs: input.timeoutMs,
    pollIntervalMs: input.pollIntervalMs,
    sleep: hooks.sleep ?? sleep,
    ...(hooks.onStatus ? { onStatus: hooks.onStatus } : {}),
  });

  const results: Pick<
    ScanResults,
    "vulnerabilities" | "licenses" | "licenseConflicts" | "licensePackage"
  > = {
    vulnerabilities: [],
    licenses: [],
    licenseConflicts: [],
    licensePackage: "",
  };
  if (input.scanType === "security" || input.scanType === "all") {
    results.vulnerabilities = (
      await collectPages(
        (page, size) => client.getVulnerabilities(projectId, page, size),
        (data) => data.itemList ?? [],
      )
    ).filter(isCountedVulnerability);
  }
  if (input.scanType === "licenses" || input.scanType === "all") {
    const licenseData = await collectLicensePages(client, projectId);
    results.licenses = licenseData.licenses;
    results.licenseConflicts = licenseData.licenseConflicts;
    results.licensePackage = licenseData.licensePackage;
  }

  return {
    ...results,
    projectName,
    projectId,
    scanId,
    status: status.status,
    projectPackage: status.projectPackage ?? "",
    shareLink: status.shareLink ?? "",
  };
}
