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
const DEFAULT_PAGE_SIZE = 300;
// Guards against endpoints that keep returning full pages without totalPages.
const MAX_PAGES = 1000;
const EXCLUDED_VULNERABILITY_STATUSES: ReadonlySet<string> =
  new Set<VulnerabilityStatus>(["已修复", "误报", "忽略"]);

export function isCountedVulnerability(item: Vulnerability): boolean {
  return !item.status || !EXCLUDED_VULNERABILITY_STATUSES.has(item.status);
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export function normalizeRepository(repository: string): string {
  const value = repository.trim().replace(/\/+$/, "");
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

function isLastPage(
  page: number,
  totalPages: PageData<unknown>["totalPages"],
  pageIsShort: boolean,
): boolean {
  const total = Number(totalPages);
  const last =
    totalPages != null && Number.isFinite(total) ? page >= total : pageIsShort;
  if (!last && page >= MAX_PAGES)
    throw new Error(`Pagination exceeded ${MAX_PAGES} pages; aborting`);
  return last;
}

export async function collectPages<T>(
  fetchPage: (page: number, size: number) => Promise<PageData<T>>,
  pageSize = DEFAULT_PAGE_SIZE,
): Promise<T[]> {
  const items: T[] = [];
  for (let page = 1; ; page += 1) {
    const data = await fetchPage(page, pageSize);
    const pageItems = data.itemList ?? [];
    items.push(...pageItems);
    if (isLastPage(page, data.totalPages, pageItems.length < pageSize)) break;
  }
  return items;
}

export async function collectLicensePages(
  client: Pick<ScannerClient, "getLicenses">,
  repoId: string,
  pageSize = DEFAULT_PAGE_SIZE,
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
    // The API may repeat project-level conflicts on every page.
    for (const conflict of pageConflicts) {
      const key = JSON.stringify(conflict);
      if (!seenConflicts.has(key)) {
        seenConflicts.add(key);
        licenseConflicts.push(conflict);
      }
    }
    const pageIsShort =
      pageLicenses.length < pageSize && pageConflicts.length < pageSize;
    if (isLastPage(page, data.totalPages, pageIsShort)) break;
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
  let status = "unknown";
  for (;;) {
    const statusData = await client.getStatus(scanId);
    status = String(statusData.status ?? "unknown");
    options.onStatus?.(status);
    if (status === COMPLETE_STATUS) return statusData;
    if (status.includes("失败")) throw new Error(`Scan failed: ${status}`);
    const remaining = options.timeoutMs - (Date.now() - startedAt);
    if (remaining <= 0) break;
    await options.sleep(Math.min(options.pollIntervalMs, remaining));
  }
  throw new Error(
    `Scan timed out after ${Math.ceil(options.timeoutMs / 1000)} seconds (last status: ${status})`,
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
  const scanId = String(task.scanId);
  const projectId = String(task.projectId);

  const status = await waitForScan(client, scanId, {
    timeoutMs: input.timeoutMs,
    pollIntervalMs: input.pollIntervalMs,
    sleep: hooks.sleep ?? sleep,
    ...(hooks.onStatus ? { onStatus: hooks.onStatus } : {}),
  });

  const includeSecurity = input.scanType !== "licenses";
  const includeLicenses = input.scanType !== "security";
  const vulnerabilities = includeSecurity
    ? (
        await collectPages((page, size) =>
          client.getVulnerabilities(projectId, page, size),
        )
      ).filter(isCountedVulnerability)
    : [];
  const licenseData = includeLicenses
    ? await collectLicensePages(client, projectId)
    : { licenses: [], licenseConflicts: [], licensePackage: "" };

  return {
    vulnerabilities,
    ...licenseData,
    projectName,
    projectId,
    scanId,
    status: status.status,
    projectPackage: status.projectPackage ?? "",
    shareLink: status.shareLink ?? "",
  };
}
