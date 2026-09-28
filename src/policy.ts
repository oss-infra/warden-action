import type { PolicyResult, ScanResults, Vulnerability } from "./types";

const SEVERITY: ReadonlyMap<string, number> = new Map([
  ["警告", 1],
  ["warning", 1],
  ["低危", 2],
  ["low", 2],
  ["中危", 3],
  ["medium", 3],
  ["高危", 4],
  ["high", 4],
  ["严重", 5],
  ["critical", 5],
]);

// Thresholds additionally accept "none"; it is never a valid vulnerability rank.
const THRESHOLD: ReadonlyMap<string, number> = new Map([
  ...SEVERITY,
  ["none", Number.POSITIVE_INFINITY],
]);

export interface PolicyOptions {
  failOnSeverity?: string;
  failOnLicenseRisk?: boolean;
  failOnLicenseConflict?: boolean;
}

export function normalizeThreshold(value = "high"): string {
  const key = value.trim().toLowerCase();
  if (!THRESHOLD.has(key)) {
    throw new Error(`Invalid fail-on severity: ${value}`);
  }
  return key;
}

export function severityScore(item: Pick<Vulnerability, "rank">): number {
  return (
    SEVERITY.get(
      String(item.rank ?? "")
        .trim()
        .toLowerCase(),
    ) ?? 0
  );
}

export function evaluatePolicy(
  results: Pick<
    ScanResults,
    "vulnerabilities" | "licenses" | "licenseConflicts"
  >,
  options: PolicyOptions = {},
): PolicyResult {
  const threshold =
    THRESHOLD.get(normalizeThreshold(options.failOnSeverity)) ??
    Number.POSITIVE_INFINITY;
  const blockingVulnerabilities = results.vulnerabilities.filter(
    (item) => severityScore(item) >= threshold,
  );
  const licenseRisks = results.licenses.filter(
    (item) => item.isRisk === true || item.isRisk === "true",
  );
  const licenseConflicts = results.licenseConflicts;
  const failed =
    blockingVulnerabilities.length > 0 ||
    (options.failOnLicenseRisk === true && licenseRisks.length > 0) ||
    (options.failOnLicenseConflict === true && licenseConflicts.length > 0);

  return { failed, blockingVulnerabilities, licenseRisks, licenseConflicts };
}
