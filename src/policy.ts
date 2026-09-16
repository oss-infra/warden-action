import type { PolicyResult, ScanResults } from "./types";

const SEVERITY = {
  警告: 1,
  warning: 1,
  低危: 2,
  low: 2,
  中危: 3,
  medium: 3,
  高危: 4,
  high: 4,
  严重: 5,
  critical: 5,
  none: Number.POSITIVE_INFINITY,
} as const satisfies Readonly<Record<string, number>>;

type Severity = keyof typeof SEVERITY;

export interface PolicyOptions {
  failOnSeverity?: string;
  failOnLicenseRisk?: boolean;
  failOnLicenseConflict?: boolean;
}

function isSeverity(value: string): value is Severity {
  return Object.hasOwn(SEVERITY, value);
}

export function normalizeThreshold(value = "high"): Severity {
  const key = String(value).trim().toLowerCase();
  if (!isSeverity(key)) {
    throw new Error(`Invalid fail-on severity: ${value}`);
  }
  return key;
}

export function evaluatePolicy(
  results: Pick<
    ScanResults,
    "vulnerabilities" | "licenses" | "licenseConflicts"
  >,
  options: PolicyOptions = {},
): PolicyResult {
  const threshold = normalizeThreshold(options.failOnSeverity);
  const thresholdValue = SEVERITY[threshold];
  const blockingVulnerabilities = results.vulnerabilities.filter(
    (item) => {
      const rank = item.rank ?? "";
      return (isSeverity(rank) ? SEVERITY[rank] : 0) >= thresholdValue;
    },
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
