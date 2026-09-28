import type {
  License,
  LicenseConflict,
  PolicyResult,
  ScanConfig,
  ScanResults,
  Vulnerability,
} from "./types";

type ReportConfig = Pick<ScanConfig, "repository" | "branch" | "scanType">;
type ReportResults = Pick<
  ScanResults,
  | "status"
  | "projectName"
  | "projectId"
  | "scanId"
  | "shareLink"
  | "projectPackage"
  | "licensePackage"
  | "vulnerabilities"
  | "licenses"
>;

export type ResultLabel = "FAILED" | "PASSED";

export function resultLabel(policy: Pick<PolicyResult, "failed">): ResultLabel {
  return policy.failed ? "FAILED" : "PASSED";
}

export function vulnerabilityMessage(item: Vulnerability): string {
  const proof = item.vulDependenceProofs?.[0];
  const details = [
    item.subject || item.cveNo || `Vulnerability ${item.id}`,
    `severity=${item.rank || "unknown"}`,
  ];
  if (proof?.vulComponent)
    details.push(
      `component=${proof.vulComponent}@${proof.vulCurrentVersion || "?"}`,
    );
  if (proof?.vulFixVersion) details.push(`fix=${proof.vulFixVersion}`);
  return details.join(" | ");
}

export function licenseRiskMessage(item: License): string {
  const component = `${item.name || "unknown"}@${item.version || "?"}`;
  return `License risk: ${component} | license=${item.license || "unknown"}`;
}

export function licenseConflictMessage(item: LicenseConflict): string {
  const message = `License conflict: ${item.projectLicense || "?"} / ${item.sbomLicense || "?"}`;
  return item.explanation ? `${message} | ${item.explanation}` : message;
}

export function summary(results: ReportResults, policy: PolicyResult): string {
  return [
    `Result: ${resultLabel(policy)}`,
    `Vulnerabilities: ${results.vulnerabilities.length} (${policy.blockingVulnerabilities.length} blocking)`,
    `License risks: ${policy.licenseRisks.length}`,
    `License conflicts: ${policy.licenseConflicts.length}`,
    results.shareLink ? `Report: ${results.shareLink}` : null,
  ]
    .filter((line): line is string => line !== null)
    .join("\n");
}

export interface StructuredReport {
  schemaVersion: "1.0";
  target: ReportConfig;
  scan: Pick<
    ScanResults,
    "status" | "projectName" | "projectId" | "scanId" | "shareLink"
  > & {
    projectPackage: string;
    licensePackage: string;
  };
  result: ResultLabel;
  summary: {
    vulnerabilities: number;
    blockingVulnerabilities: number;
    licenseRisks: number;
    licenseConflicts: number;
  };
  details: Omit<PolicyResult, "failed"> & {
    vulnerabilities: Vulnerability[];
    licenses: ScanResults["licenses"];
  };
}

export function structuredReport(
  config: ReportConfig,
  results: ReportResults,
  policy: PolicyResult,
): StructuredReport {
  return {
    schemaVersion: "1.0",
    target: {
      repository: config.repository,
      branch: config.branch,
      scanType: config.scanType,
    },
    scan: {
      status: results.status,
      projectName: results.projectName,
      projectId: results.projectId,
      scanId: results.scanId,
      shareLink: results.shareLink,
      projectPackage: results.projectPackage,
      licensePackage: results.licensePackage,
    },
    result: resultLabel(policy),
    summary: {
      vulnerabilities: results.vulnerabilities.length,
      blockingVulnerabilities: policy.blockingVulnerabilities.length,
      licenseRisks: policy.licenseRisks.length,
      licenseConflicts: policy.licenseConflicts.length,
    },
    details: {
      vulnerabilities: results.vulnerabilities,
      licenses: results.licenses,
      blockingVulnerabilities: policy.blockingVulnerabilities,
      licenseRisks: policy.licenseRisks,
      licenseConflicts: policy.licenseConflicts,
    },
  };
}
