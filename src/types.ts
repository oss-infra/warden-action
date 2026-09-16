export type ScanType = "security" | "licenses" | "all";

// Yuanxi responses can contain additional fields that are preserved in JSON reports.
export interface VulnerabilityProof {
  vulComponent?: string;
  vulCurrentVersion?: string;
  vulFixVersion?: string;
  [key: string]: unknown;
}

export interface Vulnerability {
  id?: string | number;
  subject?: string;
  cveNo?: string;
  rank?: string;
  vulDependenceProofs?: VulnerabilityProof[];
  [key: string]: unknown;
}

export interface License {
  isRisk?: boolean | string;
  [key: string]: unknown;
}

export interface LicenseConflict {
  projectLicense?: string;
  sbomLicense?: string;
  explanation?: string;
  [key: string]: unknown;
}

export interface ScanConfig {
  token: string;
  baseUrl: string;
  repository: string;
  branch: string;
  projectName: string;
  scanType: ScanType;
  debug: boolean;
  failOnSeverity: string;
  failOnLicenseConflict: boolean;
  failOnLicenseRisk: boolean;
  timeoutMs: number;
  pollIntervalMs: number;
}

export interface ScanResults {
  vulnerabilities: Vulnerability[];
  licenses: License[];
  licenseConflicts: LicenseConflict[];
  projectName: string;
  projectId: string;
  scanId: string;
  status: string;
  shareLink: string;
}

export interface PolicyResult {
  failed: boolean;
  blockingVulnerabilities: Vulnerability[];
  licenseRisks: License[];
  licenseConflicts: LicenseConflict[];
}

export interface PageData<T> {
  totalPages?: number | string;
  itemList?: T[];
}

export interface LicensePageData {
  totalPages?: number | string;
  sbomLicense?: License[];
  projectLicenseConflict?: LicenseConflict[];
}

export interface ScanTask {
  scanId?: string;
  projectId?: string;
}

export interface CreateScanInput {
  projectName: string;
  repository: string;
  branch: string;
}

export interface ScanStatus {
  status: string;
  shareLink?: string;
}

export interface ScannerClient {
  createScan(input: CreateScanInput): Promise<ScanTask>;
  getStatus(scanId: string): Promise<ScanStatus>;
  getVulnerabilities(
    repoId: string,
    page: number,
    size: number,
  ): Promise<PageData<Vulnerability>>;
  getLicenses(
    repoId: string,
    page: number,
    size: number,
  ): Promise<LicensePageData>;
}
