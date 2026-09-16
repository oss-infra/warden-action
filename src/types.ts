export type ScanType = "security" | "licenses" | "all";

export type ScanStatusValue =
  | "排队中"
  | "组件依赖扫描中"
  | "可达分析扫描中"
  | "扫描中"
  | "扫描完成"
  | "扫描失败";

export type ProjectPackage =
  | "JAVA(Maven)"
  | "Node(NPM)"
  | "GO(GoMod)"
  | "Python(PyPI)"
  | (string & {});

export type VulnerabilityRank = "严重" | "高危" | "中危" | "低危" | "警告";
export type VulnerabilityStatus = "待处置" | "已修复" | "误报" | "忽略";
export type AccuracyTag = "" | "潜在可达" | "确认可达";
export type DependencyType = "直接依赖" | "间接依赖";

// Yuanxi can add response fields without notice; index signatures preserve them in reports.
export interface VulnerabilityProof {
  vulDependenceLink?: string;
  vulLineNum?: number;
  vulComponent?: string;
  vulCurrentVersion?: string;
  vulFixVersion?: string;
  vulUrgentlyFixVersion?: string;
  downloadPath?: string | null;
  introductionPath?: string;
  [key: string]: unknown;
}

export interface Vulnerability {
  id?: string | number;
  subject?: string;
  rank?: VulnerabilityRank | (string & {});
  vulType?: string;
  cwes?: string;
  vulDesciption?: string;
  vulImpactRange?: string;
  cveNo?: string | null;
  cnvdNo?: string | null;
  status?: VulnerabilityStatus | (string & {});
  urgentlyFix?: "是" | "否" | (string & {});
  accuracyTag?: AccuracyTag | (string & {});
  directDepency?: DependencyType | (string & {});
  vulDependenceProofs?: VulnerabilityProof[];
  [key: string]: unknown;
}

export interface License {
  namespace?: string;
  name?: string;
  version?: string;
  license?: string | null;
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
  projectPackage: string;
  licensePackage: string;
  shareLink: string;
}

export interface PolicyResult {
  failed: boolean;
  blockingVulnerabilities: Vulnerability[];
  licenseRisks: License[];
  licenseConflicts: LicenseConflict[];
}

export interface PageData<T> {
  currentPage?: number;
  totalPages?: number | string;
  totalElements?: number;
  itemList?: T[];
}

export interface LicensePageData {
  package?: "maven" | "pypi" | "npm" | "golang" | (string & {});
  packageName?: "maven" | "pypi" | "npm" | "golang" | (string & {});
  currentPage?: number;
  totalPages?: number | string;
  totalElements?: number;
  sbomLicense?: License[];
  projectLicenseConflict?: LicenseConflict[];
}

export interface ScanTask {
  scanId: string;
  projectId: string;
}

export interface CreateScanInput {
  projectName: string;
  repository: string;
  branch: string;
}

export interface ScanStatus {
  status: ScanStatusValue | (string & {});
  projectPackage?: ProjectPackage;
  shareLink?: string;
}

export interface VulnerabilityQuery {
  rank?: VulnerabilityRank[];
  vulType?: string[];
  cveNo?: string[];
  status?: VulnerabilityStatus[];
  urgentlyFix?: "是" | "否";
  accuracyTag?: Exclude<AccuracyTag, "">[];
  directDepency?: DependencyType;
}

export interface ScannerClient {
  createScan(input: CreateScanInput): Promise<ScanTask>;
  getStatus(scanId: string): Promise<ScanStatus>;
  getVulnerabilities(
    repoId: string,
    page: number,
    size: number,
    filters?: VulnerabilityQuery,
  ): Promise<PageData<Vulnerability>>;
  getLicenses(
    repoId: string,
    page: number,
    size: number,
  ): Promise<LicensePageData>;
}
