import type { ScanConfig, ScanType } from "./types";

const SCAN_TYPE_ALIASES: Readonly<Record<string, ScanType>> = {
  stc: "security",
  sca: "licenses",
};

function isScanType(value: string): value is ScanType {
  return value === "security" || value === "licenses" || value === "all";
}

export function normalizeScanType(value = "all"): ScanType {
  const normalized = SCAN_TYPE_ALIASES[value] ?? value;
  if (!isScanType(normalized)) throw new Error(`Invalid scan type: ${value}`);
  return normalized;
}

export interface ConfigValues {
  token?: string | undefined;
  baseUrl?: string | undefined;
  repository?: string | undefined;
  branch?: string | undefined;
  projectName?: string | undefined;
  scanType?: string | undefined;
  debug?: boolean | string | undefined;
  failOnSeverity?: string | undefined;
  failOnLicenseConflict?: boolean | string | undefined;
  failOnLicenseRisk?: boolean | string | undefined;
  timeoutSeconds?: number | string | undefined;
  pollIntervalSeconds?: number | string | undefined;
}

export function parseBoolean(
  value: boolean | string | undefined,
  name: string,
): boolean {
  if (typeof value === "boolean") return value;
  if (value === undefined || value === "") return false;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${name} must be true or false`);
}

export function parsePositiveNumber(
  value: number | string | undefined,
  name: string,
  defaultValue: number,
): number {
  const number =
    value === undefined || value === "" ? defaultValue : Number(value);
  if (!Number.isFinite(number) || number <= 0)
    throw new Error(`${name} must be a positive number`);
  return number;
}

export function buildConfig(values: ConfigValues): ScanConfig {
  if (!values.token) throw new Error("token is required");
  if (!values.repository) throw new Error("repository is required");
  if (!values.branch) throw new Error("branch is required");
  return {
    token: values.token,
    baseUrl: values.baseUrl || "https://cybersec.antgroup.com",
    repository: values.repository,
    branch: values.branch,
    projectName: values.projectName || "",
    scanType: normalizeScanType(values.scanType),
    debug: parseBoolean(values.debug, "debug"),
    failOnSeverity: values.failOnSeverity || "high",
    failOnLicenseConflict:
      values.failOnLicenseConflict === undefined
        ? true
        : parseBoolean(
            values.failOnLicenseConflict,
            "fail-on-license-conflict",
          ),
    failOnLicenseRisk: parseBoolean(
      values.failOnLicenseRisk,
      "fail-on-license-risk",
    ),
    timeoutMs:
      parsePositiveNumber(values.timeoutSeconds, "timeout-seconds", 1200) *
      1000,
    pollIntervalMs:
      parsePositiveNumber(
        values.pollIntervalSeconds,
        "poll-interval-seconds",
        10,
      ) * 1000,
  };
}
