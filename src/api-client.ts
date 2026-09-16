import type {
  CreateScanInput,
  LicensePageData,
  PageData,
  ScanStatus,
  ScanTask,
  ScannerClient,
  Vulnerability,
  VulnerabilityQuery,
} from "./types";

const API_PREFIX = "/api/sca/open/v1/repo";
const SENSITIVE_KEY = /token|secret|authorization|private[_-]?key/i;
const SENSITIVE_QUERY_PARAMETER =
  /([?&](?:access_token|stoken|token|secret)=)[^&#\s"']*/gi;

export function redactSensitive(
  value: unknown,
  key = "",
  sensitiveValues: readonly string[] = [],
): unknown {
  if (SENSITIVE_KEY.test(key)) return "[REDACTED]";
  if (typeof value === "string") {
    let redacted = value.replace(SENSITIVE_QUERY_PARAMETER, "$1[REDACTED]");
    for (const sensitiveValue of sensitiveValues) {
      if (sensitiveValue)
        redacted = redacted.replaceAll(sensitiveValue, "[REDACTED]");
    }
    return redacted;
  }
  if (Array.isArray(value))
    return value.map((item) => redactSensitive(item, "", sensitiveValues));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([childKey, childValue]) => [
        childKey,
        redactSensitive(childValue, childKey, sensitiveValues),
      ]),
    );
  }
  return value;
}

export function debugJson(
  value: unknown,
  sensitiveValues: readonly string[] = [],
): string {
  return JSON.stringify(redactSensitive(value, "", sensitiveValues), null, 2);
}

export function responseSummary(data: unknown): string {
  if (!data || typeof data !== "object") return "data=empty";
  const record = data as Record<string, unknown>;
  return [
    "status" in record ? `status=${JSON.stringify(record.status)}` : null,
    "scanId" in record ? `scanId=${JSON.stringify(record.scanId)}` : null,
    "projectId" in record
      ? `projectId=${JSON.stringify(record.projectId)}`
      : null,
    "totalPages" in record ? `totalPages=${String(record.totalPages)}` : null,
    Array.isArray(record.itemList)
      ? `itemList=${record.itemList.length}`
      : null,
    Array.isArray(record.sbomLicense)
      ? `sbomLicense=${record.sbomLicense.length}`
      : null,
    Array.isArray(record.projectLicenseConflict)
      ? `projectLicenseConflict=${record.projectLicenseConflict.length}`
      : null,
  ]
    .filter((item): item is string => item !== null)
    .join(" ");
}

export class WardenApiError extends Error {
  readonly status?: number;
  readonly code?: number;

  constructor(
    message: string,
    details: { cause?: unknown; status?: number; code?: number | undefined } = {},
  ) {
    super(message);
    this.name = "WardenApiError";
    if ("cause" in details) this.cause = details.cause;
    if (details.status !== undefined) this.status = details.status;
    if (details.code !== undefined) this.code = details.code;
  }
}

export interface ApiEnvelope<T> {
  code: number;
  success: boolean;
  message?: string;
  data?: T;
}

function isApiEnvelope(value: unknown): value is ApiEnvelope<unknown> {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return typeof record.code === "number" && typeof record.success === "boolean";
}

interface FetchResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

export type FetchImplementation = (
  url: URL,
  options: {
    method: string;
    headers?: Record<string, string>;
    body?: string;
  },
) => Promise<FetchResponse>;

interface ClientOptions {
  token: string;
  baseUrl?: string;
  fetchImpl?: FetchImplementation;
  debug?: boolean;
  logger?: (message: string) => void;
}

export class WardenApiClient implements ScannerClient {
  private readonly token: string;
  private readonly baseUrl: string;
  private readonly fetch: FetchImplementation;
  private readonly debug: boolean;
  private readonly logger: (message: string) => void;

  constructor({
    token,
    baseUrl = "https://cybersec.antgroup.com",
    fetchImpl = globalThis.fetch,
    debug = false,
    logger = () => {},
  }: ClientOptions) {
    if (!token) throw new Error("token is required");
    if (typeof fetchImpl !== "function")
      throw new Error("fetch is unavailable; Node.js 20 or later is required");
    this.token = token;
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.fetch = fetchImpl;
    this.debug = debug;
    this.logger = logger;
  }

  async createScan(input: CreateScanInput): Promise<ScanTask> {
    return this.request("POST", `${API_PREFIX}/scan/git`, {
      body: input,
    });
  }

  async getStatus(scanId: string): Promise<ScanStatus> {
    return this.request("GET", `${API_PREFIX}/job/status`, {
      query: { jobId: scanId },
    });
  }

  async getVulnerabilities(
    repoId: string,
    page: number,
    size: number,
    filters: VulnerabilityQuery = {},
  ): Promise<PageData<Vulnerability>> {
    return this.request("POST", `${API_PREFIX}/vuls/detail`, {
      body: { repoId, page, size, ...filters },
    });
  }

  async getLicenses(
    repoId: string,
    page: number,
    size: number,
  ): Promise<LicensePageData> {
    return this.request("POST", `${API_PREFIX}/lisense`, {
      body: { repoId, page, size },
    });
  }

  private async request<T>(
    method: string,
    path: string,
    options: {
      query?: Record<string, string>;
      body?: object;
    } = {},
  ): Promise<T> {
    const { query = {}, body } = options;
    const url = new URL(`${this.baseUrl}${path}`);
    const queryWithToken = {
      ...query,
      token: this.token,
    };
    url.search = new URLSearchParams(queryWithToken).toString();
    const headers = body ? { "content-type": "application/json" } : undefined;
    const startedAt = Date.now();
    if (this.debug) {
      const safeUrl = new URL(url);
      safeUrl.searchParams.set("token", "[REDACTED]");
      this.logger(
        [
          `API request: ${method} ${safeUrl.toString()}`,
          `  path: ${path}`,
          `  query: ${debugJson(queryWithToken)}`,
          `  headers: ${debugJson(headers ?? {})}`,
          `  body: ${body === undefined ? "none" : debugJson(body)}`,
        ].join("\n"),
      );
    }
    const requestOptions: {
      method: string;
      headers?: Record<string, string>;
      body?: string;
    } = { method };
    if (headers) requestOptions.headers = headers;
    if (body) requestOptions.body = JSON.stringify(body);
    const response = await this.fetch(url, requestOptions);

    let rawPayload: unknown;
    try {
      rawPayload = await response.json();
    } catch (error) {
      throw new WardenApiError(
        `Yuanxi returned invalid JSON (${response.status})`,
        { cause: error, status: response.status },
      );
    }
    if (!isApiEnvelope(rawPayload)) {
      throw new WardenApiError(
        `${method} ${path}: Yuanxi returned an invalid response envelope`,
        { status: response.status },
      );
    }
    const payload = rawPayload;

    if (this.debug) {
      this.logger(
        [
          `API response: ${method} ${path}`,
          `  durationMs: ${Date.now() - startedAt}`,
          `  httpStatus: ${response.status}`,
          `  code: ${String(payload.code)}`,
          `  success: ${String(payload.success)}`,
          `  message: ${payload.message ?? ""}`,
          `  data: ${responseSummary(payload.data)}`,
          `  payload: ${debugJson(payload, [this.token])}`,
        ].join("\n"),
      );
    }

    if (!response.ok || payload.success === false || payload.code !== 0) {
      throw new WardenApiError(
        `${method} ${path}: ${payload.message || `Yuanxi request failed (${response.status})`}`,
        {
          status: response.status,
          code: payload.code,
        },
      );
    }
    if (!("data" in payload) || payload.data === undefined) {
      throw new WardenApiError(
        `${method} ${path}: Yuanxi returned an invalid response envelope`,
        { status: response.status, code: payload.code },
      );
    }
    // Endpoint methods define the expected data shape after the envelope is validated.
    return payload.data as T;
  }
}
