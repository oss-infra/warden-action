"use strict";

const API_PREFIX = "/api/sca/open/v1/repo";
const SENSITIVE_KEY = /token|secret|authorization|private[_-]?key/i;
const SENSITIVE_QUERY_PARAMETER =
  /([?&](?:access_token|stoken|token|secret)=)[^&#\s"']*/gi;

function redactSensitive(value, key = "", sensitiveValues = []) {
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

function debugJson(value, sensitiveValues = []) {
  return JSON.stringify(redactSensitive(value, "", sensitiveValues), null, 2);
}

function responseSummary(data) {
  if (!data || typeof data !== "object") return "data=empty";
  return [
    "status" in data ? `status=${JSON.stringify(data.status)}` : null,
    "scanId" in data ? `scanId=${JSON.stringify(data.scanId)}` : null,
    "projectId" in data ? `projectId=${JSON.stringify(data.projectId)}` : null,
    "totalPages" in data ? `totalPages=${data.totalPages}` : null,
    Array.isArray(data.itemList) ? `itemList=${data.itemList.length}` : null,
    Array.isArray(data.sbomLicense)
      ? `sbomLicense=${data.sbomLicense.length}`
      : null,
    Array.isArray(data.projectLicenseConflict)
      ? `projectLicenseConflict=${data.projectLicenseConflict.length}`
      : null,
  ]
    .filter(Boolean)
    .join(" ");
}

class WardenApiError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = "WardenApiError";
    Object.assign(this, details);
  }
}

class WardenApiClient {
  constructor({
    token,
    baseUrl = "https://cybersec.antgroup.com",
    fetchImpl = globalThis.fetch,
    debug = false,
    logger = () => {},
  }) {
    if (!token) throw new Error("token is required");
    if (typeof fetchImpl !== "function")
      throw new Error("fetch is unavailable; Node.js 20 or later is required");
    this.token = token;
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.fetch = fetchImpl;
    this.debug = debug;
    this.logger = logger;
  }

  async createScan({ projectName, repository, branch }) {
    return this.request("POST", `${API_PREFIX}/scan/git`, {
      body: { projectName, repository, branch },
    });
  }

  // 获取扫描任务状态
  async getStatus(scanId) {
    return this.request("GET", `${API_PREFIX}/job/status`, {
      query: { jobId: scanId },
    });
  }

  // 获取仓库的漏洞信息
  async getVulnerabilities(repoId, page, size) {
    return this.request("POST", `${API_PREFIX}/vuls/detail`, {
      body: { repoId, page, size },
    });
  }

  // 获取仓库的许可证信息
  async getLicenses(repoId, page, size) {
    return this.request("POST", `${API_PREFIX}/lisense`, {
      body: { repoId, page, size },
    });
  }

  async request(method, path, { query = {}, body } = {}) {
    const url = new URL(`${this.baseUrl}${path}`);
    const queryWithToken = {
      ...query,
      token: this.token,
    };
    url.search = new URLSearchParams(queryWithToken).toString();
    const headers = body ? { "content-type": "application/json" } : {};
    const startedAt = Date.now();
    if (this.debug) {
      const safeUrl = new URL(url);
      safeUrl.searchParams.set("token", "[REDACTED]");
      this.logger(
        [
          `API request: ${method} ${safeUrl.toString()}`,
          `  path: ${path}`,
          `  query: ${debugJson(queryWithToken)}`,
          `  headers: ${debugJson(headers)}`,
          `  body: ${body === undefined ? "none" : debugJson(body)}`,
        ].join("\n"),
      );
    }
    const response = await this.fetch(url, {
      method,
      headers: body ? headers : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });

    let payload;
    try {
      payload = await response.json();
    } catch (error) {
      throw new WardenApiError(
        `Yuanxi returned invalid JSON (${response.status})`,
        { cause: error, status: response.status },
      );
    }

    if (this.debug) {
      this.logger(
        [
          `API response: ${method} ${path}`,
          `  durationMs: ${Date.now() - startedAt}`,
          `  httpStatus: ${response.status}`,
          `  code: ${payload.code}`,
          `  success: ${payload.success}`,
          `  message: ${payload.message || ""}`,
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
    return payload.data;
  }
}

module.exports = {
  WardenApiClient,
  WardenApiError,
  debugJson,
  redactSensitive,
  responseSummary,
};
