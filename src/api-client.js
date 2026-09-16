"use strict";

const API_PREFIX = "/api/sca/open/v1/repo";

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
    url.search = new URLSearchParams({
      ...query,
      token: this.token,
    }).toString();
    if (this.debug) {
      const safeUrl = new URL(url);
      safeUrl.searchParams.set("token", "[REDACTED]");
      this.logger(
        `${method} ${safeUrl.toString()}${body ? ` body=${JSON.stringify(body)}` : ""}`,
      );
    }
    const response = await this.fetch(url, {
      method,
      headers: body ? { "content-type": "application/json" } : undefined,
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
        `${method} ${path} response http=${response.status} code=${payload.code} success=${payload.success} ${responseSummary(payload.data)}`.trim(),
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

module.exports = { WardenApiClient, WardenApiError };
