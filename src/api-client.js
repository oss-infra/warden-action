"use strict";

const API_PREFIX = "/api/sca/open/v1/repo";

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
  }) {
    if (!token) throw new Error("token is required");
    if (typeof fetchImpl !== "function")
      throw new Error("fetch is unavailable; Node.js 20 or later is required");
    this.token = token;
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.fetch = fetchImpl;
  }

  async createScan({ projectName, repository, branch }) {
    return this.request("POST", `${API_PREFIX}/scan/git`, {
      body: { projectName, repository, branch },
    });
  }

  async getStatus(scanId) {
    return this.request("GET", `${API_PREFIX}/job/status`, {
      query: { jobId: scanId },
    });
  }

  async getVulnerabilities(repoId, page, size) {
    return this.request("POST", `${API_PREFIX}/vuls/detail`, {
      body: { repoId, page, size },
    });
  }

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
