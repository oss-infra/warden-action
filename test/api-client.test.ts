import assert from "node:assert/strict";
import test from "node:test";
import { WardenApiClient, type FetchImplementation } from "../src/api-client";

test("uses the documented status endpoint and keeps the token out of the body", async () => {
  let request:
    | {
        url: string;
        options: Parameters<FetchImplementation>[1];
      }
    | undefined;
  const client = new WardenApiClient({
    token: "secret-token",
    baseUrl: "https://scanner.example",
    fetchImpl: async (url, options) => {
      request = { url: String(url), options };
      return {
        ok: true,
        status: 200,
        json: async () => ({
          code: 0,
          success: true,
          data: { status: "排队中" },
        }),
      };
    },
  });
  await client.getStatus("scan-1");
  assert.ok(request);
  assert.equal(request.options.method, "GET");
  assert.match(request.url, /\/api\/sca\/open\/v1\/repo\/job\/status\?/);
  assert.match(request.url, /jobId=scan-1/);
  assert.match(request.url, /token=secret-token/);
  assert.equal(request.options.headers, undefined);
  assert.equal(request.options.body, undefined);
});

test("sends documented vulnerability filters and returns structured details", async () => {
  let requestBody: unknown;
  const client = new WardenApiClient({
    token: "token",
    fetchImpl: async (_url, options) => {
      requestBody = JSON.parse(options.body ?? "null");
      return {
        ok: true,
        status: 200,
        json: async () => ({
          code: 0,
          message: "成功",
          success: true,
          data: {
            currentPage: 1,
            totalPages: 1,
            totalElements: 1,
            itemList: [
              {
                id: 123456,
                rank: "严重",
                cveNo: "CVE-2017-18349",
                urgentlyFix: "是",
                accuracyTag: "潜在可达",
                directDepency: "直接依赖",
                vulDependenceProofs: [
                  {
                    vulComponent: "com.alibaba:fastjson",
                    vulCurrentVersion: "1.2.24",
                    vulFixVersion: "1.2.25",
                    vulUrgentlyFixVersion: "1.2.25",
                    vulLineNum: 16,
                  },
                ],
              },
            ],
          },
        }),
      };
    },
  });

  const result = await client.getVulnerabilities("repo-1", 1, 300, {
    rank: ["严重", "高危"],
    status: ["待处置"],
    urgentlyFix: "是",
    accuracyTag: ["潜在可达"],
    directDepency: "直接依赖",
  });

  assert.deepEqual(requestBody, {
    repoId: "repo-1",
    page: 1,
    size: 300,
    rank: ["严重", "高危"],
    status: ["待处置"],
    urgentlyFix: "是",
    accuracyTag: ["潜在可达"],
    directDepency: "直接依赖",
  });
  assert.equal(result.currentPage, 1);
  assert.equal(result.totalElements, 1);
  assert.equal(result.itemList?.[0]?.vulDependenceProofs?.[0]?.vulLineNum, 16);
});

test("returns documented status and license response fields", async () => {
  const responses = [
    {
      code: 0,
      success: true,
      data: {
        status: "扫描完成",
        projectPackage: "JAVA(Maven)",
        shareLink: "https://scanner.example/report",
      },
    },
    {
      code: 0,
      success: true,
      data: {
        packageName: "maven",
        sbomLicense: [
          {
            namespace: "javax.inject",
            name: "javax.inject",
            version: "1",
            license: "Apache-2.0",
            isRisk: false,
          },
        ],
        projectLicenseConflict: [
          {
            projectLicense: "Apache-2.0",
            sbomLicense: "CDDL-1.1",
            explanation: "Copyleft conflict",
          },
        ],
      },
    },
  ];
  const client = new WardenApiClient({
    token: "token",
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => responses.shift(),
    }),
  });

  const status = await client.getStatus("scan-1");
  const licenses = await client.getLicenses("repo-1", 1, 300);

  assert.equal(status.projectPackage, "JAVA(Maven)");
  assert.equal(licenses.packageName, "maven");
  assert.equal(licenses.sbomLicense?.[0]?.license, "Apache-2.0");
  assert.equal(
    licenses.projectLicenseConflict?.[0]?.explanation,
    "Copyleft conflict",
  );
});

test("rejects an unsuccessful API envelope", async () => {
  const client = new WardenApiClient({
    token: "token",
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ({ code: 400, success: false, message: "bad request" }),
    }),
  });
  await assert.rejects(
    client.createScan({
      projectName: "test",
      repository: "repo",
      branch: "main",
    }),
    /POST \/api\/sca\/open\/v1\/repo\/scan\/git: bad request/,
  );
});

test("rejects a malformed API envelope", async () => {
  const client = new WardenApiClient({
    token: "token",
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ({ status: "扫描完成" }),
    }),
  });

  await assert.rejects(client.getStatus("scan-1"), /invalid response envelope/i);
});

test("debug logging includes request details without exposing the token", async () => {
  const messages: string[] = [];
  const client = new WardenApiClient({
    token: "secret-token",
    baseUrl: "https://scanner.example",
    debug: true,
    logger: (message) => messages.push(message),
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        code: 0,
        success: true,
        data: {
          itemList: [{ id: 1, subject: "Example vulnerability" }],
          totalPages: 1,
          shareLink:
            "https://scanner.example/report?id=1&stoken=response-secret",
          metadata: { authorization: "response-authorization" },
        },
      }),
    }),
  });

  await client.getVulnerabilities("repo-1", 2, 300);
  const [requestMessage, responseMessage] = messages;
  assert.ok(requestMessage);
  assert.ok(responseMessage);

  assert.match(
    requestMessage,
    /API request: POST https:\/\/scanner\.example\/api\/sca\/open\/v1\/repo\/vuls\/detail/,
  );
  assert.match(requestMessage, /"token": "\[REDACTED\]"/);
  assert.match(requestMessage, /"repoId": "repo-1"/);
  assert.match(requestMessage, /"page": 2/);
  assert.match(requestMessage, /"size": 300/);
  assert.match(requestMessage, /"content-type": "application\/json"/);
  assert.match(responseMessage, /durationMs: \d+/);
  assert.match(responseMessage, /httpStatus: 200/);
  assert.match(responseMessage, /data: totalPages=1 itemList=1/);
  assert.match(responseMessage, /payload: \{/);
  assert.match(responseMessage, /"subject": "Example vulnerability"/);
  assert.match(responseMessage, /stoken=\[REDACTED\]/);
  assert.match(responseMessage, /"authorization": "\[REDACTED\]"/);
  assert.doesNotMatch(messages.join("\n"), /secret-token/);
  assert.doesNotMatch(messages.join("\n"), /response-secret/);
  assert.doesNotMatch(messages.join("\n"), /response-authorization/);
});
