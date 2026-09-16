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
