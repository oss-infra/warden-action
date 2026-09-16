"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { WardenApiClient } = require("../src/api-client");

test("uses the documented status endpoint and keeps the token out of the body", async () => {
  let request;
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
  assert.equal(request.options.method, "GET");
  assert.match(request.url, /\/api\/sca\/open\/v1\/repo\/job\/status\?/);
  assert.match(request.url, /jobId=scan-1/);
  assert.match(request.url, /token=secret-token/);
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
    client.createScan({}),
    /POST \/api\/sca\/open\/v1\/repo\/scan\/git: bad request/,
  );
});
