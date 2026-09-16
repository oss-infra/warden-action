"use strict";

const { WardenApiClient } = require("./api-client");
const { evaluatePolicy } = require("./policy");
const { runScan } = require("./scanner");

async function run(config, hooks = {}) {
  const client =
    hooks.client ||
    new WardenApiClient({
      token: config.token,
      baseUrl: config.baseUrl,
      fetchImpl: hooks.fetchImpl,
    });
  const results = await runScan(client, config, hooks);
  const policy = evaluatePolicy(results, config);
  return { results, policy };
}

module.exports = { run };
