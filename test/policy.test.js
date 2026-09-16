"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { evaluatePolicy } = require("../src/policy");

test("fails at the configured vulnerability threshold", () => {
  const results = {
    vulnerabilities: [{ rank: "中危" }, { rank: "高危" }],
    licenses: [],
    licenseConflicts: [],
  };
  const policy = evaluatePolicy(results, { failOnSeverity: "high" });
  assert.equal(policy.failed, true);
  assert.deepEqual(policy.blockingVulnerabilities, [{ rank: "高危" }]);
});

test("can disable vulnerability failure and fail on license policy", () => {
  const results = {
    vulnerabilities: [{ rank: "严重" }],
    licenses: [{ isRisk: "true" }],
    licenseConflicts: [],
  };
  const policy = evaluatePolicy(results, {
    failOnSeverity: "none",
    failOnLicenseRisk: true,
    failOnLicenseConflict: false,
  });
  assert.equal(policy.failed, true);
  assert.equal(policy.blockingVulnerabilities.length, 0);
  assert.equal(policy.licenseRisks.length, 1);
});
