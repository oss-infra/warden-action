import assert from "node:assert/strict";
import test from "node:test";
import { evaluatePolicy } from "../src/policy";

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

test("matches English ranks case-insensitively and never treats none as a rank", () => {
  const results = {
    vulnerabilities: [{ rank: "High" }, { rank: "none" }],
    licenses: [],
    licenseConflicts: [],
  };
  assert.deepEqual(
    evaluatePolicy(results, { failOnSeverity: "high" }).blockingVulnerabilities,
    [{ rank: "High" }],
  );
  assert.equal(
    evaluatePolicy(results, { failOnSeverity: "none" }).failed,
    false,
  );
});
