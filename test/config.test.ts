import assert from "node:assert/strict";
import test from "node:test";
import {
  buildConfig,
  normalizeScanType,
  parseBoolean,
  parsePositiveNumber,
} from "../src/config";

test("buildConfig normalizes defaults and converts seconds to milliseconds", () => {
  const config = buildConfig({
    token: "token",
    repository: "https://github.com/acme/project.git",
    branch: "main",
  });

  assert.equal(config.scanType, "all");
  assert.equal(config.failOnSeverity, "high");
  assert.equal(config.failOnLicenseConflict, true);
  assert.equal(config.failOnLicenseRisk, false);
  assert.equal(config.timeoutMs, 1_200_000);
  assert.equal(config.pollIntervalMs, 10_000);
});

test("configuration parsers reject invalid values", () => {
  assert.throws(() => parseBoolean("yes", "debug"), /must be true or false/);
  assert.throws(
    () => parsePositiveNumber("0", "timeout-seconds", 1200),
    /must be a positive number/,
  );
  assert.throws(
    () =>
      buildConfig({
        token: "token",
        repository: "https://github.com/acme/project.git",
        branch: "main",
        scanType: "unknown",
      }),
    /Invalid scan type/,
  );
});

test("normalizeScanType supports documented aliases", () => {
  assert.equal(normalizeScanType("stc"), "security");
  assert.equal(normalizeScanType("sca"), "licenses");
});

test("parseBoolean falls back to the default for blank values", () => {
  assert.equal(parseBoolean("", "enforce-policy", true), true);
  assert.equal(parseBoolean(" FALSE ", "enforce-policy", true), false);
  const config = buildConfig({
    token: "token",
    repository: "https://github.com/acme/project.git",
    branch: "main",
    failOnLicenseConflict: "",
    scanType: "",
  });
  assert.equal(config.failOnLicenseConflict, true);
  assert.equal(config.scanType, "all");
});

test("buildConfig validates the severity threshold before scanning", () => {
  const base = {
    token: "token",
    repository: "https://github.com/acme/project.git",
    branch: "main",
  };
  assert.equal(
    buildConfig({ ...base, failOnSeverity: "Critical" }).failOnSeverity,
    "critical",
  );
  assert.throws(
    () => buildConfig({ ...base, failOnSeverity: "severe" }),
    /Invalid fail-on severity/,
  );
});