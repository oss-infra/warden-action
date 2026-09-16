import assert from "node:assert/strict";
import test from "node:test";
import { parseArgs } from "../src/cli";

test("parses value and boolean options", () => {
  assert.deepEqual(parseArgs(["--scan-type", "all", "--debug"]), {
    "scan-type": "all",
    debug: true,
  });
});

test("rejects unknown options", () => {
  assert.throws(() => parseArgs(["--scan-typo", "all"]), /Unknown option/);
});

test("rejects options without a value", () => {
  assert.throws(() => parseArgs(["--repository"]), /Missing value/);
});