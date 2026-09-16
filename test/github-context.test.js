"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { resolveGitHubTarget } = require("../src/github-context");

for (const eventName of ["pull_request", "pull_request_target"]) {
  test(`${eventName} scans the pull request head repository and branch`, () => {
    const result = resolveGitHubTarget({
      eventName,
      ref: "refs/pull/42/merge",
      payload: {
        repository: { clone_url: "https://github.com/base/project.git" },
        pull_request: {
          number: 42,
          head: {
            ref: "feature/security-fix",
            repo: { clone_url: "https://github.com/contributor/project.git" },
          },
          base: { ref: "main" },
        },
      },
    });

    assert.deepEqual(result, {
      repository: "https://github.com/contributor/project.git",
      branch: "feature/security-fix",
      eventName,
      pullRequestNumber: 42,
    });
  });
}

test("push scans the event repository and pushed branch", () => {
  assert.deepEqual(
    resolveGitHubTarget({
      eventName: "push",
      ref: "refs/heads/main",
      payload: {
        ref: "refs/heads/release",
        repository: { clone_url: "https://github.com/acme/project.git" },
      },
    }),
    {
      repository: "https://github.com/acme/project.git",
      branch: "release",
      eventName: "push",
    },
  );
});

test("rejects pull request events without an accessible head repository", () => {
  assert.throws(
    () =>
      resolveGitHubTarget({
        eventName: "pull_request_target",
        payload: { pull_request: { head: { ref: "feature" } } },
      }),
    /accessible head repository and branch/,
  );
});
