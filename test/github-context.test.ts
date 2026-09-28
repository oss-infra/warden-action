import assert from "node:assert/strict";
import test from "node:test";
import { resolveGitHubTarget } from "../src/github-context";

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

test("rejects tag refs instead of scanning them as branches", () => {
  assert.throws(
    () =>
      resolveGitHubTarget({
        eventName: "push",
        ref: "refs/tags/v1.0.0",
        payload: {
          ref: "refs/tags/v1.0.0",
          repository: { clone_url: "https://github.com/acme/project.git" },
        },
      }),
    /does not reference a repository branch/,
  );
});

test("falls back to GITHUB_REPOSITORY when the payload has no repository", () => {
  assert.deepEqual(
    resolveGitHubTarget({
      eventName: "schedule",
      ref: "refs/heads/main",
      serverUrl: "https://github.com",
      repositoryName: "acme/project",
      payload: {},
    }),
    {
      repository: "https://github.com/acme/project.git",
      branch: "main",
      eventName: "schedule",
    },
  );
});
