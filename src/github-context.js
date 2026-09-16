"use strict";

function resolveGitHubTarget(context) {
  const payload = context.payload || {};
  const pullRequest = payload.pull_request;

  if (pullRequest) {
    const repository =
      pullRequest.head?.repo?.clone_url || pullRequest.head?.repo?.html_url;
    const branch = pullRequest.head?.ref;
    if (!repository || !branch) {
      throw new Error(
        "Pull request event does not contain an accessible head repository and branch",
      );
    }
    return {
      repository,
      branch,
      eventName: context.eventName,
      pullRequestNumber: pullRequest.number,
    };
  }

  const repository =
    payload.repository?.clone_url || payload.repository?.html_url;
  const branch =
    payload.ref?.replace(/^refs\/heads\//, "") ||
    context.ref?.replace(/^refs\/heads\//, "");
  if (!repository || !branch) {
    throw new Error(
      `GitHub ${context.eventName || "unknown"} event does not contain a repository and branch`,
    );
  }
  return { repository, branch, eventName: context.eventName };
}

module.exports = { resolveGitHubTarget };
