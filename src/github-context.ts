export interface GitHubContext {
  eventName?: string;
  ref?: string;
  payload?: {
    ref?: string;
    repository?: { clone_url?: string; html_url?: string };
    pull_request?: {
      number?: number;
      base?: { ref?: string };
      head?: {
        ref?: string;
        repo?: { clone_url?: string; html_url?: string } | null;
      };
    };
  };
}

export interface GitHubTarget {
  repository: string;
  branch: string;
  eventName?: string;
  pullRequestNumber?: number;
}

export function resolveGitHubTarget(context: GitHubContext): GitHubTarget {
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
      ...(context.eventName ? { eventName: context.eventName } : {}),
      ...(pullRequest.number !== undefined
        ? { pullRequestNumber: pullRequest.number }
        : {}),
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
  return {
    repository,
    branch,
    ...(context.eventName ? { eventName: context.eventName } : {}),
  };
}
