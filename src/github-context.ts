interface GitHubRepositoryPayload {
  clone_url?: string;
  html_url?: string;
}

export interface GitHubContext {
  eventName?: string;
  ref?: string;
  serverUrl?: string;
  /** `owner/name`, as provided by `GITHUB_REPOSITORY`. */
  repositoryName?: string;
  payload?: {
    ref?: string;
    repository?: GitHubRepositoryPayload;
    pull_request?: {
      number?: number;
      base?: { ref?: string };
      head?: {
        ref?: string;
        repo?: GitHubRepositoryPayload | null;
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

function repositoryUrl(
  repository: GitHubRepositoryPayload | null | undefined,
): string | undefined {
  return repository?.clone_url || repository?.html_url;
}

function branchFromRef(ref: string | undefined): string | undefined {
  return ref?.startsWith("refs/heads/")
    ? ref.slice("refs/heads/".length)
    : undefined;
}

export function resolveGitHubTarget(context: GitHubContext): GitHubTarget {
  const payload = context.payload || {};
  const pullRequest = payload.pull_request;
  const eventName = context.eventName ? { eventName: context.eventName } : {};

  if (pullRequest) {
    const repository = repositoryUrl(pullRequest.head?.repo);
    const branch = pullRequest.head?.ref;
    if (!repository || !branch) {
      throw new Error(
        "Pull request event does not contain an accessible head repository and branch",
      );
    }
    return {
      repository,
      branch,
      ...eventName,
      ...(pullRequest.number !== undefined
        ? { pullRequestNumber: pullRequest.number }
        : {}),
    };
  }

  const repository =
    repositoryUrl(payload.repository) ||
    (context.repositoryName
      ? `${context.serverUrl || "https://github.com"}/${context.repositoryName}.git`
      : undefined);
  const branch = branchFromRef(payload.ref) || branchFromRef(context.ref);
  if (!repository || !branch) {
    throw new Error(
      `GitHub ${context.eventName || "unknown"} event does not reference a repository branch; set the repository and branch inputs`,
    );
  }
  return { repository, branch, ...eventName };
}
