import { WardenApiClient, type FetchImplementation } from "./api-client";
import { evaluatePolicy } from "./policy";
import { runScan } from "./scanner";
import type {
  PolicyResult,
  ScanConfig,
  ScannerClient,
  ScanResults,
} from "./types";

export interface RunHooks {
  client?: ScannerClient;
  fetchImpl?: FetchImplementation;
  sleep?: (milliseconds: number) => Promise<void>;
  onStatus?: (status: string) => void;
  onDebug?: (message: string) => void;
}

export async function run(
  config: ScanConfig,
  hooks: RunHooks = {},
): Promise<{ results: ScanResults; policy: PolicyResult }> {
  const client =
    hooks.client ??
    new WardenApiClient({
      token: config.token,
      baseUrl: config.baseUrl,
      debug: config.debug,
      ...(hooks.fetchImpl ? { fetchImpl: hooks.fetchImpl } : {}),
      ...(hooks.onDebug ? { logger: hooks.onDebug } : {}),
    });
  const results = await runScan(client, config, hooks);
  const policy = evaluatePolicy(results, config);
  return { results, policy };
}
