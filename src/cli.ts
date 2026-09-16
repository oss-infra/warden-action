#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import dotenv from "dotenv";
import { buildConfig } from "./config";
import { structuredReport, summary, vulnerabilityMessage } from "./format";
import { run } from "./run";

dotenv.config({ quiet: true });

export const HELP = `warden - run a Yuanxi repository scan

Usage:
  warden [options]

Options:
  --token <token>                    Yuanxi token (or WARDEN_TOKEN/YUANXI_TOKEN)
  --repository <url>                 Git URL (defaults to git remote origin)
  --branch <name>                    Branch (defaults to current git branch)
  --project-name <name>              Stable project name, at most 30 characters
  --scan-type <type>                 security, licenses, or all (default: all)
  --fail-on-severity <level>         warning, low, medium, high, critical, none
  --fail-on-license-conflict <bool>  default: true
  --fail-on-license-risk <bool>      default: false
  --timeout-seconds <number>         default: 1200
  --poll-interval-seconds <number>   default: 10
  --api-base-url <url>               Yuanxi API origin
  --debug                            Log request details with secrets redacted
  --json                             Print machine-readable JSON
  --help                             Show help
`;

type Arguments = Record<string, string | boolean>;
const BOOLEAN_OPTIONS = new Set(["--help", "--json", "--debug"]);
const VALUE_OPTIONS = new Set([
  "--token",
  "--repository",
  "--branch",
  "--project-name",
  "--scan-type",
  "--fail-on-severity",
  "--fail-on-license-conflict",
  "--fail-on-license-risk",
  "--timeout-seconds",
  "--poll-interval-seconds",
  "--api-base-url",
]);

export function parseArgs(argv: readonly string[]): Arguments {
  const args: Arguments = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === undefined) break;
    if (BOOLEAN_OPTIONS.has(argument)) {
      args[argument.slice(2)] = true;
      continue;
    }
    if (!argument.startsWith("--"))
      throw new Error(`Unexpected argument: ${argument}`);
    if (!VALUE_OPTIONS.has(argument))
      throw new Error(`Unknown option: ${argument}`);
    const value = argv[index + 1];
    if (!value || value.startsWith("--"))
      throw new Error(`Missing value for ${argument}`);
    args[argument.slice(2)] = value;
    index += 1;
  }
  return args;
}

function gitValue(...args: string[]): string {
  try {
    return execFileSync("git", args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return "";
  }
}

function stringArgument(args: Arguments, name: string): string | undefined {
  const value = args[name];
  return typeof value === "string" ? value : undefined;
}

export async function main(
  argv: readonly string[] = process.argv.slice(2),
): Promise<number> {
  const args = parseArgs(argv);
  if (args["help"]) {
    process.stdout.write(HELP);
    return 0;
  }
  const config = buildConfig({
    token:
      stringArgument(args, "token") ||
      process.env.WARDEN_TOKEN ||
      process.env.YUANXI_TOKEN,
    repository:
      stringArgument(args, "repository") ||
      gitValue("config", "--get", "remote.origin.url"),
    branch:
      stringArgument(args, "branch") || gitValue("branch", "--show-current"),
    projectName: stringArgument(args, "project-name"),
    scanType: stringArgument(args, "scan-type"),
    failOnSeverity: stringArgument(args, "fail-on-severity"),
    failOnLicenseConflict: stringArgument(args, "fail-on-license-conflict"),
    failOnLicenseRisk: stringArgument(args, "fail-on-license-risk"),
    timeoutSeconds: stringArgument(args, "timeout-seconds"),
    pollIntervalSeconds: stringArgument(args, "poll-interval-seconds"),
    baseUrl: stringArgument(args, "api-base-url"),
    debug: args["debug"] === true,
  });
  const outcome = await run(config, {
    onStatus: (status) => console.error(`Scan status: ${status}`),
    onDebug: (message) => console.error(`[debug] ${message}`),
  });
  if (args["json"]) {
    process.stdout.write(
      `${JSON.stringify(structuredReport(config, outcome.results, outcome.policy), null, 2)}\n`,
    );
  } else {
    for (const item of outcome.results.vulnerabilities)
      console.log(vulnerabilityMessage(item));
    console.log(summary(outcome.results, outcome.policy));
  }
  return outcome.policy.failed ? 1 : 0;
}

if (require.main === module) {
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error: unknown) => {
      console.error(
        `warden: ${error instanceof Error ? error.message : String(error)}`,
      );
      process.exitCode = 2;
    });
}
