#!/usr/bin/env node
"use strict";

const { execFileSync } = require("node:child_process");
require("dotenv").config({ quiet: true });
const { buildConfig } = require("./config");
const { structuredReport, summary, vulnerabilityMessage } = require("./format");
const { run } = require("./run");

const HELP = `warden - run a Yuanxi repository scan

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

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (["--help", "--json", "--debug"].includes(argument)) {
      args[argument.slice(2)] = true;
      continue;
    }
    if (!argument.startsWith("--"))
      throw new Error(`Unexpected argument: ${argument}`);
    const value = argv[index + 1];
    if (!value || value.startsWith("--"))
      throw new Error(`Missing value for ${argument}`);
    args[argument.slice(2)] = value;
    index += 1;
  }
  return args;
}

function gitValue(...args) {
  try {
    return execFileSync("git", args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return "";
  }
}

async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (args.help) {
    process.stdout.write(HELP);
    return 0;
  }
  const config = buildConfig({
    token: args.token || process.env.WARDEN_TOKEN || process.env.YUANXI_TOKEN,
    repository:
      args.repository || gitValue("config", "--get", "remote.origin.url"),
    branch: args.branch || gitValue("branch", "--show-current"),
    projectName: args["project-name"],
    scanType: args["scan-type"],
    failOnSeverity: args["fail-on-severity"],
    failOnLicenseConflict: args["fail-on-license-conflict"],
    failOnLicenseRisk: args["fail-on-license-risk"],
    timeoutSeconds: args["timeout-seconds"],
    pollIntervalSeconds: args["poll-interval-seconds"],
    baseUrl: args["api-base-url"],
    debug: args.debug,
  });
  const outcome = await run(config, {
    onStatus: (status) => console.error(`Scan status: ${status}`),
    onDebug: (message) => console.error(`[debug] ${message}`),
  });
  if (args.json) {
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
    .catch((error) => {
      console.error(`warden: ${error.message}`);
      process.exitCode = 2;
    });
}

module.exports = { HELP, main, parseArgs };
