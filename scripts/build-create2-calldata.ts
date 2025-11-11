import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

type CliArgs = Map<string, string>;

const args = parseArgs(process.argv.slice(2));

if (args.has("help") || args.has("h")) {
  printUsage();
  process.exit(0);
}

const saltInput = mustGet(args, "salt", "32-byte salt");
const bytecode = getBytecode(args);
const salt = normalizeSalt(saltInput);
const calldata = `0x${salt.slice(2)}${bytecode.slice(2)}`;
const outFile = args.get("out");

console.log("Salt (32 bytes):", salt);
console.log("Bytecode length :", (bytecode.length - 2) / 2, "bytes");
console.log("Calldata        :", calldata);

if (outFile) {
  const outputPath = path.resolve(process.cwd(), outFile);
  writeFileSync(outputPath, `${calldata}\n`);
  console.log("Calldata file   :", outputPath);
}

console.log("");
console.log("Example cast call:");
console.log(
  `cast send 0x4e59b44847b379578588920cA78FbF26c0B4956C --value 0 --data ${calldata} --rpc-url <rpc>`
);

function getBytecode(cliArgs: CliArgs): `0x${string}` {
  const hex = cliArgs.get("bytecode");
  if (hex) {
    return normalizeBytecode(hex);
  }

  const artifactPath =
    cliArgs.get("artifact") ??
    "artifacts/contracts/Create2Factory.sol/Create2Factory.json";
  const artifactFullPath = path.resolve(process.cwd(), artifactPath);
  const artifact = JSON.parse(readFileSync(artifactFullPath, "utf8"));
  const code: string | undefined = artifact.bytecode;

  if (!code || code === "0x") {
    throw new Error(`Artifact at ${artifactFullPath} does not contain creation bytecode`);
  }

  return normalizeBytecode(code);
}

function normalizeSalt(value: string): `0x${string}` {
  const hex = strip0x(value);
  if (hex.length > 64) {
    throw new Error("Salt longer than 32 bytes");
  }
  return `0x${hex.padStart(64, "0")}`;
}

function normalizeBytecode(value: string): `0x${string}` {
  const hex = strip0x(value);
  if (hex.length === 0 || hex.length % 2 !== 0) {
    throw new Error("Bytecode must be non-empty full bytes");
  }
  return `0x${hex}`;
}

function strip0x(value: string): string {
  return value.startsWith("0x") ? value.slice(2) : value;
}

function parseArgs(argv: string[]): CliArgs {
  const result: CliArgs = new Map();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) {
      continue;
    }
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (next && !next.startsWith("--")) {
      result.set(key, next);
      i++;
    } else {
      result.set(key, "true");
    }
  }
  return result;
}

function mustGet(args: CliArgs, key: string, label: string): string {
  const value = args.get(key);
  if (!value) {
    throw new Error(`Missing --${key} (${label})`);
  }
  return value;
}

function printUsage() {
  console.log(`Usage: tsx scripts/build-create2-calldata.ts --salt <hex> [options]

Options:
  --artifact <path>   Hardhat artifact JSON (default Create2Factory)
  --bytecode <hex>    Provide the creation bytecode directly
  --out <path>        Write calldata to a file
  --salt <hex>        32-byte salt (0x-prefixed or not)
  --help              Show this message
`);
}
