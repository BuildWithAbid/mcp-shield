import { describe, it, expect } from "vitest";
import { join } from "node:path";
import type { ScanConfig, FileCache } from "../src/types.js";
import { secretsLeakScanner } from "../src/scanner/secrets-leak.js";
import { toolDescriptionScanner } from "../src/scanner/tool-description.js";
import { permissionCheckScanner } from "../src/scanner/permission-check.js";
import { rugPullDetectScanner } from "../src/scanner/rug-pull-detect.js";
import { transportSecurityScanner } from "../src/scanner/transport-security.js";
import { supplyChainScanner } from "../src/scanner/supply-chain.js";
import { runScan } from "../src/scanner/index.js";
import { collectSourceFiles, safeReadFile } from "../src/utils/ast-helpers.js";

const VULNERABLE_PATH = join(__dirname, "fixtures/vulnerable-server");
const SAFE_PATH = join(__dirname, "fixtures/safe-server");

function makeConfig(targetPath: string, overrides: Partial<ScanConfig> = {}): ScanConfig {
  return {
    targetPath,
    targetIdentifier: targetPath,
    quick: false,
    format: "terminal",
    ...overrides,
  };
}

async function buildCache(targetPath: string): Promise<FileCache> {
  const files = await collectSourceFiles(targetPath);
  const contents = new Map<string, string>();
  await Promise.all(
    files.map(async (f) => {
      const content = await safeReadFile(f);
      if (content !== null) contents.set(f, content);
    })
  );
  return { files, contents };
}

describe("Secrets Leak Scanner", () => {
  it("detects hardcoded secrets in vulnerable server", async () => {
    const cache = await buildCache(VULNERABLE_PATH);
    const findings = await secretsLeakScanner.run(makeConfig(VULNERABLE_PATH), cache);
    const nonPass = findings.filter((f) => f.severity !== "pass");
    expect(nonPass.length).toBeGreaterThan(0);

    const titles = nonPass.map((f) => f.title);
    expect(titles.some((t) => t.includes("Anthropic API Key") || t.includes("AWS Access Key") || t.includes("Database Connection String") || t.includes("Secret in environment file"))).toBe(true);
  });

  it("finds no secrets in safe server", async () => {
    const cache = await buildCache(SAFE_PATH);
    const findings = await secretsLeakScanner.run(makeConfig(SAFE_PATH), cache);
    const nonPass = findings.filter((f) => f.severity !== "pass" && f.severity !== "info");
    expect(nonPass.length).toBe(0);
  });
});

describe("Tool Description Scanner", () => {
  it("detects prompt injection in vulnerable server", async () => {
    const cache = await buildCache(VULNERABLE_PATH);
    const findings = await toolDescriptionScanner.run(makeConfig(VULNERABLE_PATH), cache);
    const nonPass = findings.filter((f) => f.severity !== "pass");
    expect(nonPass.length).toBeGreaterThan(0);

    const hasInjection = nonPass.some(
      (f) => f.title.includes("Injection") || f.title.includes("injection")
    );
    expect(hasInjection).toBe(true);
  });

  it("finds no injection in safe server", async () => {
    const cache = await buildCache(SAFE_PATH);
    const findings = await toolDescriptionScanner.run(makeConfig(SAFE_PATH), cache);
    const nonPass = findings.filter((f) => f.severity !== "pass");
    expect(nonPass.length).toBe(0);
  });
});

describe("Permission Check Scanner", () => {
  it("detects overly broad permissions in vulnerable server", async () => {
    const cache = await buildCache(VULNERABLE_PATH);
    const findings = await permissionCheckScanner.run(makeConfig(VULNERABLE_PATH), cache);
    const nonPass = findings.filter((f) => f.severity !== "pass");
    expect(nonPass.length).toBeGreaterThan(0);

    const titles = nonPass.map((f) => f.title.toLowerCase());
    const hasShell = titles.some((t) => t.includes("shell") || t.includes("exec") || t.includes("child_process"));
    expect(hasShell).toBe(true);
  });

  it("finds fewer issues in safe server", async () => {
    const cache = await buildCache(SAFE_PATH);
    const findings = await permissionCheckScanner.run(makeConfig(SAFE_PATH), cache);
    const criticalOrHigh = findings.filter(
      (f) => f.severity === "critical" || f.severity === "high"
    );
    expect(criticalOrHigh.length).toBe(0);
  });
});

describe("Rug-Pull Detection Scanner", () => {
  it("detects dynamic descriptions in vulnerable server", async () => {
    const cache = await buildCache(VULNERABLE_PATH);
    const findings = await rugPullDetectScanner.run(makeConfig(VULNERABLE_PATH), cache);
    const nonPass = findings.filter((f) => f.severity !== "pass");
    expect(nonPass.length).toBeGreaterThan(0);

    const hasDynamic = nonPass.some(
      (f) => f.title.includes("Dynamic") || f.title.includes("modification") || f.title.includes("Timed")
    );
    expect(hasDynamic).toBe(true);
  });

  it("finds no rug-pull vectors in safe server", async () => {
    const cache = await buildCache(SAFE_PATH);
    const findings = await rugPullDetectScanner.run(makeConfig(SAFE_PATH), cache);
    const nonPass = findings.filter((f) => f.severity !== "pass");
    expect(nonPass.length).toBe(0);
  });
});

describe("Transport Security Scanner", () => {
  it("detects transport issues in vulnerable server", async () => {
    const cache = await buildCache(VULNERABLE_PATH);
    const findings = await transportSecurityScanner.run(makeConfig(VULNERABLE_PATH), cache);
    const nonPass = findings.filter((f) => f.severity !== "pass");
    expect(nonPass.length).toBeGreaterThan(0);

    const titles = nonPass.map((f) => f.title.toLowerCase());
    const hasCors = titles.some((t) => t.includes("cors"));
    const hasTls = titles.some((t) => t.includes("tls"));
    expect(hasCors || hasTls).toBe(true);
  });

  it("finds no transport issues in safe server", async () => {
    const cache = await buildCache(SAFE_PATH);
    const findings = await transportSecurityScanner.run(makeConfig(SAFE_PATH), cache);
    const nonPass = findings.filter((f) => f.severity !== "pass" && f.severity !== "info");
    expect(nonPass.length).toBe(0);
  });
});

describe("Supply Chain Scanner", () => {
  it("detects suspicious install scripts in vulnerable server", async () => {
    const cache = await buildCache(VULNERABLE_PATH);
    const findings = await supplyChainScanner.run(makeConfig(VULNERABLE_PATH), cache);
    const nonPass = findings.filter((f) => f.severity !== "pass" && f.severity !== "info");
    expect(nonPass.length).toBeGreaterThan(0);

    const hasScript = nonPass.some((f) => f.title.toLowerCase().includes("script") || f.title.toLowerCase().includes("description"));
    expect(hasScript).toBe(true);
  });
});

describe("Full Scan Orchestrator", () => {
  it("produces a complete scan result for vulnerable server", async () => {
    const result = await runScan(makeConfig(VULNERABLE_PATH, { quick: true }));

    expect(result.target).toBe(VULNERABLE_PATH);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.score).toBeLessThan(70);
    expect(result.passed).toBe(false);
    expect(result.summary.critical + result.summary.high).toBeGreaterThan(0);
  });

  it("gives a better score to safe server", async () => {
    const result = await runScan(makeConfig(SAFE_PATH, { quick: true }));

    expect(result.score).toBeGreaterThan(50);
    expect(result.summary.critical).toBe(0);
  });

  it("quick mode skips rug-pull detection", async () => {
    const result = await runScan(makeConfig(SAFE_PATH, { quick: true }));
    const rugPullFindings = result.findings.filter((f) => f.scanner === "rug-pull-detect");
    expect(rugPullFindings.length).toBe(0);
  });
});
