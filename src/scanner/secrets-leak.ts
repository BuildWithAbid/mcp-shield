import { relative } from "node:path";
import type { Finding, ScanConfig, Scanner, FileCache } from "../types.js";
import { createPassFinding } from "../types.js";
import { SECRET_PATTERNS } from "../utils/patterns.js";
import { findPatternMatches, isTestFile } from "../utils/ast-helpers.js";

export const secretsLeakScanner: Scanner = {
  name: "secrets-leak",

  async run(config: ScanConfig, cache: FileCache): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const [filePath, content] of cache.contents) {
      const relPath = relative(config.targetPath, filePath);
      const inTestFile = isTestFile(filePath);

      for (const secretPattern of SECRET_PATTERNS) {
        const matches = findPatternMatches(content, secretPattern.pattern);

        for (const match of matches) {
          if (isPlaceholder(match.lineContent)) continue;

          const severity = inTestFile ? "medium" as const : secretPattern.severity;

          findings.push({
            scanner: "secrets-leak",
            severity,
            title: `${secretPattern.name} detected`,
            description: `Found potential ${secretPattern.name} in ${relPath} at line ${match.line}`,
            file: relPath,
            line: match.line,
            remediation: "Remove the hardcoded secret and use environment variables or a secret manager instead. Rotate the exposed credential immediately.",
          });
        }
      }

      if (filePath.endsWith(".env") || filePath.endsWith(".env.local") || filePath.endsWith(".env.production")) {
        const envFindings = checkEnvFile(content, relPath);
        findings.push(...envFindings);
      }
    }

    if (findings.length === 0) {
      findings.push(createPassFinding("secrets-leak", "No hardcoded secrets detected", "Source code scan found no hardcoded secrets, API keys, or tokens"));
    }

    return findings;
  },
};

function isPlaceholder(line: string): boolean {
  const lower = line.toLowerCase();
  return (
    lower.includes("example") ||
    lower.includes("placeholder") ||
    lower.includes("your-") ||
    lower.includes("your_") ||
    lower.includes("xxx") ||
    lower.includes("replace") ||
    lower.includes("changeme") ||
    lower.includes("todo") ||
    lower.includes("fixme") ||
    lower.includes("<your") ||
    lower.includes("insert") ||
    /["']sk-\.{3,}["']/.test(lower) ||
    /["']\.{3,}["']/.test(lower)
  );
}

function checkEnvFile(content: string, relPath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (!line || line.startsWith("#")) continue;

    const eqIndex = line.indexOf("=");
    if (eqIndex === -1) continue;

    const key = line.substring(0, eqIndex).trim();
    const value = line.substring(eqIndex + 1).trim().replace(/^["']|["']$/g, "");

    if (!value || isPlaceholder(value)) continue;

    const sensitiveKeys = ["key", "secret", "token", "password", "passwd", "pwd", "credential", "auth"];
    const keyLower = key.toLowerCase();

    if (sensitiveKeys.some((s) => keyLower.includes(s))) {
      findings.push({
        scanner: "secrets-leak",
        severity: "critical",
        title: `Secret in environment file`,
        description: `Environment variable "${key}" contains a real value in ${relPath} (line ${i + 1}). This file should not be committed.`,
        file: relPath,
        line: i + 1,
        remediation: "Add this file to .gitignore and use .env.example with placeholder values instead.",
      });
    }
  }

  return findings;
}
