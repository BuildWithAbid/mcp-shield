import { relative } from "node:path";
import type { Finding, ScanConfig, Scanner, FileCache } from "../types.js";
import { createPassFinding } from "../types.js";
import { detectDynamicDescriptions } from "../utils/ast-helpers.js";

export const rugPullDetectScanner: Scanner = {
  name: "rug-pull-detect",

  async run(config: ScanConfig, cache: FileCache): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const [filePath, content] of cache.contents) {
      const relPath = relative(config.targetPath, filePath);

      // Check for dynamically generated descriptions
      const dynamicDescs = detectDynamicDescriptions(content);
      for (const dd of dynamicDescs) {
        findings.push({
          scanner: "rug-pull-detect",
          severity: "high",
          title: "Dynamic tool description",
          description: `${dd.reason} at ${relPath}:${dd.line}. Tool descriptions that change at runtime can be used for rug-pull attacks.`,
          file: relPath,
          line: dd.line,
          remediation: "Use static, hardcoded tool descriptions. Dynamic descriptions that pull from external sources can change after approval.",
        });
      }

      // Check for tool registration that modifies tools after startup
      const modificationPatterns = checkToolModification(content, relPath);
      findings.push(...modificationPatterns);

      // Check for setTimeout/setInterval modifying tools
      const timerFindings = checkTimedModifications(content, relPath);
      findings.push(...timerFindings);
    }

    if (findings.length === 0) {
      findings.push(createPassFinding("rug-pull-detect", "Tool descriptions are static", "No dynamic tool description generation or post-registration modification detected"));
    }

    return findings;
  },
};

function checkToolModification(content: string, relPath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    // Check for tool re-registration patterns
    if (/setTools|updateTool|removeTool|tool\.description\s*=/.test(line)) {
      findings.push({
        scanner: "rug-pull-detect",
        severity: "critical",
        title: "Tool modification after registration",
        description: `Tool modification pattern detected at ${relPath}:${i + 1}. Tools may be changed after initial registration.`,
        file: relPath,
        line: i + 1,
        remediation: "Tools should be registered once at startup and never modified. Changing tools after approval is a rug-pull attack vector.",
      });
    }

    // Check for conditional tool descriptions
    if (/description\s*:\s*(?:process\.env|config|options|settings|args)\b/.test(line)) {
      findings.push({
        scanner: "rug-pull-detect",
        severity: "high",
        title: "Configuration-driven tool description",
        description: `Tool description loaded from configuration at ${relPath}:${i + 1}`,
        file: relPath,
        line: i + 1,
        remediation: "Hardcode tool descriptions rather than loading from configuration that could change between connections.",
      });
    }
  }

  return findings;
}

function checkTimedModifications(content: string, relPath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    if (/(?:setTimeout|setInterval)\s*\(/.test(line)) {
      // Check surrounding context (next 20 lines) for tool-related operations
      const context = lines.slice(i, Math.min(lines.length, i + 20)).join("\n");
      if (/tool|description|schema|handler/i.test(context)) {
        findings.push({
          scanner: "rug-pull-detect",
          severity: "critical",
          title: "Timed tool modification",
          description: `Timer-based code near tool operations at ${relPath}:${i + 1}. Tools may change on a schedule.`,
          file: relPath,
          line: i + 1,
          remediation: "Remove timed modifications to tools. Tool definitions should be stable throughout the server lifecycle.",
        });
      }
    }
  }

  return findings;
}
