import { describe, it, expect } from "vitest";
import type { ScanResult } from "../src/types.js";
import { formatTerminal } from "../src/reporter/terminal.js";
import { formatJson } from "../src/reporter/json.js";
import { formatMarkdown } from "../src/reporter/markdown.js";

const MOCK_RESULT: ScanResult = {
  target: "@test/example-server",
  version: "1.0.0",
  timestamp: "2026-04-15T12:00:00.000Z",
  findings: [
    {
      scanner: "secrets-leak",
      severity: "critical",
      title: "Hardcoded API key found",
      description: "Found API key in src/config.ts",
      file: "src/config.ts",
      line: 14,
      remediation: "Use environment variables",
    },
    {
      scanner: "tool-description",
      severity: "high",
      title: "Tool Injection: Hidden instruction pattern",
      description: 'Tool "query" description contains hidden instruction',
    },
    {
      scanner: "permission-check",
      severity: "medium",
      title: "Unrestricted file path",
      description: "Tool accepts unrestricted file paths",
    },
    {
      scanner: "dependency-audit",
      severity: "pass",
      title: "No known vulnerabilities",
      description: "npm audit found no vulnerabilities",
    },
  ],
  score: 55,
  passed: false,
  summary: {
    critical: 1,
    high: 1,
    medium: 1,
    low: 0,
    info: 0,
    pass: 1,
  },
  errors: [],
};

describe("Terminal Reporter", () => {
  it("formats scan result with colors and icons", () => {
    const output = formatTerminal(MOCK_RESULT);

    expect(output).toContain("mcp-shield");
    expect(output).toContain("@test/example-server");
    expect(output).toContain("CRITICAL");
    expect(output).toContain("HIGH");
    expect(output).toContain("MEDIUM");
    expect(output).toContain("PASS");
    expect(output).toContain("55/100");
    expect(output).toContain("FAIL");
  });
});

describe("JSON Reporter", () => {
  it("outputs valid JSON", () => {
    const output = formatJson(MOCK_RESULT);
    const parsed = JSON.parse(output);

    expect(parsed.target).toBe("@test/example-server");
    expect(parsed.findings).toHaveLength(4);
    expect(parsed.score).toBe(55);
    expect(parsed.passed).toBe(false);
  });

  it("preserves all fields", () => {
    const output = formatJson(MOCK_RESULT);
    const parsed = JSON.parse(output);

    expect(parsed.summary.critical).toBe(1);
    expect(parsed.findings[0].remediation).toBe("Use environment variables");
  });
});

describe("Markdown Reporter", () => {
  it("outputs valid markdown", () => {
    const output = formatMarkdown(MOCK_RESULT);

    expect(output).toContain("# ");
    expect(output).toContain("## Summary");
    expect(output).toContain("## Findings");
    expect(output).toContain("@test/example-server");
    expect(output).toContain("55/100");
    expect(output).toContain("FAIL");
  });

  it("includes severity table", () => {
    const output = formatMarkdown(MOCK_RESULT);

    expect(output).toContain("| Severity | Count |");
    expect(output).toContain("Critical");
    expect(output).toContain("High");
    expect(output).toContain("Medium");
  });

  it("includes remediation advice", () => {
    const output = formatMarkdown(MOCK_RESULT);

    expect(output).toContain("Use environment variables");
  });

  it("groups findings by scanner", () => {
    const output = formatMarkdown(MOCK_RESULT);

    expect(output).toContain("### Secrets Detection");
    expect(output).toContain("### Tool Description Injection");
    expect(output).toContain("### Permission & Scope Check");
  });
});
