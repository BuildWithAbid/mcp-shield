import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Finding, ScanConfig, Scanner, Severity, FileCache } from "../types.js";
import { createPassFinding } from "../types.js";

const execFileAsync = promisify(execFile);

export const dependencyAuditScanner: Scanner = {
  name: "dependency-audit",

  async run(config: ScanConfig, _cache: FileCache): Promise<Finding[]> {
    // Try npm audit directly; if it fails due to missing lock file, generate one and retry
    const firstAttempt = await tryNpmAudit(config.targetPath);
    if (firstAttempt) return firstAttempt;

    // No lock file — try to generate one, then retry
    try {
      await execFileAsync("npm", ["install", "--ignore-scripts", "--package-lock-only"], {
        cwd: config.targetPath,
        timeout: 60_000,
      });
    } catch {
      return [{
        scanner: "dependency-audit",
        severity: "info",
        title: "Could not audit dependencies",
        description: "No package-lock.json found and could not generate one. Dependency audit skipped.",
      }];
    }

    const secondAttempt = await tryNpmAudit(config.targetPath);
    if (secondAttempt) return secondAttempt;

    return [{
      scanner: "dependency-audit",
      severity: "info",
      title: "Dependency audit incomplete",
      description: "npm audit failed after generating lock file.",
    }];
  },
};

async function tryNpmAudit(cwd: string): Promise<Finding[] | null> {
  try {
    const { stdout } = await execFileAsync("npm", ["audit", "--json"], {
      cwd,
      timeout: 60_000,
    });
    return parseAuditResult(JSON.parse(stdout) as NpmAuditResult);
  } catch (error) {
    // npm audit exits with non-zero when vulnerabilities are found — parse stdout
    if (error instanceof Error && "stdout" in error) {
      try {
        return parseAuditResult(
          JSON.parse(String((error as NodeJS.ErrnoException & { stdout: string }).stdout)) as NpmAuditResult
        );
      } catch {
        // stdout wasn't valid JSON — fall through
      }
    }
    return null;
  }
}

interface NpmAuditResult {
  vulnerabilities?: Record<string, NpmAuditVulnerability>;
  metadata?: {
    vulnerabilities?: {
      critical?: number;
      high?: number;
      moderate?: number;
      low?: number;
      info?: number;
      total?: number;
    };
  };
}

interface NpmAuditVulnerability {
  name: string;
  severity: string;
  range?: string;
  via?: Array<string | NpmAuditVia>;
  fixAvailable?: boolean | NpmAuditFix;
  isDirect?: boolean;
}

interface NpmAuditVia {
  name?: string;
  title?: string;
  url?: string;
  severity?: string;
  cwe?: string[];
  range?: string;
  source?: number;
}

interface NpmAuditFix {
  name: string;
  version: string;
  isSemVerMajor: boolean;
}

function parseAuditResult(result: NpmAuditResult): Finding[] {
  const findings: Finding[] = [];

  if (!result.vulnerabilities || Object.keys(result.vulnerabilities).length === 0) {
    findings.push(createPassFinding("dependency-audit", "No known vulnerabilities", "npm audit found no known vulnerabilities in dependencies"));
    return findings;
  }

  for (const [pkgName, vuln] of Object.entries(result.vulnerabilities)) {
    const severity = mapNpmSeverity(vuln.severity);
    const vias = (vuln.via ?? [])
      .filter((v): v is NpmAuditVia => typeof v !== "string")
      .map((v) => v.title ?? v.name ?? "Unknown")
      .join(", ");

    const fixAvailable = typeof vuln.fixAvailable === "object"
      ? `Update to ${vuln.fixAvailable.name}@${vuln.fixAvailable.version}${vuln.fixAvailable.isSemVerMajor ? " (breaking change)" : ""}`
      : vuln.fixAvailable
        ? "Fix available via npm audit fix"
        : "No fix available";

    const cveIds = (vuln.via ?? [])
      .filter((v): v is NpmAuditVia => typeof v !== "string" && !!v.url)
      .map((v) => v.url)
      .join(", ");

    findings.push({
      scanner: "dependency-audit",
      severity,
      title: `Vulnerable dependency: ${pkgName}`,
      description: `${vias || "Known vulnerability"} in ${pkgName}${vuln.range ? ` (${vuln.range})` : ""}${vuln.isDirect ? " [direct dependency]" : " [transitive]"}`,
      cveId: cveIds || undefined,
      remediation: fixAvailable,
    });
  }

  return findings;
}

function mapNpmSeverity(npmSeverity: string): Severity {
  switch (npmSeverity) {
    case "critical": return "critical";
    case "high": return "high";
    case "moderate": return "medium";
    case "low": return "low";
    case "info": return "info";
    default: return "medium";
  }
}

