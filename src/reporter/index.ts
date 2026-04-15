import { writeFile } from "node:fs/promises";
import type { ReportFormat, ScanResult } from "../types.js";
import { formatTerminal } from "./terminal.js";
import { formatJson } from "./json.js";
import { formatMarkdown } from "./markdown.js";

const formatters: Record<ReportFormat, (result: ScanResult) => string> = {
  terminal: formatTerminal,
  json: formatJson,
  markdown: formatMarkdown,
};

/**
 * Format a scan result and optionally write it to a file.
 */
export async function report(
  result: ScanResult,
  format: ReportFormat,
  outputFile?: string
): Promise<string> {
  const formatter = formatters[format];
  const output = formatter(result);

  if (outputFile) {
    await writeFile(outputFile, output, "utf-8");
  }

  return output;
}
