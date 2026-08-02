import yaml from "js-yaml";
import type { Finding, RepoConfig, Severity } from "../types";

const SEVERITY_LEVELS: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/**
 * Critical malware & remote code execution rules that CANNOT be disabled
 * via .repoguard.yml. This prevents malicious PRs from disabling detection
 * rules to sneak malware past RepoGuard.
 */
export const UNBYPASSABLE_CRITICAL_RULES = new Set([
  "curl-pipe-bash",
  "wget-pipe-shell",
  "reverse-shell",
  "obfuscated-base64",
  "obfuscated-malware-pattern",
  "python-exec-compile",
  "js-obfuscated-charcode",
  "js-obfuscated-constructors",
  "js-obfuscated-hex",
  "crypto-miner-keywords",
  "event-stream-malware",
  "ua-parser-js-malware",
]);

/**
 * Parses raw .repoguard.yml string into a typed RepoConfig object.
 * Returns default empty config if parsing fails or input is invalid.
 */
export function parseRepoConfig(yamlContent: string): RepoConfig {
  if (!yamlContent || typeof yamlContent !== "string") {
    return {};
  }

  try {
    const parsed = yaml.load(yamlContent);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }
    return parsed as RepoConfig;
  } catch {
    return {};
  }
}

/**
 * Applies repository-level configuration (.repoguard.yml) to a list of findings:
 * 1. Disables rules set to "off" (unless the rule is an unbypassable critical rule).
 * 2. Overrides rule severities if configured.
 * 3. Filters out findings in paths specified in config.ignore.paths (excluding critical rules).
 * 4. Filters out findings below config.severity.minimum threshold.
 * 5. Applies secret whitelist patterns.
 */
export function applyRepoConfig(findings: Finding[], config?: RepoConfig): Finding[] {
  if (!config || Object.keys(config).length === 0) {
    return findings;
  }

  const result: Finding[] = [];
  const minimumLevel = config.severity?.minimum
    ? (SEVERITY_LEVELS[config.severity.minimum] ?? 1)
    : 1;

  for (const finding of findings) {
    const isProtectedCritical = UNBYPASSABLE_CRITICAL_RULES.has(finding.rule);

    // 1. Check if rule is turned off (protected critical rules CANNOT be turned off)
    const ruleConfig = config.rules?.[finding.rule];
    if (ruleConfig === "off" && !isProtectedCritical) {
      continue;
    }

    // 2. Check path exclusions in config.ignore.paths (protected critical rules bypass path ignores)
    if (finding.file && config.ignore?.paths?.length && !isProtectedCritical) {
      const isIgnored = config.ignore.paths.some((pattern) =>
        matchesPathPattern(finding.file!, pattern),
      );
      if (isIgnored) continue;
    }

    // 3. Check whitelist patterns
    if (config.whitelist?.patterns?.length && !isProtectedCritical) {
      const isWhitelisted = config.whitelist.patterns.some((pattern) =>
        matchesWhitelistPattern(finding.message, finding.file, pattern),
      );
      if (isWhitelisted) continue;
    }

    // 4. Override severity if specified in config.rules
    let severity = finding.severity;
    if (ruleConfig) {
      if (ruleConfig === "warn") {
        severity = "medium";
      } else if (ruleConfig in SEVERITY_LEVELS) {
        severity = ruleConfig as Severity;
      }
    }

    // Protected critical rules cannot have their severity downgraded below 'high'
    if (isProtectedCritical && SEVERITY_LEVELS[severity] < SEVERITY_LEVELS.high) {
      severity = "high";
    }

    // 5. Filter out findings below minimum severity (protected critical rules ignore minimum severity filter)
    if (!isProtectedCritical && SEVERITY_LEVELS[severity] < minimumLevel) {
      continue;
    }

    result.push({
      ...finding,
      severity,
    });
  }

  return result;
}

function matchesPathPattern(filePath: string, pattern: string): boolean {
  const normalizedFile = filePath.toLowerCase().replace(/\\/g, "/");
  const normalizedPattern = pattern.toLowerCase().replace(/\\/g, "/").replace(/\/$/, "");

  if (normalizedPattern.endsWith("*")) {
    const prefix = normalizedPattern.slice(0, -1);
    return normalizedFile.startsWith(prefix);
  }

  return (
    normalizedFile === normalizedPattern ||
    normalizedFile.startsWith(normalizedPattern + "/") ||
    normalizedFile.includes("/" + normalizedPattern + "/")
  );
}

function matchesWhitelistPattern(
  message: string,
  filePath: string | null,
  pattern: string,
): boolean {
  if (!pattern) return false;
  const regexPattern = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  const regex = new RegExp(regexPattern, "i");

  return regex.test(message) || (filePath ? regex.test(filePath) : false);
}
