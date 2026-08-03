import { parseRepoConfig, applyRepoConfig, UNBYPASSABLE_CRITICAL_RULES } from "../src/config";
import type { Finding } from "../src/types";

describe("RepoConfig (repoguard.yml)", () => {
  describe("parseRepoConfig", () => {
    it("parses valid YAML config correctly", () => {
      const yamlContent = `
rules:
  workflow-unpinned-action: off
  hardcoded-secret: warn
ignore:
  paths:
    - docs/
    - examples/
severity:
  minimum: high
whitelist:
  patterns:
    - "sk-test-*"
`;
      const config = parseRepoConfig(yamlContent);
      expect(config.rules?.["workflow-unpinned-action"]).toBe("off");
      expect(config.rules?.["hardcoded-secret"]).toBe("warn");
      expect(config.ignore?.paths).toEqual(["docs/", "examples/"]);
      expect(config.severity?.minimum).toBe("high");
      expect(config.whitelist?.patterns).toEqual(["sk-test-*"]);
    });

    it("returns empty object on invalid or empty YAML", () => {
      expect(parseRepoConfig("")).toEqual({});
      expect(parseRepoConfig("   ")).toEqual({});
      expect(parseRepoConfig("invalid: : :")).toEqual({});
    });
  });

  describe("applyRepoConfig", () => {
    const sampleFindings: Finding[] = [
      {
        rule: "workflow-unpinned-action",
        severity: "medium",
        message: "Unpinned action",
        file: ".github/workflows/ci.yml",
      },
      {
        rule: "hardcoded-secret",
        severity: "high",
        message: "Hardcoded secret detected: sk-test-123456789",
        file: "src/config.js",
      },
      {
        rule: "curl-pipe-bash",
        severity: "critical",
        message: "curl pipe bash",
        file: "docs/install.sh",
      },
    ];

    it("disables non-critical rules configured as 'off'", () => {
      const config = { rules: { "workflow-unpinned-action": "off" as const } };
      const filtered = applyRepoConfig(sampleFindings, config);
      expect(filtered.some((f) => f.rule === "workflow-unpinned-action")).toBe(false);
      expect(filtered).toHaveLength(2);
    });

    it("PREVENTS critical malware rules from being disabled via 'off'", () => {
      const config = { rules: { "curl-pipe-bash": "off" as const } };
      const filtered = applyRepoConfig(sampleFindings, config);
      // Protected critical rules MUST NOT be disabled
      expect(filtered.some((f) => f.rule === "curl-pipe-bash")).toBe(true);
    });

    it("ignores findings matching config.ignore.paths for non-critical rules", () => {
      const nonCriticalFindings: Finding[] = [
        {
          rule: "workflow-unpinned-action",
          severity: "medium",
          message: "Unpinned action",
          file: "docs/ci.yml",
        },
      ];
      const config = { ignore: { paths: ["docs/"] } };
      const filtered = applyRepoConfig(nonCriticalFindings, config);
      expect(filtered).toHaveLength(0);
    });

    it("filters findings below minimum severity threshold for non-critical rules", () => {
      const config = { severity: { minimum: "high" as const } };
      const filtered = applyRepoConfig(sampleFindings, config);
      expect(filtered.some((f) => f.severity === "medium" && f.rule === "workflow-unpinned-action")).toBe(false);
    });

    it("filters out whitelisted patterns for non-critical findings", () => {
      const config = { whitelist: { patterns: ["sk-test-*"] } };
      const filtered = applyRepoConfig(sampleFindings, config);
      expect(filtered.some((f) => f.rule === "hardcoded-secret")).toBe(false);
    });

    it("overrides rule severity when 'warn' or explicit severity is specified", () => {
      const config = { rules: { "workflow-unpinned-action": "warn" as const } };
      const filtered = applyRepoConfig(sampleFindings, config);
      const target = filtered.find((f) => f.rule === "workflow-unpinned-action");
      expect(target?.severity).toBe("medium");
    });
  });
});
