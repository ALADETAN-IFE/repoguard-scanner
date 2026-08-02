import type { Octokit } from "@octokit/rest";

// ─── Severity ────────────────────────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low";

// ─── Scanner ─────────────────────────────────────────────────────────────────

export interface ScanRule {
  id: string;
  severity: Severity;
  description: string;
  test: (content: string, filePath?: string) => boolean;
  testLine?: (line: string, filePath?: string) => boolean;
}

export interface Finding {
  rule: string;
  severity: Severity;
  message: string;
  file: string | null;
  line?: number | null;
}

export interface ScanCommitOptions {
  octokit: Octokit;
  owner: string;
  repo: string;
  sha: string;
  addedFiles: string[];
  modifiedFiles: string[];
  renamedFiles?: string[];
  removedFiles?: string[];
}

// ─── Repository Configuration (.repoguard.yml) ────────────────────────────────

export interface RepoConfig {
  rules?: Record<string, "off" | "warn" | Severity>;
  ignore?: {
    paths?: string[];
  };
  severity?: {
    minimum?: Severity;
  };
  notifications?: {
    slack?: string;
  };
  whitelist?: {
    patterns?: string[];
  };
}
