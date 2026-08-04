// Everything a consumer needs
export {
  scanFileContent,
  scanWorkflowContent,
  scanCommit,
  scanFileContentWithConfig,
  scanWorkflowContentWithConfig,
} from "./scanner";
export { parseRepoConfig, applyRepoConfig, UNBYPASSABLE_CRITICAL_RULES } from "./config";
export { shouldSkipPath } from "./utils/skipPaths";
export { isBinaryPath, looksLikeJavaScript } from "./utils/binaryPath";
export { removeMalwareArtifactIgnoreLines } from "./scanner/malwareArtifacts";
export { KNOWN_NPM_TYPOSQUATS, KNOWN_PYPI_TYPOSQUATS } from "./scanner/typosquat";
export type { Finding, ScanRule, RepoConfig, Severity, ScanCommitOptions } from "./types";
