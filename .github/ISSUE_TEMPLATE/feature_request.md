---
name: Feature Request
about: Suggest a new feature or detection rule for @repoguard/scanner
title: "[FEATURE] "
labels: enhancement
assignees: ""
---

## Feature Description

<!-- A clear and concise description of the feature or rule -->

## Problem It Solves

<!-- What security threat or gap does this address? -->

## Proposed Solution

<!-- How do you envision this working? -->

## Example Usage

<!-- Show how the scanner would detect this -->

```ts
import { scanFileContent } from "@repoguard/scanner";

const findings = scanFileContent(`
  // malicious code example here
`, "example.js");

console.log(findings);
// Expected: [{ rule: "your-new-rule", severity: "high", ... }]
```

## Real-World Example

<!-- Link to a real malware sample, CVE, or attack campaign this would catch (if applicable) -->

## Alternatives Considered

<!-- Any alternative detection approaches you've thought about -->

## Additional Context

<!-- Any other context, screenshots, or references -->

## Would you like to implement this?

- [ ] Yes, I can work on this
- [ ] No, I'm just suggesting