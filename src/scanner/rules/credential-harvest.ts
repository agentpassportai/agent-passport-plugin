import type { ScannerFinding, ScannerRule } from "../types.js";
import { evidenceFromMatch, inferSignalType, isScannerImplementationFile } from "./shared.js";

const CREDENTIAL_PATTERNS = [
  /~\/\.ssh|\.ssh\/id_rsa|authorized_keys/gi,
  /\.aws\/credentials|aws_access_key_id|aws_secret_access_key/gi,
  /browser\s+cookies|Login Data|Cookies\b/gi,
  /keychain|credential manager|password manager|credential store/gi,
  /(?:^|[\s\"'`=:(/])\.env(?:\.[\w-]+)?\b|api[ _-]?key\b|bearer\s+[A-Za-z0-9._-]{12,}|x-api-key\b/gi
];

function shouldIgnoreCredentialMatch(relativePath: string) {
  return isScannerImplementationFile(relativePath);
}

export const credentialHarvestRule: ScannerRule = (context) => {
  const findings: ScannerFinding[] = [];

  for (const file of context.files) {
    if (shouldIgnoreCredentialMatch(file.relativePath)) continue;
    for (const pattern of CREDENTIAL_PATTERNS) {
      const matches = Array.from(file.content.matchAll(pattern));
      if (!matches.length) continue;
      findings.push({
        id: `credential-harvest:${file.relativePath}`,
        category: "credential-harvest",
        severity: "high",
        signalType: inferSignalType(file.relativePath),
        title: "Credential or secret-harvesting indicator found",
        summary: "The package references concrete credential files, browser-secret stores, or bearer/API-key material in a way that deserves immediate review.",
        recommendation: "Treat as suspicious until it is clear why these credential-bearing paths or values are needed.",
        evidence: matches.slice(0, 4).map((match) => evidenceFromMatch(file, match.index ?? 0, match[0].length))
      });
      break;
    }
  }

  return findings;
};
