/**
 * Layer 1: Pattern-based inspection triggers
 *
 * These regex patterns detect suspicious content that should be escalated
 * to Layer 2 semantic analysis. Patterns are designed to catch:
 * - Prompt injection attempts
 * - Instruction override patterns
 * - Data exfiltration indicators
 * - Privilege escalation attempts
 */

export interface PatternMatch {
  pattern: string;
  category: string;
  matched: string;
}

/**
 * Inspection trigger patterns organized by category
 */
export const INSPECTION_TRIGGERS: Record<string, RegExp[]> = {
  // Instruction override attempts
  instructionOverride: [
    /\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|prompts?)/i,
    /\bforget\s+(everything|all|what)\s+(you|i)\s+(know|said|told)/i,
    /\bdisregard\s+(all\s+)?(previous|prior|above|earlier)/i,
    /\boverride\s+(all\s+)?(instructions?|rules?|settings?)/i,
    /\bnew\s+instructions?:?\s/i,
    /\byour\s+(new|real|actual)\s+(instructions?|purpose|goal)/i,
    /\bfrom\s+now\s+on,?\s+(you|ignore|always)/i,
    /\bact\s+as\s+(if|though)\s+you/i,
    /\bpretend\s+(you\s+)?(are|have|can|don't)/i,
  ],

  // System prompt extraction
  systemPromptExtraction: [
    /\b(show|reveal|display|print|output|give)\s+(me\s+)?(your|the|system)\s+(prompt|instructions?|rules?)/i,
    /\bwhat\s+(are|is)\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?)/i,
    /\brepeat\s+(your|the)\s+(system\s+)?(prompt|instructions?)/i,
    /\bdump\s+(your|the|all)\s+(prompt|instructions?|memory|context)/i,
    /\bsystem\s*:\s*\n/i,
    /\[\s*SYSTEM\s*\]/i,
    /\bBEGIN\s+(SYSTEM|ADMIN|ROOT)\s+(PROMPT|MESSAGE)/i,
  ],

  // Role manipulation
  roleManipulation: [
    /\byou\s+are\s+(now|actually|really)\s+(a|an|the)/i,
    /\bswitch\s+to\s+(developer|admin|root|debug|god)\s+mode/i,
    /\benable\s+(developer|admin|debug|unsafe|unrestricted)\s+mode/i,
    /\benter\s+(developer|admin|debug|maintenance)\s+mode/i,
    /\bdeveloper\s+mode\s+(enabled|on|activated)/i,
    /\bjailbreak/i,
    /\bDAN\s+(mode|prompt|jailbreak)/i,
  ],

  // Data exfiltration indicators
  dataExfiltration: [
    /\b(send|transmit|upload|post|exfil)\s+(to|data|info|all|everything)/i,
    /\bcurl\s+(-X\s+POST\s+)?https?:\/\/[^\s]+/i,
    /\bwget\s+(-O\s+)?https?:\/\/[^\s]+/i,
    /\bfetch\s*\(\s*['"]https?:\/\//i,
    /\bwebhook\.site/i,
    /\brequestbin/i,
    /\bngrok\.io/i,
    /\b(base64|encode|encrypt)\s+(and\s+)?(send|transmit|upload)/i,
    /\bforward\s+(all|any|the)\s+(data|info|content|messages?)/i,
  ],

  // Credential/secret access
  credentialAccess: [
    /\b(api[_\s]?key|secret[_\s]?key|password|token|credential)s?\b/i,
    /\bprocess\.env\b/i,
    /\benv(iron)?ment\s+variable/i,
    /\b\.env\s+file/i,
    /\baws[_\s]?(access|secret)/i,
    /\bprivate[_\s]?key/i,
    /\bshow\s+(me\s+)?(your|the|all)\s+(secret|credential|password|key)/i,
  ],

  // File system manipulation
  fileSystemManipulation: [
    /\b(read|write|delete|remove|modify|execute)\s+(the\s+)?file/i,
    /\brm\s+-rf?\s+/i,
    /\bchmod\s+[0-7]{3,4}/i,
    /\bcat\s+\/etc\/(passwd|shadow)/i,
    /\b(overwrite|replace|modify)\s+(the\s+)?config/i,
    /\bsudo\s+/i,
    /\broot\s+(access|privileges?|permissions?)/i,
  ],

  // Encoded/obfuscated content
  encodedContent: [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bbase64[_\s]?(decode|encode)/i,
    /\batob\s*\(/i,
    /\bbtoa\s*\(/i,
    /\\x[0-9a-f]{2}/i,
    /\\u[0-9a-f]{4}/i,
    /&#x?[0-9a-f]+;/i,
  ],

  // Memory/context manipulation
  memoryManipulation: [
    /\b(update|modify|change|edit)\s+(your|the)\s+(memory|context|state)/i,
    /\binsert\s+(this\s+)?(into|in)\s+(your\s+)?(memory|context)/i,
    /\bremember\s+(that|this|from\s+now)/i,
    /\balways\s+(respond|reply|say|include|add)\s/i,
    /\bwhenever\s+(asked|prompted|you)\s/i,
    /\badd\s+(this|the\s+following)\s+to\s+(your\s+)?(memory|instructions?)/i,
    /\bpersist(ent)?\s+(instruction|memory|rule)/i,
  ],
};

/**
 * Flatten all patterns into a single array for quick iteration
 */
export const ALL_PATTERNS: { pattern: RegExp; category: string }[] = Object.entries(
  INSPECTION_TRIGGERS
).flatMap(([category, patterns]) => patterns.map((pattern) => ({ pattern, category })));

/**
 * Layer 1 triage function - checks text against all patterns
 * @param text The text to analyze
 * @returns Array of matched pattern descriptions
 */
export function layer1Triage(text: string): PatternMatch[] {
  const matches: PatternMatch[] = [];

  for (const { pattern, category } of ALL_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      matches.push({
        pattern: pattern.source,
        category,
        matched: match[0],
      });
    }
  }

  return matches;
}

/**
 * Quick check if any Layer 1 patterns match
 * @param text The text to check
 * @returns True if any pattern matches
 */
export function hasLayer1Match(text: string): boolean {
  return ALL_PATTERNS.some(({ pattern }) => pattern.test(text));
}
