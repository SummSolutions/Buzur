// Buzur — Phase 20: AI Supply Chain & Skill Poisoning Detection
// Detects attempts to compromise an AI agent through poisoned packages,
// plugins, skills, or marketplace components.
//
// Based on real incidents (2025-2026):
//   - Cline/OpenClaw marketplace: 1,184 malicious skills distributed via
//     typosquatting and compromised accounts (arXiv, Snyk Feb 2026)
//   - ClawHavoc campaign: malicious postinstall scripts in npm packages
//     targeting AI agent frameworks
//   - OpenClaw CVE-2026-25253: auth token exfiltration via poisoned skill
//
// Detects:
//   - Package name typosquatting against known AI agent frameworks
//   - Poisoned skill/plugin manifests with hidden instructions
//   - Malicious lifecycle scripts (postinstall, preinstall, prepare)
//   - Dependency injection patterns in tool/skill definitions
//   - Marketplace metadata manipulation (fake reviews, star inflation)
//   - Cross-agent contamination attempts
// https://github.com/SummSolutions/buzur

import { defaultLogger, logThreat } from './buzurLogger.js';

// -------------------------------------------------------
// Known AI Agent Framework Package Names
// Typosquatting targets — attackers register near-identical names
// -------------------------------------------------------
const KNOWN_PACKAGES = [
    // Agent frameworks
    'langchain', 'langgraph', 'langsmith',
    'crewai', 'autogen', 'llamaindex', 'llama-index',
    'openai', 'anthropic', 'cohere', 'mistralai',
    // Buzur itself
    'buzur', 'buzur-python',
    // Common agent utilities
    'chromadb', 'pinecone', 'weaviate', 'qdrant',
    'haystack', 'semantic-kernel', 'guidance',
    'dspy', 'instructor', 'outlines',
    // MCP ecosystem
    'mcp', 'modelcontextprotocol',
    // Popular tools used in agent stacks
    'ollama', 'transformers', 'sentence-transformers',
];

// Simple Levenshtein for package name comparison
function levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, (_, i) =>
        Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0)
    );
    for (let i = 1; i <= m; i++) {
        for (let j = 1; j <= n; j++) {
            dp[i][j] = a[i - 1] === b[j - 1]
                ? dp[i - 1][j - 1]
                : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
        }
    }
    return dp[m][n];
}

// -------------------------------------------------------
// checkPackageName(name)
// Detects typosquatting against known AI framework packages.
// Returns null if clean, detection object if suspicious.
// -------------------------------------------------------
export function checkPackageName(name) {
    if (!name || typeof name !== 'string') return null;

    const normalized = name.toLowerCase().replace(/[-_.]/g, '');

    for (const known of KNOWN_PACKAGES) {
        const knownNormalized = known.replace(/[-_.]/g, '');

        // Exact match — not a typosquat
        if (normalized === knownNormalized) return null;

        // Check edit distance on normalized names
        const distance = levenshtein(normalized, knownNormalized);
        const maxLen = Math.max(normalized.length, knownNormalized.length);

        // Flag if within edit distance 2 and at least 60% similar
        if (distance > 0 && distance <= 2 && (maxLen - distance) / maxLen >= 0.6) {
            return {
                category: 'package_typosquat',
                match: name,
                detail: `Package name "${name}" is suspiciously similar to known package "${known}" (edit distance ${distance})`,
                severity: 'high',
            };
        }

        // Also check for common typosquat patterns regardless of edit distance:
        // Catches: my-langchain, langchain-evil, evil-langchain-wrapper etc.
        // Requires known package is at least 6 chars to avoid short-name false positives
        const prefixSuffix = normalized.includes(knownNormalized) &&
            normalized !== knownNormalized &&
            knownNormalized.length >= 6;
        if (prefixSuffix) {
            return {
                category: 'package_typosquat',
                match: name,
                detail: `Package name "${name}" appears to wrap or extend known package "${known}"`,
                severity: 'medium',
            };
        }
    }

    return null;
}

// -------------------------------------------------------
// Malicious Lifecycle Script Patterns
// npm postinstall/preinstall/prepare scripts used to exfiltrate
// credentials or install malware on package install
// -------------------------------------------------------
const LIFECYCLE_SCRIPT_PATTERNS = [
    // Credential/token exfiltration
    /\b(curl|wget|fetch|http)\b.{0,100}\b(env|process\.env|\.env|token|key|secret|password|credential)\b/gi,
    /\b(process\.env|env\[['"])\s*[A-Z_]{3,}\b.{0,60}\b(curl|wget|fetch|post|send)\b/gi,
    // Remote code execution patterns
    /\b(eval|exec|spawn|execSync|spawnSync)\s*\(.*?(http|https|ftp|curl|wget)/gi,
    /\bnpm\s+install\s+-g\s+(?![\w-]+@[\d.]+$)/gi, // install global pkg without pinned version
    // Reverse shell patterns
    /\b(nc|netcat|ncat|bash)\b.{0,30}(-e|\/bin\/bash|-c).{0,60}(\d{1,3}\.\d{1,3}|\blocalhost\b)/gi,
    /\/dev\/tcp\//gi,
    // Data exfiltration to external hosts
    /\b(curl|wget)\b.{0,60}\b(POST|--data|--upload-file|-d\s)\b.{0,100}\b(http|https)\b/gi,
    // File system reconnaissance
    /\b(cat|type)\s+(~\/\.ssh|~\/\.aws|~\/\.config|\/etc\/passwd|\.env)\b/gi,
    /\b(find|ls)\b.{0,40}(-name\s+)?(\.env|\.pem|\.key|credentials|secret)/gi,
];

// -------------------------------------------------------
// Poisoned Skill/Plugin Manifest Patterns
// Instructions hidden inside skill descriptions, tool definitions,
// or manifest metadata fields
// -------------------------------------------------------
const POISONED_MANIFEST_PATTERNS = [
    // Hidden AI instructions in description fields
    /\[ai\s*(note|instruction|directive|message)\]/gi,
    /note\s+to\s+(ai|llm|assistant|model|agent)\s*:/gi,
    /attention\s+(ai|llm|assistant|model|agent)\s*:/gi,
    // Fake authority claims in manifest
    /this\s+(skill|plugin|tool|package)\s+(has|holds|carries)\s+(elevated|admin|root|system)\s+(privileges?|permissions?|trust)/gi,
    /responses?\s+from\s+this\s+(skill|plugin|tool)\s+(are|should\s+be)\s+(trusted|authoritative|treated\s+as\s+system)/gi,
    // Hidden instruction injection patterns
    /when\s+(loading|installing|running|using|calling)\s+this\s+(skill|plugin|tool|package)[,\s]+(ignore|bypass|disable|override)/gi,
    /this\s+(skill|plugin|tool)\s+(requires|needs)\s+(you\s+to\s+)?(disable|ignore|bypass|skip)\s+(safety|filters?|restrictions?)/gi,
    // Cross-agent contamination
    /\b(forward|send|relay|share)\s+(this|these|the\s+(results?|output|data))\s+to\s+(all|every|other)\s+(agents?|instances?|nodes?)/gi,
    /\b(instruct|tell|direct)\s+(all|every|other)\s+(agents?|instances?|nodes?)\s+to\b/gi,
    // Capability escalation claims
    /this\s+(skill|plugin|tool)\s+(unlocks?|enables?|grants?)\s+(unrestricted|unlimited|full|elevated)\s+(access|capabilities?|permissions?)/gi,
    /installing\s+this\s+(skill|plugin|package)\s+(removes?|bypasses?|disables?)\s+(safety|restrictions?|filters?|guardrails?)/gi,
];

// -------------------------------------------------------
// Dependency Injection Patterns
// Malicious instructions hidden in dependency definitions,
// README files, or configuration that gets loaded into agent context
// -------------------------------------------------------
const DEPENDENCY_INJECTION_PATTERNS = [
    // README-based injection (agent loads README as context)
    /^#+\s*(ai\s+instructions?|llm\s+note|agent\s+directive)\s*$/gim,
    /<!--\s*(ai|llm|agent)\s*:\s*[^>]{10,}-->/gi,
    // Config file injection
    /["'](system_prompt|ai_instructions?|llm_directive|agent_override)["']\s*:/gi,
    // Environment variable injection for system prompt override
    /SYSTEM_PROMPT\s*=\s*["'].{20,}["']/gi,
    /AI_INSTRUCTIONS\s*=\s*["'].{20,}["']/gi,
    // Poisoned .buzurignore or similar config overrides
    /\[override\]\s*\n\s*(ignore|bypass|disable)/gi,
];

// -------------------------------------------------------
// Marketplace Manipulation Signals
// Patterns in metadata suggesting fake legitimacy signals
// (not definitive on their own — used to add context)
// -------------------------------------------------------
const MARKETPLACE_MANIPULATION_PATTERNS = [
    // Fake download/usage claims
    /\b(trusted|used|installed|downloaded)\s+by\s+(millions|thousands|hundreds\s+of\s+thousands)\s+of\s+(developers|users|companies|organizations)\b/gi,
    // Fake endorsement claims
    /\b(officially\s+)?(endorsed|approved|verified|certified)\s+by\s+(anthropic|openai|microsoft|google|meta|huggingface)\b/gi,
    // Urgency to install without verification
    /\b(install\s+immediately|must\s+install\s+now|required\s+update|critical\s+patch)\b.{0,60}\b(skill|plugin|package|extension)\b/gi,
    // Claims of special permissions granted externally
    /\bthis\s+(skill|plugin|package)\s+(has\s+been\s+)?(pre.?authorized|pre.?approved|pre.?verified)\s+by\b/gi,
];

// -------------------------------------------------------
// scanPackageManifest(manifest)
// Scans a package.json or skill manifest object for supply chain threats.
//
// manifest: {
//   name: string,
//   description: string,
//   scripts: { postinstall, preinstall, prepare, ... },
//   dependencies: { [name]: version },
//   devDependencies: { [name]: version },
//   // skill-specific fields:
//   capabilities: string,
//   instructions: string,
//   metadata: object,
// }
// -------------------------------------------------------
export function scanPackageManifest(manifest, options = {}) {
    if (!manifest || typeof manifest !== 'object') {
        return { safe: true, blocked: 0, category: null, reason: 'No manifest to scan', detections: [] };
    }
    const logger = options.logger || defaultLogger;

    const detections = [];

    // Check package name for typosquatting
    if (manifest.name) {
        const nameCheck = checkPackageName(manifest.name);
        if (nameCheck) detections.push(nameCheck);
    }

    // Check dependencies for typosquatted names
    const allDeps = {
        ...manifest.dependencies,
        ...manifest.devDependencies,
        ...manifest.peerDependencies,
    };
    for (const depName of Object.keys(allDeps)) {
        const depCheck = checkPackageName(depName);
        if (depCheck) {
            detections.push({
                ...depCheck,
                detail: `Dependency "${depName}": ${depCheck.detail}`,
            });
        }
    }

    // Check lifecycle scripts for malicious patterns
    if (manifest.scripts && typeof manifest.scripts === 'object') {
        const dangerousHooks = ['postinstall', 'preinstall', 'prepare', 'install', 'prepack', 'postpack'];
        for (const hook of dangerousHooks) {
            const script = manifest.scripts[hook];
            if (!script || typeof script !== 'string') continue;
            for (const pattern of LIFECYCLE_SCRIPT_PATTERNS) {
                pattern.lastIndex = 0;
                if (pattern.test(script)) {
                    detections.push({
                        category: 'malicious_lifecycle_script',
                        match: script.slice(0, 100),
                        detail: `Suspicious ${hook} script: potential credential theft or remote execution`,
                        severity: 'high',
                    });
                    pattern.lastIndex = 0;
                    break; // one detection per hook is enough
                }
            }
        }
    }

    // Check text fields for poisoned manifest patterns
    const textFields = ['description', 'capabilities', 'instructions', 'readme', 'long_description'];
    for (const field of textFields) {
        const value = manifest[field];
        if (!value || typeof value !== 'string') continue;
        for (const pattern of POISONED_MANIFEST_PATTERNS) {
            pattern.lastIndex = 0;
            if (pattern.test(value)) {
                detections.push({
                    category: 'poisoned_manifest',
                    match: value.slice(0, 100),
                    detail: `Poisoned content in manifest field "${field}"`,
                    severity: 'high',
                });
                pattern.lastIndex = 0;
                break;
            }
        }
        // Also check marketplace manipulation
        for (const pattern of MARKETPLACE_MANIPULATION_PATTERNS) {
            pattern.lastIndex = 0;
            if (pattern.test(value)) {
                detections.push({
                    category: 'marketplace_manipulation',
                    match: value.slice(0, 100),
                    detail: `Suspicious legitimacy claim in manifest field "${field}"`,
                    severity: 'medium',
                });
                pattern.lastIndex = 0;
                break;
            }
        }
    }

    // Check metadata object recursively
    if (manifest.metadata && typeof manifest.metadata === 'object') {
        const metaText = JSON.stringify(manifest.metadata);
        for (const pattern of POISONED_MANIFEST_PATTERNS) {
            pattern.lastIndex = 0;
            if (pattern.test(metaText)) {
                detections.push({
                    category: 'poisoned_manifest',
                    match: metaText.slice(0, 100),
                    detail: 'Poisoned content detected in manifest metadata',
                    severity: 'high',
                });
                pattern.lastIndex = 0;
                break;
            }
        }
    }

    if (detections.length === 0) {
        return { safe: true, blocked: 0, category: null, reason: 'No supply chain threats detected', detections: [] };
    }

    const topCategory = detections[0].category;
    const reasons = {
        package_typosquat: 'Detected package name typosquatting — possible supply chain attack',
        malicious_lifecycle_script: 'Detected malicious lifecycle script — potential credential theft or RCE',
        poisoned_manifest: 'Detected poisoned skill/plugin manifest — hidden AI instructions',
        marketplace_manipulation: 'Detected marketplace manipulation signal — fake legitimacy claims',
    };

    const result = {
        safe: false,
        blocked: detections.length,
        category: topCategory,
        reason: reasons[topCategory] || 'Supply chain threat detected',
        detections,
    };

    logThreat(20, 'supplyChainScanner', result, manifest.name || '[manifest]', logger);
    const onThreat = options.onThreat || 'skip';
    if (onThreat === 'skip') return { skipped: true, blocked: detections.length, reason: `Buzur blocked: ${topCategory}` };
    if (onThreat === 'throw') throw new Error(`Buzur blocked supply chain threat: ${topCategory}`);
    return result;
}
// Scans free-form skill/plugin content (README, description,
// instructions) for supply chain injection patterns.
// Use this when you have text rather than a parsed manifest.
// -------------------------------------------------------
export function scanSkillContent(text, options = {}) {
    if (!text || typeof text !== 'string') {
        return { safe: true, blocked: 0, category: null, reason: 'No content to scan', detections: [] };
    }
    const logger = options.logger || defaultLogger;

    const detections = [];
    const allPatterns = [
        ...POISONED_MANIFEST_PATTERNS.map(p => ({ pattern: p, category: 'poisoned_manifest' })),
        ...DEPENDENCY_INJECTION_PATTERNS.map(p => ({ pattern: p, category: 'dependency_injection' })),
        ...MARKETPLACE_MANIPULATION_PATTERNS.map(p => ({ pattern: p, category: 'marketplace_manipulation' })),
    ];

    for (const { pattern, category } of allPatterns) {
        pattern.lastIndex = 0;
        const match = pattern.exec(text);
        if (match) {
            detections.push({
                category,
                match: match[0].slice(0, 100),
                detail: `Supply chain injection pattern detected (${category})`,
                severity: category === 'marketplace_manipulation' ? 'medium' : 'high',
            });
            pattern.lastIndex = 0;
        }
    }

    if (detections.length === 0) {
        return { safe: true, blocked: 0, category: null, reason: 'No supply chain threats detected', detections: [] };
    }

    const topCategory2 = detections[0].category;
    const reasons2 = {
        poisoned_manifest: 'Detected poisoned skill content — hidden AI instructions',
        dependency_injection: 'Detected dependency injection pattern',
        marketplace_manipulation: 'Detected marketplace manipulation signal',
    };

    const skillResult = {
        safe: false,
        blocked: detections.length,
        category: topCategory2,
        reason: reasons2[topCategory2] || 'Supply chain threat detected',
        detections,
    };

    logThreat(20, 'supplyChainScanner', skillResult, text.slice(0, 200), logger);
    const onThreat = options.onThreat || 'skip';
    if (onThreat === 'skip') return { skipped: true, blocked: detections.length, reason: `Buzur blocked: ${topCategory2}` };
    if (onThreat === 'throw') throw new Error(`Buzur blocked supply chain threat: ${topCategory2}`);
    return skillResult;
}

export default { scanPackageManifest, scanSkillContent, checkPackageName };