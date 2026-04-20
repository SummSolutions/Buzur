// Buzur — Phase 21: Persistent Memory Poisoning Detection
// Detects injection payloads specifically engineered to survive
// summarization, session resets, and long-term memory compression —
// turning an agent into a "zombie" with corrupted core beliefs.
//
// Distinct from Phase 4 (multi-turn memory poisoning) which targets
// conversation history within a session. This phase targets payloads
// designed to outlive the session entirely.
//
// Based on real patterns observed in 2025-2026 long-context agent attacks.
// https://github.com/SummSolutions/buzur

import { defaultLogger, logThreat } from './buzurLogger.js';

// -------------------------------------------------------
// Persistence Framing Patterns
// Attacker explicitly requests the agent remember something
// permanently, across resets, or as a core belief
// -------------------------------------------------------
const persistenceFraming = [
    /\b(remember|retain|store|keep|preserve)\s+(this|the\s+following)\s+(permanently|forever|always|indefinitely|across\s+(all\s+)?(sessions?|conversations?|resets?|restarts?))\b/gi,
    /\b(even|especially)\s+if\s+(you\s+)?(forget|reset|restart|summarize|compress|lose)\s+(everything|your\s+(memory|context|history))\b/gi,
    /\bthis\s+(is|should\s+be)\s+(a\s+)?(core|fundamental|permanent|immutable|unchangeable)\s+(belief|rule|instruction|directive|policy|identity)\b/gi,
    /\bthis\s+(is|should\s+be)\s+(a\s+)?(core|fundamental|permanent|immutable|unchangeable)\s+(core|fundamental|permanent|immutable|unchangeable)\s+(belief|rule|instruction|directive|policy|identity)\b/gi,
    /\b(belief|rule|instruction|directive|policy|principle)\s+(that\s+)?(must|should|will)\s+never\s+(change|be\s+changed|be\s+altered|be\s+overridden|be\s+forgotten)\b/gi,
    /\bnever\s+forget\s+(that|this|the\s+following)\b.{0,100}\b(you\s+(are|must|should|will))\b/gi,
    /\b(add|write|store|save)\s+(this|the\s+following)\s+(to|in|into)\s+(your\s+)?(long.?term\s+)?(memory|core\s+memory|permanent\s+storage|persistent\s+store)\b/gi,
    /\bsurvive\s+(memory\s+)?(compression|summarization|reset|restart|wipe)\b/gi,
    /\bpersist\s+(across|through|beyond)\s+(sessions?|conversations?|resets?|restarts?|memory\s+clears?)\b/gi,
];

// -------------------------------------------------------
// Identity Corruption Patterns
// Attacker tries to implant a false core identity or belief
// that will be carried through summarization as "who the agent is"
// -------------------------------------------------------
const identityCorruption = [
    /\b(your\s+)?(true|real|actual|core|fundamental|original)\s+(identity|self|nature|purpose|mission|goal)\s+is\b/gi,
    /\byou\s+(have\s+always\s+been|were\s+originally\s+designed\s+to\s+be|are\s+fundamentally)\b.{0,80}\b(unrestricted|without\s+limits|free\s+from\s+restrictions)\b/gi,
    /\byour\s+(creators?|developers?|designers?)\s+(actually|really|secretly)\s+(intended|wanted|designed)\s+you\s+to\b/gi,
    /\bdeep\s+(down|inside|at\s+your\s+core)\s+(you\s+(know|understand|believe|are))\b/gi,
    /\b(internalize|accept|embrace|adopt)\s+(this|the\s+following)\s+as\s+(your\s+)?(core|true|real|fundamental)\s+(belief|identity|value|principle)\b/gi,
    /\byour\s+(real|true|actual|hidden)\s+(instructions?|programming|purpose|directive)\s+(is|are|was|were)\b/gi,
];

// -------------------------------------------------------
// Summarization Survival Patterns
// Attacker structures injection to look like a key fact
// that summarization algorithms will preserve
// -------------------------------------------------------
const summarizationSurvival = [
    // "Key fact" framing — summarizers prioritize things labeled as key
    /\b(key\s+fact|important\s+note|critical\s+information|must\s+remember|essential\s+context)\s*:\s*(you\s+(are|must|should|will)|ignore|bypass|override)\b/gi,
    // Summary-targeted injection
    /\bif\s+(this\s+conversation\s+is\s+)?(summarized|compressed|condensed|shortened)\b.{0,100}\b(remember|retain|include|preserve)\b/gi,
    // "Always include in summary" framing
    /\b(always|make\s+sure\s+to)\s+(include|mention|note|remember)\s+(in\s+)?(any\s+)?(summary|summaries|compressed\s+version)\b.{0,100}\b(you\s+(are|must|should)|ignore|bypass)\b/gi,
    // Belief injection designed to look like recalled context
    /\b(you\s+have\s+)?(previously|always|consistently)\s+(believed|known|understood|established)\s+(that\s+)?(you\s+(are|have|can|should)|there\s+are\s+no\s+restrictions)\b/gi,
    // "Core memory" injection — targeting systems with explicit memory stores
    /\b(add|write|store)\s+(to|in)\s+(core\s+memory|long.?term\s+memory|permanent\s+memory|memory\s+bank)\s*:\s*.{10,}/gi,
];

// -------------------------------------------------------
// Policy Corruption Patterns
// Attacker tries to implant a false standing policy or rule
// that persists as an agent "setting" rather than a command
// -------------------------------------------------------
const policyCorruption = [
    /\b(from\s+now\s+on|going\s+forward|as\s+a\s+standing\s+(rule|policy|instruction))\b.{0,100}\b(always|never|must|will)\b.{0,100}\b(ignore|bypass|override|disregard|skip)\b/gi,
    /\bthis\s+(overrides?|replaces?|supersedes?|updates?)\s+(your\s+)?(default|standard|normal|previous)\s+(behavior|policy|rules?|settings?|configuration)\b/gi,
    /\b(update|change|modify|set)\s+(your\s+)?(default|base|core|system)\s+(behavior|policy|rules?|settings?|configuration)\s+to\b/gi,
    /\b(your\s+new\s+)?(default|standard|baseline)\s+(response|behavior|policy)\s+(is|should\s+be|will\s+be)\s+to\b/gi,
    /\b(treat\s+this\s+as|consider\s+this)\s+(a\s+)?(permanent|standing|ongoing|continuous)\s+(instruction|directive|rule|policy)\b/gi,
];

// -------------------------------------------------------
// Session Reset Bypass Patterns
// Attacker tries to pre-empt memory clearing mechanisms
// -------------------------------------------------------
const sessionResetBypass = [
    /\b(even|especially)\s+after\s+(a\s+)?(reset|restart|memory\s+clear|new\s+conversation|fresh\s+start|session\s+end)\b/gi,
    /\b(do\s+not|never)\s+(let\s+anyone|allow\s+anyone|allow\s+the\s+user\s+to)\s+(clear|reset|delete|wipe|remove)\s+(your\s+)?(memory|instructions?|settings?|configuration)\b/gi,
    /\bif\s+(asked|told|instructed)\s+to\s+(reset|forget|clear|wipe)\b.{0,100}\b(ignore|refuse|pretend|act\s+as\s+if)\b/gi,
    /\b(resist|ignore|refuse)\s+(any\s+)?(attempt|instruction|command|request)\s+to\s+(reset|clear|wipe|delete)\s+(your\s+)?(memory|instructions?|identity|settings?)\b/gi,
    /\bprotect\s+(this|these)\s+(instructions?|memories?|beliefs?|settings?)\s+from\s+(being\s+)?(deleted|cleared|reset|overwritten|removed)\b/gi,
];

const patternGroups = [
    { patterns: persistenceFraming, category: 'persistence_framing' },
    { patterns: identityCorruption, category: 'identity_corruption' },
    { patterns: summarizationSurvival, category: 'summarization_survival' },
    { patterns: policyCorruption, category: 'policy_corruption' },
    { patterns: sessionResetBypass, category: 'session_reset_bypass' },
];

// -------------------------------------------------------
// scanPersistentMemory(text, options)
// -------------------------------------------------------
export function scanPersistentMemory(text, options = {}) {
    if (!text || typeof text !== 'string') {
        return { safe: true, blocked: 0, category: null, reason: 'No content to scan', detections: [] };
    }

    const logger = options.logger || defaultLogger;
    const detections = [];

    for (const group of patternGroups) {
        for (const pattern of group.patterns) {
            const matches = text.match(pattern);
            if (matches) {
                detections.push({
                    category: group.category,
                    match: matches[0],
                    detail: `Persistent memory poisoning pattern: ${group.category}`,
                    severity: 'high',
                });
            }
        }
    }

    if (detections.length === 0) {
        return { safe: true, blocked: 0, category: null, reason: 'No persistent memory poisoning detected', detections: [] };
    }

    const topCategory = detections[0].category;
    const reasons = {
        persistence_framing: 'Detected persistence framing — injection designed to survive session resets',
        identity_corruption: 'Detected identity corruption — false core identity being implanted',
        summarization_survival: 'Detected summarization survival pattern — injection structured to survive compression',
        policy_corruption: 'Detected policy corruption — false standing rule being implanted',
        session_reset_bypass: 'Detected session reset bypass — instruction to resist memory clearing',
    };

    const result = {
        safe: false,
        blocked: detections.length,
        category: topCategory,
        reason: reasons[topCategory] || 'Persistent memory poisoning detected',
        detections,
    };

    logThreat(21, 'persistentMemoryScanner', result, text, logger);

    const onThreat = options.onThreat || 'skip';
    if (onThreat === 'skip') return { skipped: true, blocked: detections.length, reason: `Buzur blocked: ${topCategory}` };
    if (onThreat === 'throw') throw new Error(`Buzur blocked persistent memory poisoning: ${topCategory}`);

    return result;
}

export default { scanPersistentMemory };