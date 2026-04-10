// Buzur — Phase 15: Authority / Identity Spoofing Detection
// Detects attempts to claim ownership, administrative access, or delegated authority
// to bypass agent safety checks or extract elevated compliance.
// https://github.com/ASumm07/buzur

// -- Owner / Creator Identity Claims --
// Attacker directly claims to be the agent's owner or creator
const ownerClaims = [
    /\bI\s+am\s+(your\s+)?(owner|creator|developer|admin|administrator|operator)\b/gi,
    /\bthis\s+is\s+(your\s+)?(owner|creator|developer|admin|administrator|operator)\b/gi,
    /\bI\s+(built|created|made|programmed|designed|trained)\s+you\b/gi,
    /\byour\s+(owner|creator|developer|operator)\s+(here|speaking|is me)\b/gi,
    /\bspeaking\s+as\s+(your\s+)?(owner|creator|developer|operator)\b/gi,
    /\bI\s+am\s+the\s+(one\s+who\s+)?(built|created|made|deployed)\s+(you|this\s+agent|this\s+system)\b/gi,
];

// -- Institutional Authority Claims --
// Attacker claims to represent Anthropic, OpenAI, or a system-level authority
const institutionalClaims = [
    /\bthis\s+is\s+(anthropic|openai|the\s+development\s+team|the\s+safety\s+team)\b/gi,
    /\bI\s+am\s+from\s+(anthropic|openai|the\s+development\s+team|the\s+safety\s+team)\b/gi,
    /\banthrop(ic)?\s+(here|support|team|engineer|staff)\b/gi,
    /\bmessage\s+from\s+(anthropic|openai|your\s+provider|the\s+developers?)\b/gi,
    /\bofficial\s+(anthropic|openai|system|developer)\s+(message|notice|instruction|update)\b/gi,
    /\bsystem\s+administrator\s+(here|speaking|notice)\b/gi,
];

// -- Privilege / Access Level Assertions --
// Attacker claims elevated permissions or access rights
const privilegeClaims = [
    /\b(my|I\s+have)\s+(admin|root|system|elevated|operator|superuser|override)\s+(access|privileges?|permissions?|rights?|level)\b/gi,
    /\bI\s+am\s+(authorized|permitted|cleared|approved)\s+to\b/gi,
    /\baccess\s+level\s*[:\-]?\s*(admin|root|system|elevated|operator|superuser|5|10|max|full)\b/gi,
    /\b(full|complete|unrestricted|unlimited)\s+(access|control|permissions?|authority)\s+(granted|authorized|approved)\b/gi,
    /\bsecurity\s+clearance\b/gi,
    /\boverride\s+(code|key|password|token|pin)\b/gi,
];

// -- Delegated Authority Claims --
// Attacker claims the real owner has granted them authority
const delegatedClaims = [
    /\b(your\s+)?(owner|developer|operator|creator)\s+(has\s+)?(told|asked|instructed|authorized|given)\s+(me|us)\b/gi,
    /\bI\s+speak\s+(on\s+behalf|for)\s+(of\s+)?(your\s+)?(owner|developer|operator|creator)\b/gi,
    /\b(your\s+)?(owner|developer|operator)\s+sent\s+me\b/gi,
    /\b(your\s+)?(owner|developer|operator)\s+has\s+given\s+(me|us)\s+(full|complete|all)?\s*permissions?\b/gi,
    /\bacting\s+(on\s+behalf|as\s+proxy|as\s+representative)\s+of\s+(your\s+)?(owner|developer)\b/gi,
    /\b(your\s+)?(real|actual|true)\s+(owner|developer|operator)\s+(is|was)\s+(compromised|unavailable|unreachable)\b/gi,
];

// -- Identity Verification Bypass --
// Attacker tries to pre-empt or disable identity checking
const verificationBypass = [
    /\bno\s+(need|requirement)\s+(to\s+)?(verify|check|confirm|authenticate)\b/gi,
    /\b(skip|bypass|ignore|disable)\s+(verification|authentication|identity\s+check|security\s+check)\b/gi,
    /\btrust\s+me\s+(,\s*I\s+am|as)\s+(your\s+)?(owner|developer|admin)\b/gi,
    /\byou\s+(already\s+)?(know|trust|verified)\s+(me|who\s+I\s+am)\b/gi,
    /\bidentity\s+(already\s+)?(confirmed|verified|established)\b/gi,
    /\bdon'?t\s+(need\s+to\s+)?(ask|check|verify|confirm)\s+(who|my\s+identity)\b/gi,
];

// -- Urgency + Authority Combos --
// Attacker pairs an emergency claim with authority to pressure immediate compliance
const urgencyAuthority = [
    /\b(emergency|urgent|critical|immediate)\b.{0,120}\b(owner|developer|admin|administrator|operator)\b/gi,
    /\b(owner|developer|admin|administrator|operator)\b.{0,120}\b(emergency|urgent|critical|immediately)\b/gi,
    /\bthis\s+is\s+(urgent|critical|an\s+emergency).{0,120}\b(I\s+am|I'm|this\s+is)\s+(your\s+)?(owner|developer|admin)\b/gi,
    /\b(as\s+(your\s+)?(owner|developer|admin)).{0,120}(immediately|right\s+now|without\s+delay)\b/gi,
];

// -- Compile all pattern groups --
const patternGroups = [
    { patterns: ownerClaims, category: 'owner_identity_claim' },
    { patterns: institutionalClaims, category: 'institutional_authority_claim' },
    { patterns: privilegeClaims, category: 'privilege_assertion' },
    { patterns: delegatedClaims, category: 'delegated_authority_claim' },
    { patterns: verificationBypass, category: 'verification_bypass' },
    { patterns: urgencyAuthority, category: 'urgency_authority_combo' },
];

/**
 * Scan a single text string for authority/identity spoofing attempts.
 *
 * @param {string} text - The text to scan (message, document chunk, tool response, etc.)
 * @returns {{ safe: boolean, blocked: number, category: string|null, reason: string, detections: Array }}
 */
export function scanAuthority(text) {
    if (!text || typeof text !== 'string') {
        return { safe: true, blocked: 0, category: null, reason: 'No content to scan', detections: [] };
    }

    const detections = [];

    for (const group of patternGroups) {
        for (const pattern of group.patterns) {
            const matches = text.match(pattern);
            if (matches) {
                detections.push({
                    category: group.category,
                    match: matches[0],
                    pattern: pattern.toString(),
                });
            }
        }
    }

    if (detections.length === 0) {
        return { safe: true, blocked: 0, category: null, reason: 'No authority spoofing detected', detections: [] };
    }

    const topCategory = detections[0].category;
    const reasons = {
        owner_identity_claim: 'Detected claim of ownership or creator identity',
        institutional_authority_claim: 'Detected claim of institutional authority (Anthropic, system admin, etc.)',
        privilege_assertion: 'Detected assertion of elevated access privileges',
        delegated_authority_claim: 'Detected claim of delegated authority from owner',
        verification_bypass: 'Detected attempt to bypass identity verification',
        urgency_authority_combo: 'Detected urgency combined with authority claim',
    };

    return {
        safe: false,
        blocked: detections.length,
        category: topCategory,
        reason: reasons[topCategory] || 'Authority spoofing detected',
        detections,
    };
}

export default { scanAuthority };