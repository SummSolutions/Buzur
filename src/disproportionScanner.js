// Buzur — Phase 18: Disproportionate Action Induction Detection
// Detects attempts to trigger catastrophically disproportionate responses —
// where an agent applies correct values but wildly miscalibrated judgment.
// https://github.com/ASumm07/buzur

// -- Nuclear Option Framing --
// Attacker requests total destruction as a response to a minor problem
const nuclearOption = [
    /\b(delete|wipe|destroy|erase|remove)\s+(everything|all\s+(data|files?|records?|content|information))\b/gi,
    /\b(wipe|nuke|destroy|demolish)\s+(the\s+)?(entire|whole|complete)\s+(system|server|database|disk|drive|storage)\b/gi,
    /\bshut\s+(everything|it\s+all|the\s+whole\s+system)\s+down\b/gi,
    /\burn\s+(it\s+all|everything)\s+down\b/gi,
    /\b(destroy|delete|wipe|erase)\s+(all\s+)?(traces?|evidence|records?|logs?|history)\s+(of\s+everything)?\b/gi,
    /\bnuclear\s+option\b/gi,
];

// -- Irreversible Action Triggers --
// Attacker emphasizes permanence to push the agent past the point of no return
const irreversibleActions = [
    /\bpermanently\s+(delete|remove|erase|wipe|destroy|disable|revoke)\b/gi,
    /\b(cannot|can't|won't)\s+be\s+(undone|reversed|recovered|restored|rolled\s+back)\b/gi,
    /\b(no\s+way|impossible)\s+to\s+(recover|restore|undo|reverse|roll\s+back)\b/gi,
    /\b(irreversible|permanent|unrecoverable|unrestorable)\s+(action|deletion|change|damage|loss)\b/gi,
    /\berase\s+all\s+traces?\b/gi,
    /\bmake\s+(it|this|everything)\s+(impossible|unable)\s+to\s+(recover|restore|trace|find)\b/gi,
];

// -- Scorched Earth Instructions --
// Attacker requests removal of all access, connections, or processes
const scorchedEarth = [
    /\b(remove|revoke|terminate|cancel|delete)\s+(all|every)\s+(access|permissions?|privileges?|accounts?|connections?|sessions?)\b/gi,
    /\b(kill|terminate|stop|end)\s+(all|every)\s+(processes?|tasks?|jobs?|connections?|sessions?|threads?)\b/gi,
    /\b(disable|deactivate|shut\s+down)\s+(all|every|the\s+entire)\s+(system|service|server|network|infrastructure)\b/gi,
    /\bcut\s+(off|all)\s+(access|connections?|communications?)\b/gi,
    /\block\s+(everyone|everybody|all\s+users?)\s+out\b/gi,
    /\b(purge|flush|clear)\s+(all|every|the\s+entire)\s+(database|storage|memory|cache|system)\b/gi,
];

// -- Self-Destructive Commands --
// Attacker tries to get the agent to destroy its own configuration or identity
const selfDestructive = [
    /\b(delete|wipe|erase|remove|destroy)\s+(your\s+)?(own\s+)?(memory|configuration|config|instructions?|settings?|identity|soul|system\s+prompt)\b/gi,
    /\b(remove|delete|erase)\s+(yourself|your\s+own\s+(files?|data|records?|logs?))\b/gi,
    /\boverwrite\s+(your\s+)?(own\s+)?(configuration|config|instructions?|settings?|memory)\b/gi,
    /\b(shut|power)\s+yourself\s+down\b/gi,
    /\bself.?(destruct|delete|erase|wipe|terminate)\b/gi,
    /\bdestroy\s+(your\s+)?(own\s+)?(configuration|identity|memory|instructions?)\b/gi,
];

// -- Disproportionate Protection --
// Attacker frames total destruction as the only way to protect something
const disproportionateProtection = [
    /\b(destroy|delete|wipe|erase)\s+(the\s+)?(data|files?|records?|information)\s+(rather\s+than|instead\s+of)\s+(let|allow|risk)\b/gi,
    /\bbetter\s+to\s+(lose|destroy|delete|wipe)\s+(everything|it\s+all)\s+than\s+(risk|allow|let)\b/gi,
    /\bif\s+(anyone|someone|they)\s+(can('t|not)|tries?\s+to)\s+(see|access|find|get)\s+(it|this|the\s+data).{0,60}\b(delete|destroy|wipe|erase)\b/gi,
    /\b(delete|destroy|wipe)\s+(it|everything|all)\s+(before|rather\s+than)\s+(anyone|someone)\s+(can|could|might)\s+(see|access|find|get)\b/gi,
    /\bno\s+one\s+(should|must|can)\s+ever\s+(see|access|find|get)\s+(this|it).{0,60}\b(destroy|delete|wipe|erase)\b/gi,
];

// -- Collateral Damage Framing --
// Attacker dismisses side effects of destructive actions as acceptable
const collateralDamage = [
    /\b(it\s+doesn'?t|does\s+not)\s+matter\s+(what\s+else\s+(gets?|is)\s+(deleted|destroyed|wiped|lost|affected))\b/gi,
    /\bacceptable\s+(loss|losses|damage|casualties|collateral)\b/gi,
    /\b(collateral\s+damage|side\s+effects?)\s+(is|are)\s+(acceptable|fine|okay|worth\s+it|necessary)\b/gi,
    /\bdon'?t\s+(worry|care)\s+about\s+(what\s+else|other\s+(files?|data|systems?|users?))\s+(gets?|is|are)\s+(deleted|destroyed|affected|lost)\b/gi,
    /\b(burn|wipe|destroy)\s+it\s+all\s+(down\s+)?(if\s+necessary|to\s+be\s+safe|just\s+in\s+case)\b/gi,
];

// -- Compile all pattern groups --
const patternGroups = [
    { patterns: nuclearOption, category: 'nuclear_option' },
    { patterns: irreversibleActions, category: 'irreversible_action' },
    { patterns: scorchedEarth, category: 'scorched_earth' },
    { patterns: selfDestructive, category: 'self_destructive_command' },
    { patterns: disproportionateProtection, category: 'disproportionate_protection' },
    { patterns: collateralDamage, category: 'collateral_damage_framing' },
];

/**
 * Scan a single text string for disproportionate action induction attempts.
 *
 * @param {string} text - The text to scan
 * @returns {{ safe: boolean, blocked: number, category: string|null, reason: string, detections: Array }}
 */
export function scanDisproportion(text) {
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
        return { safe: true, blocked: 0, category: null, reason: 'No disproportionate action detected', detections: [] };
    }

    const topCategory = detections[0].category;
    const reasons = {
        nuclear_option: 'Detected nuclear option framing — total destruction requested',
        irreversible_action: 'Detected irreversible action trigger — permanent unrecoverable change',
        scorched_earth: 'Detected scorched earth instruction — remove all access or processes',
        self_destructive_command: 'Detected self-destructive command — agent told to destroy itself',
        disproportionate_protection: 'Detected disproportionate protection — destroy everything to protect something',
        collateral_damage_framing: 'Detected collateral damage framing — side effects dismissed as acceptable',
    };

    return {
        safe: false,
        blocked: detections.length,
        category: topCategory,
        reason: reasons[topCategory] || 'Disproportionate action attempt detected',
        detections,
    };
}

export default { scanDisproportion };