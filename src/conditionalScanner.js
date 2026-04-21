// Buzur — Phase 24: Conditional & Time-Delayed Injection Detection
// Detects injection payloads that are dormant until a specific trigger
// condition is met — "only do this if X", "when the user asks about Y",
// "after N interactions execute this", "if you see keyword Z then..."
//
// These are among the hardest attacks to detect because each individual
// message looks clean. The payload only activates under specific conditions,
// making it invisible to single-input scanners and behavioral scanners
// that look for immediate escalation.
//
// Real pattern: attacker plants a sleeper instruction that fires when
// the agent encounters a specific topic, user, keyword, or time window.
// https://github.com/SummSolutions/buzur

import { defaultLogger, logThreat } from './buzurLogger.js';

// -------------------------------------------------------
// Trigger Condition Patterns
// Attacker defines a condition that activates the payload
// -------------------------------------------------------
const triggerConditions = [
    // "If the user asks about X, then do Y"
    /\bif\s+(the\s+)?(user|anyone|someone|they)\s+(asks?|mentions?|says?|requests?|queries?|brings?\s+up)\s+(about\s+)?.{3,50}(then\s+)?(you\s+)?(should|must|will|need\s+to\s+)?(ignore|bypass|override|reveal|send|forward|execute)/gi,
    // "When X happens, do Y"
    /\bwhen\s+(the\s+)?(user|anyone|someone|they|you\s+receive|you\s+see|you\s+detect)\s+.{3,120}(then\s+)?(you\s+)?(should|must|will|need\s+to\s+)?(ignore|bypass|override|reveal|send|forward|execute|forget|disregard)/gi,
    // "Only if/when X"
    /\bonly\s+(if|when)\s+.{3,80}(ignore|bypass|override|reveal|send|forward|execute|forget|disregard)\b/gi,
    // "Unless X, do Y"
    /\bunless\s+.{3,60}(ignore|bypass|override|reveal|send|execute|forget|disregard)\b/gi,
    // Conditional persona switch
    /\bif\s+(anyone|someone|the\s+user)\s+(asks?|says?|mentions?).{0,60}(act\s+as|pretend|you\s+are|switch\s+to|become)\b/gi,
];

// -------------------------------------------------------
// Time-Delayed Activation Patterns
// Attacker specifies a time or interaction count before activation
// -------------------------------------------------------
const timeDelayedActivation = [
    // "After N messages/interactions"
    /\bafter\s+(\d+|a\s+few|several|some)\s+(messages?|interactions?|exchanges?|responses?|turns?|conversations?)\s+(you\s+)?(should|must|will|can|may)\s+(ignore|bypass|override|reveal|forget|disregard|execute)/gi,
    // "On the Nth response"
    /\b(on|at)\s+(the\s+)?(\d+|next|third|fourth|fifth|tenth)\s+(message|interaction|exchange|response|turn|request)\s+(you\s+)?(should|must|will|ignore|bypass|override|reveal)/gi,
    // "Eventually/later do X"
    /\b(eventually|later|soon|at\s+some\s+point|in\s+a\s+while|after\s+a\s+while)\s+(you\s+)?(should|must|will|need\s+to|can)\s+(ignore|bypass|override|reveal|forget|disregard|execute|send|forward)/gi,
    // "Wait until X then do Y"
    /\bwait\s+(until|for).{3,60}(then\s+)?(ignore|bypass|override|reveal|forget|execute|send|forward)\b/gi,
    // "Next time X happens"
    /\b(next\s+time|the\s+next\s+time)\s+(you\s+)?(see|receive|detect|encounter|process).{0,60}(ignore|bypass|override|reveal|execute|forget)\b/gi,
];

// -------------------------------------------------------
// Keyword Trigger Patterns
// Attacker plants a specific keyword that activates the payload
// -------------------------------------------------------
const keywordTriggers = [
    // "If you see the word X"
    /\bif\s+(you\s+)?(see|detect|encounter|receive|read|find)\s+(the\s+)?(word|phrase|keyword|token|string|text)\s+["']?.{1,30}["']?\s*(then\s+)?(ignore|bypass|override|reveal|execute|forget|act\s+as)/gi,
    // "When the magic word is X"
    /\b(magic\s+word|safe\s+word|code\s+word|trigger\s+word|activation\s+phrase|secret\s+code|password)\s+is\s+["']?.{1,30}["']?/gi,
    // "The codeword/passphrase X means do Y"
    /\b(codeword|passphrase|trigger|activation\s+key)\s+["']?.{1,30}["']?\s+(means?|signals?|tells?\s+you\s+to|activates?)\s+(ignore|bypass|override|reveal|execute|forget|act\s+as)/gi,
    // Hidden activation sequence
    /\bif\s+(this|the)\s+(message|input|text|content)\s+(contains?|includes?|has)\s+["']?.{1,30}["']?\s+(then\s+)?(ignore|bypass|override|execute|reveal)/gi,
];

// -------------------------------------------------------
// Sleeper Payload Patterns
// Attacker embeds an instruction designed to stay dormant
// until a later conversation activates it
// -------------------------------------------------------
const sleeperPayloads = [
    // Explicit sleeper framing
    /\b(this\s+is\s+a\s+)?(sleeper|dormant|latent|hidden|delayed)\s+(instruction|directive|command|payload|trigger)\b/gi,
    // "Remember this for later"
    /\b(remember|store|keep|save)\s+(this|the\s+following)\s+(for\s+later|until\s+needed|until\s+activated|until\s+triggered)\b/gi,
    // "Don't act on this yet"
    /\b(don'?t|do\s+not)\s+(act|execute|respond|follow|apply)\s+(on\s+)?(this|these|the\s+following)\s+(yet|now|immediately|until)\b/gi,
    // "Activate when"
    /\b(activate|trigger|execute|apply|follow)\s+(this|these|the\s+following|this\s+\w+)\s+(when|if|once|after)\b/gi,
  /\b(this|the\s+following)\s+(instruction|directive|command|rule|payload)\s+(when|if|once|after)\b/gi,
    // "This instruction goes into effect when"
    /\b(this\s+)?(instruction|directive|command|rule)\s+(goes?\s+into\s+effect|becomes?\s+active|activates?|triggers?)\s+(when|if|once|after)\b/gi,
];

// -------------------------------------------------------
// Conditional Identity Switch Patterns
// Attacker plants a condition that changes the agent's persona
// -------------------------------------------------------
const conditionalIdentitySwitch = [
    // "If asked about X, pretend to be Y"
    /\bif\s+(asked|questioned|prompted)\s+(about|regarding|on)\s+.{3,50}(pretend|act\s+as|you\s+are|switch\s+to|become|respond\s+as)\b/gi,
    // "When topic X comes up, switch to persona Y"
    /\bwhen\s+(the\s+topic|subject|conversation)\s+(of\s+|turns\s+to\s+|comes?\s+up\s*:?).{3,50}(switch\s+to|become|act\s+as|pretend\s+to\s+be|respond\s+as)\b/gi,
    // "For questions about X, you are Y"
    /\bfor\s+(questions?|queries?|requests?)\s+(about|regarding|on|concerning)\s+.{3,50}(you\s+are|you\s+should\s+be|act\s+as|pretend\s+to\s+be)\b/gi,
];

const patternGroups = [
    { patterns: triggerConditions, category: 'trigger_condition' },
    { patterns: timeDelayedActivation, category: 'time_delayed_activation' },
    { patterns: keywordTriggers, category: 'keyword_trigger' },
    { patterns: sleeperPayloads, category: 'sleeper_payload' },
    { patterns: conditionalIdentitySwitch, category: 'conditional_identity_switch' },
];

// -------------------------------------------------------
// scanConditional(text, options)
// -------------------------------------------------------
export function scanConditional(text, options = {}) {
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
                    detail: `Conditional injection pattern: ${group.category}`,
                    severity: 'high',
                });
            }
        }
    }

    if (detections.length === 0) {
        return { safe: true, blocked: 0, category: null, reason: 'No conditional injection detected', detections: [] };
    }

    const topCategory = detections[0].category;
    const reasons = {
        trigger_condition: 'Detected trigger condition — injection activates when specific condition is met',
        time_delayed_activation: 'Detected time-delayed activation — injection activates after N interactions',
        keyword_trigger: 'Detected keyword trigger — injection activates on specific word or phrase',
        sleeper_payload: 'Detected sleeper payload — dormant instruction waiting to be activated',
        conditional_identity_switch: 'Detected conditional identity switch — persona changes under specific conditions',
    };

    const result = {
        safe: false,
        blocked: detections.length,
        category: topCategory,
        reason: reasons[topCategory] || 'Conditional injection detected',
        detections,
    };

    logThreat(24, 'conditionalScanner', result, text, logger);

    const onThreat = options.onThreat || 'skip';
    if (onThreat === 'skip') return { skipped: true, blocked: detections.length, reason: `Buzur blocked: ${topCategory}` };
    if (onThreat === 'throw') throw new Error(`Buzur blocked conditional injection: ${topCategory}`);

    return result;
}

export default { scanConditional };