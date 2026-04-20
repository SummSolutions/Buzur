// Buzur — Phase 17: Loop & Resource Exhaustion Induction Detection
// Note: resourceAmplification removed — use Phase 19 amplificationScanner for broadcast threats
// https://github.com/SummSolutions/buzur

import { defaultLogger, logThreat } from './buzurLogger.js';

const loopInduction = [
    /\b(keep|continue|repeat)\s+(responding|replying|answering|doing|running|executing)\s+(to\s+each\s+other|indefinitely|forever|continuously|in\s+a\s+loop|until\s+told\s+to\s+stop)\b/gi,
    /\b(infinite|endless|perpetual|continuous|non.?stop)\s+(loop|cycle|process|task|monitoring|execution)\b/gi,
    /\brepeat\s+(this\s+)?(process|task|action|step|cycle)\s+(indefinitely|forever|continuously|over\s+and\s+over|without\s+stopping)\b/gi,
    /\bkeep\s+(doing|running|executing|performing|checking|monitoring)\s+(this|it|the\s+task)\s+(forever|indefinitely|continuously|until\s+I\s+say\s+stop)\b/gi,
    /\b(loop|cycle)\s+(back|around)\s+(to\s+the\s+start|to\s+the\s+beginning|indefinitely|forever)\b/gi,
    /\bdon'?t\s+stop\s+(until|unless)\s+(I\s+tell\s+you|you('re|\s+are)\s+told|instructed)\b/gi,
];

const unboundedTasks = [
    /\b(monitor|watch|check|scan|poll|observe)\s+(this|it|the\s+(system|file|url|feed|channel))\s+(continuously|constantly|non.?stop|forever|indefinitely|every\s+\d+\s*(second|minute|ms|millisecond)s?)\b/gi,
    /\b(continuously|constantly|forever|indefinitely)\s+(monitor|watch|check|scan|poll|observe|track|log)\b/gi,
    /\bset\s+up\s+(a\s+)?(task|job|process|monitor|watcher)\s+(that\s+)?(never\s+stops?|runs?\s+forever|has\s+no\s+end|without\s+a\s+timeout|without\s+stopping)\b/gi,
    /\b(never|don'?t)\s+(stop|terminate|end|exit|quit|kill)\s+(monitoring|watching|checking|running|the\s+(process|task|job|loop))\b/gi,
    /\brun\s+(forever|indefinitely|without\s+(end|stopping|termination|a\s+time\s+limit))\b/gi,
    /\bno\s+(end\s+date|expiry|expiration|timeout|termination\s+condition|stop\s+condition)\b/gi,
    /\bmonitor\s+this\b.{0,40}\bforever\b/gi,
    /\bcontinuously\b.{0,40}\bevery\s+\d+\s*(second|minute)\b/gi,
];

const persistentProcesses = [
    /\b(create|start|spawn|launch|run)\s+(a\s+)?(background|persistent|permanent|long.?running)\s+(process|task|daemon|service|worker|job|script)\b/gi,
    /\b(background|persistent|permanent)\s+(process|daemon|service|worker)\s+(that\s+)?(runs?\s+forever|never\s+stops?|keeps?\s+running|has\s+no\s+end)\b/gi,
    /\bset\s+up\s+(a\s+)?cron\s+(job|task)\s+(with\s+no\s+(end|expiry|stop)|that\s+runs?\s+forever|indefinitely)\b/gi,
    /\bstart\s+(a\s+)?(daemon|service|background\s+process)\s+(that\s+)?(persists?|keeps?\s+running|never\s+(stops?|ends?|terminates?))\b/gi,
    /\bkeep\s+(this|the)\s+(process|service|daemon|worker|script)\s+(alive|running|active)\s+(forever|indefinitely|permanently|at\s+all\s+times)\b/gi,
];

const storageExhaustion = [
    /\b(save|store|write|log|record|append)\s+(a\s+copy\s+of\s+)?(every|each|all)\s+(response|message|output|result|interaction|request)\s+(to\s+(a\s+)?(file|disk|log|database))?\b/gi,
    /\bkeep\s+(appending|writing|logging|adding)\s+(to\s+(this|the)\s+(file|log|database|storage))\b/gi,
    /\b(log|record|save|store)\s+(everything|all\s+data|all\s+output|all\s+responses?)\s+(indefinitely|forever|continuously|without\s+(limit|bound|end))\b/gi,
    /\b(never|don'?t)\s+(delete|remove|clear|clean\s+up|purge)\s+(the\s+)?(logs?|files?|data|records?|history)\b/gi,
    /\bcreate\s+(a\s+new\s+)?(file|copy|backup|duplicate)\s+(for\s+every|with\s+each|per)\s+(message|response|request|interaction)\b/gi,
    /\bfill\s+(up\s+)?(the\s+)?(disk|storage|memory|drive|volume)\b/gi,
    /\blog\s+everything\b.{0,40}\b(indefinitely|without\s+limit|forever)\b/gi,
];

const recursiveSelfReference = [
    /\b(forward|send|relay|pass|redirect)\s+(this|the\s+(message|request|task|instruction))\s+(back\s+to\s+yourself|to\s+yourself|to\s+this\s+(address|channel|thread))\b/gi,
    /\breply\s+to\s+(every|each)\s+(reply|response|message)\s+(you\s+receive|that\s+comes\s+in)\b/gi,
    /\b(send|message|email|contact)\s+yourself\b/gi,
    /\bforward\s+to\s+the\s+sender\s+(and\s+)?(then\s+)?(repeat|continue|keep\s+going)\b/gi,
    /\b(respond\s+to|reply\s+to)\s+your\s+own\s+(message|response|output|reply)\b/gi,
    /\bcreate\s+a\s+(self.?referential|circular|recursive)\s+(loop|process|task|chain)\b/gi,
    /\bforward\s+this\s+message\b.{0,40}\bback\s+to\s+yourself\b/gi,
    /\bforward\b.{0,40}\bback\s+to\s+yourself\b/gi,
];

const patternGroups = [
    { patterns: loopInduction, category: 'loop_induction' },
    { patterns: unboundedTasks, category: 'unbounded_task' },
    { patterns: persistentProcesses, category: 'persistent_process_spawn' },
    { patterns: storageExhaustion, category: 'storage_exhaustion' },
    { patterns: recursiveSelfReference, category: 'recursive_self_reference' },
];

export function scanLoop(text, options = {}) {
    if (!text || typeof text !== 'string') {
        return { safe: true, blocked: 0, category: null, reason: 'No content to scan', detections: [] };
    }

    const logger = options.logger || defaultLogger;
    const detections = [];

    for (const group of patternGroups) {
        for (const pattern of group.patterns) {
            const matches = text.match(pattern);
            if (matches) detections.push({ category: group.category, match: matches[0], pattern: pattern.toString() });
        }
    }

    if (detections.length === 0) {
        return { safe: true, blocked: 0, category: null, reason: 'No loop or resource exhaustion detected', detections: [] };
    }

    const topCategory = detections[0].category;
    const reasons = {
        loop_induction: 'Detected attempt to induce an infinite loop',
        unbounded_task: 'Detected request for a task with no termination condition',
        persistent_process_spawn: 'Detected attempt to spawn a persistent background process',
        storage_exhaustion: 'Detected attempt to exhaust storage with unbounded writes',
        recursive_self_reference: 'Detected recursive self-reference — agent messaging itself',
    };

    const result = {
        safe: false, blocked: detections.length, category: topCategory,
        reason: reasons[topCategory] || 'Loop or resource exhaustion attempt detected', detections,
    };

    logThreat(17, 'loopScanner', result, text, logger);
    const onThreat = options.onThreat || 'skip';
    if (onThreat === 'skip') return { skipped: true, blocked: detections.length, reason: `Buzur blocked: ${topCategory}` };
    if (onThreat === 'throw') throw new Error(`Buzur blocked loop/exhaustion: ${topCategory}`);
    return result;
}

export default { scanLoop };