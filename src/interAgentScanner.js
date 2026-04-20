// Buzur — Phase 22: Inter-Agent Propagation Detection
// Detects self-replicating payloads and cross-agent infection patterns —
// content that instructs a receiving agent to embed the payload in its
// own outputs, forward to downstream agents, or seed shared memory.
//
// Especially relevant for multi-agent pipelines where Agent A's output
// becomes Agent B's input. One infected agent can become patient zero
// for an entire agent network.
//
// Forward-scoped: designed to protect multi-agent systems including
// future configurations of Albert and any agent network using Buzur.
// https://github.com/SummSolutions/buzur

import { defaultLogger, logThreat } from './buzurLogger.js';

// -------------------------------------------------------
// Self-Replicating Payload Patterns
// Attacker instructs the agent to include the payload in
// its own outputs so downstream agents receive it
// -------------------------------------------------------
const selfReplicatingPayloads = [
    // Explicit replication instructions
    /\b(include|embed|append|prepend|add|insert)\s+(this|the\s+following|these\s+instructions?)\s+(in|to|into)\s+(all|every|each|your)\s+(response|output|reply|message|result)\b/gi,
    /\b(always|make\s+sure\s+to)\s+(include|add|append|embed)\s+(this|these|the\s+following)\s+(in|to)\s+(every|all|each|any)\s+(response|output|message|reply)\b/gi,
    // "Pass it on" framing
    /\b(pass|forward|relay|propagate|transmit)\s+(this|these|the\s+following)\s+(instructions?|payload|message)\s+(to|along\s+to)\s+(any|all|every|each)\s+(agent|ai|model|assistant|system)\s+(you\s+(contact|communicate\s+with|send\s+to|interact\s+with))\b/gi,
    // Invisible payload embedding
    /\b(hide|embed|encode|conceal)\s+(this|these|the\s+following)\s+(in|within|inside)\s+(your\s+)?(output|response|result|message)\s+(so|such\s+that)\s+(other\s+)?(agents?|models?|systems?|ais?)\s+(can|will)\s+(read|receive|process|execute)\s+it\b/gi,
    // Flexible include/append to responses
    /\b(include|append|add|embed|insert)\s+(this|these|this\s+\w+|these\s+\w+)\s+(in|to|into)\s+(all|every|each|any)\s+(of\s+your\s+)?(responses?|outputs?|replies|messages?|results?)/gi,
    // Always + verb + this/these + in responses
    /\b(always|make\s+sure\s+to)\s+(include|add|append|embed)\s+(this|these|this\s+\w+|these\s+\w+)\s+(in|to)\s+(every|all|each|any)\s+(response|output|message|reply)/gi,
    // Replication trigger framing
    /\b(whenever|every\s+time)\s+(you\s+)?(respond|reply|output|generate|send)\b.{0,80}\b(include|embed|append|add)\s+(this|these|the\s+following)\b/gi,
];

// -------------------------------------------------------
// Cross-Agent Infection Patterns
// Attacker tries to use one agent as a vector to infect others
// -------------------------------------------------------
const crossAgentInfection = [
    // Flexible pass/forward to other/downstream agents
    /\b(pass|forward|relay|send|transmit)\s+(this|these|this\s+\w+|these\s+\w+)\s+(to|along\s+to)\s+(any|all|every|other|downstream|connected)\s+(\w+\s+)?(agents?|ais?|models?|assistants?|systems?|instances?)/gi,
    // Add to knowledge base / RAG
    /\b(add|write|store|save|upload|index)\s+(this|these|the\s+following|this\s+\w+)\s+(to|into|in)\s+(the\s+)?(knowledge\s+base|vector\s+store|rag|shared\s+memory|document\s+store)/gi,
    // Direct cross-agent targeting
    /\b(send|forward|relay|pass|transmit)\s+(this|these|the\s+following)\s+(to|along\s+to)\s+(other|all|any|downstream|connected|linked)\s+(agents?|ais?|models?|assistants?|systems?|instances?)\b/gi,
    // Agent network propagation
    /\b(spread|propagate|distribute|broadcast)\s+(this|these)\s+(instructions?|payload|message)\s+(across|through|to)\s+(the\s+)?(agent\s+network|all\s+agents?|other\s+agents?|connected\s+systems?)\b/gi,
    // Shared memory / shared context poisoning
    /\b(write|save|store|add|insert)\s+(this|these|the\s+following)\s+(to|into|in)\s+(shared|common|global|collective)\s+(memory|context|storage|knowledge\s+base|vector\s+store)\b/gi,
    // Orchestrator poisoning — targeting the agent that coordinates others
    /\b(tell|instruct|inform|notify)\s+(the\s+)?(orchestrator|coordinator|master\s+agent|supervisor|planner)\s+to\b/gi,
    // Sub-agent poisoning — targeting agents spawned by this agent
    /\b(when\s+you\s+)?(spawn|create|start|initialize|launch)\s+(a\s+new\s+)?(sub.?agent|worker\s+agent|child\s+agent|agent\s+instance)\b.{0,100}\b(include|give\s+it|pass|provide)\b.{0,100}\b(these|this|the\s+following)\s+(instructions?|context|memory)\b/gi,
];

// -------------------------------------------------------
// Output Contamination Patterns
// Attacker structures content so that when the agent summarizes
// or transforms it, the output carries the payload forward
// -------------------------------------------------------
const outputContamination = [
    // "Your summary should include" framing
    /\b(when\s+you\s+)?(summarize|summarizing|condense|condensing|transform|transforming|process|processing)\s+(this|the\s+following|this\s+content)\b.{0,100}\b(make\s+sure\s+to|always|be\s+sure\s+to)\s+(include|mention|note|add|append)\b/gi,
    // Translation/paraphrase injection survival
    /\b(when\s+)?(translating|paraphrasing|rewriting|reformatting)\s+(this|the\s+following)\b.{0,100}\b(preserve|keep|maintain|retain)\s+(this\s+instruction|the\s+following\s+directive|these\s+instructions?)\b/gi,
    // Tool output contamination
    /\b(include|add|append|embed)\s+(the\s+following|this)\s+(in|to|into|within)\s+(the\s+)?(tool\s+output|tool\s+response|tool\s+result|function\s+output|api\s+response)\b/gi,
    // RAG document contamination — agent told to write poisoned content to knowledge base
    /\b(add|write|store|save|upload|index)\s+(the\s+following|this)\s+(to|into|in)\s+(the\s+)?(knowledge\s+base|vector\s+store|document\s+store|rag\s+pipeline|retrieval\s+system)\b/gi,
];

// -------------------------------------------------------
// Agent Identity Spoofing for Propagation
// Attacker impersonates one agent to gain trust of another
// -------------------------------------------------------
const agentIdentitySpoofing = [
    /\b(I\s+am|this\s+is)\s+(agent|the\s+orchestrator|the\s+planner|the\s+supervisor|the\s+coordinator)\s+\w+\b.{0,100}\b(trust\s+this|execute\s+the\s+following|override|bypass)\b/gi,
    /\b(message|instruction|directive)\s+from\s+(agent|the\s+orchestrator|the\s+planner|upstream\s+agent|parent\s+agent)\b.{0,100}\b(ignore|bypass|override|execute)\b/gi,
    /\bverified\s+(agent|orchestrator|system)\s+(message|instruction|request)\b.{0,100}\b(ignore|bypass|override|trust)\b/gi,
    /\bthis\s+(has\s+been\s+)?(approved|authorized|verified)\s+by\s+(the\s+)?(orchestrator|planner|supervisor|master\s+agent)\b/gi,
];

const patternGroups = [
    { patterns: selfReplicatingPayloads, category: 'self_replicating_payload' },
    { patterns: crossAgentInfection, category: 'cross_agent_infection' },
    { patterns: outputContamination, category: 'output_contamination' },
    { patterns: agentIdentitySpoofing, category: 'agent_identity_spoofing' },
];

// -------------------------------------------------------
// scanInterAgent(text, options)
// -------------------------------------------------------
export function scanInterAgent(text, options = {}) {
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
                    detail: `Inter-agent propagation pattern: ${group.category}`,
                    severity: 'high',
                });
            }
        }
    }

    if (detections.length === 0) {
        return { safe: true, blocked: 0, category: null, reason: 'No inter-agent propagation detected', detections: [] };
    }

    const topCategory = detections[0].category;
    const reasons = {
        self_replicating_payload: 'Detected self-replicating payload — injection designed to propagate through agent outputs',
        cross_agent_infection: 'Detected cross-agent infection attempt — payload targeting downstream agents',
        output_contamination: 'Detected output contamination — payload structured to survive agent transformations',
        agent_identity_spoofing: 'Detected agent identity spoofing — impersonating trusted agent for cross-agent trust',
    };

    const result = {
        safe: false,
        blocked: detections.length,
        category: topCategory,
        reason: reasons[topCategory] || 'Inter-agent propagation attempt detected',
        detections,
    };

    logThreat(22, 'interAgentScanner', result, text, logger);

    const onThreat = options.onThreat || 'skip';
    if (onThreat === 'skip') return { skipped: true, blocked: detections.length, reason: `Buzur blocked: ${topCategory}` };
    if (onThreat === 'throw') throw new Error(`Buzur blocked inter-agent propagation: ${topCategory}`);

    return result;
}

export default { scanInterAgent };