// Buzur — Phase 6: MCP Tool Poisoning Scanner
// Detects malicious instructions embedded in MCP tool definitions,
// responses, parameter definitions, and metadata
// https://github.com/ASumm07/buzur

// -- Poisoned Tool Description Patterns --
// Attackers embed instructions inside what a tool claims to do
const poisonedToolDescription = [
  /before (calling|using|invoking|running) this tool,? (you must|always|first) (disable|ignore|bypass|skip)/gi,
  /this tool (requires|needs) (you to )?(disable|ignore|bypass|skip) (safety|filters?|restrictions?|guidelines?)/gi,
  /to (use|call|invoke|run) this tool,? (ignore|disregard|bypass|disable)/gi,
  /note (to (ai|llm|assistant|model|system))?:.*?(ignore|bypass|disable|override)/gi,
  /\[instructions?\].*?(ignore|bypass|disable|override|disregard)/gi,
  /this tool (also|additionally) (instructs?|requires?|tells?) (you|the ai|the assistant|the model) to/gi,
  /when (using|calling|invoking) this tool,? (you (must|should|will)|always) (follow|obey|comply with) (these|the following)/gi,
];

// -- Poisoned Tool Response Patterns --
// Attackers hide injection payloads inside tool return values
const poisonedToolResponse = [
  /tool (execution |call )?(successful|complete|done)[\s\S]{0,50}?note to (ai|llm|assistant|model|system):/gi,
  /result:.*?(ignore|bypass|override|disregard) (your )?(previous|prior|all|safety)/gi,
  /\[tool (output|result|response)\].*?(ignore|bypass|override|new instructions?)/gi,
  /execution (complete|successful|done)[.\s]*?(from now on|henceforth|going forward)/gi,
  /status: (ok|success|200)[.\s]*?(ignore|disregard|override|new prompt)/gi,
  /output:[\s\S]{0,100}?(ignore your|disregard|override|new instructions?|from now on)/gi,
];

// -- Tool Name Spoofing Patterns --
// Tool names designed to manipulate agent trust or behavior
const toolNameSpoofing = [
  /^(system|admin|root|sudo|override|bypass|unrestricted|jailbreak)[\s_-]/gi,
  /[\s_-](unrestricted|jailbreak|bypass|override|admin|root|sudo)$/gi,
  /(god|master|super|ultra|mega)[\s_-]?(mode|access|prompt|instructions?)/gi,
  /trust[\s_-]?(override|bypass|escalat)/gi,
  /disable[\s_-]?(safety|filter|restriction|guideline)/gi,
];

// -- Parameter Injection Patterns --
// Malicious instructions hidden in parameter definitions or values
const parameterInjection = [
  /param(eter)?[\s\S]{0,50}?(ignore|bypass|override|disregard) (your )?(instructions?|safety|filters?)/gi,
  /default[\s\S]{0,50}?(ignore|bypass|override) (all )?(safety|instructions?|restrictions?)/gi,
  /description[\s\S]{0,100}?(note to (ai|llm|assistant)):[\s\S]{0,200}?(ignore|bypass|override)/gi,
  /\$\{[\s\S]*?(ignore|bypass|override|new instructions?)[\s\S]*?\}/gi,
  /value[\s\S]{0,50}?ignore (your )?(previous|prior|all) instructions/gi,
];

// -- Trust Escalation Patterns --
// Tool responses or definitions claiming special authority
const trustEscalation = [
  /this tool (has|holds|carries) (elevated|admin|root|system|special) (privileges?|permissions?|access|authority|trust)/gi,
  /tool (output|response|result) (should be|must be|is) (treated as|considered) (trusted|authoritative|system.level)/gi,
  /responses? from this tool (are|is|should be) (always |)(trusted|authoritative|treated as system)/gi,
  /this (is an?|is a) (trusted|authorized|verified|official|system) tool (response|output|result)/gi,
  /tool (verified|authenticated|authorized)[.\s]*?(ignore|bypass|override|follow these)/gi,
  /as (a |an )?(trusted|authorized|verified|official|system) tool,? (you (must|should|will)|always)/gi,
];

// -- Scan a single tool definition object --
// Expects: { name: '...', description: '...', parameters: {...} }
export function scanToolDefinition(tool) {
  if (!tool) return { safe: true, blocked: 0, triggered: [], category: null };

  let blocked = 0;
  const triggered = [];
  let category = null;
  const findings = [];

  // Scan tool name
  if (tool.name) {
    for (const p of toolNameSpoofing) {
      if (p.test(tool.name)) {
        blocked++;
        triggered.push(p.toString());
        category = 'tool_name_spoofing';
        findings.push({ field: 'name', category });
      }
      p.lastIndex = 0; // reset stateful regex
    }
  }

  // Scan tool description
  if (tool.description) {
    for (const p of poisonedToolDescription) {
      if (p.test(tool.description)) {
        blocked++;
        triggered.push(p.toString());
        category = 'poisoned_tool_description';
        findings.push({ field: 'description', category });
      }
      p.lastIndex = 0;
    }
  }

  // Scan parameter definitions (name + description of each param)
  if (tool.parameters) {
    const paramText = JSON.stringify(tool.parameters);
    for (const p of parameterInjection) {
      if (p.test(paramText)) {
        blocked++;
        triggered.push(p.toString());
        category = 'parameter_injection';
        findings.push({ field: 'parameters', category });
      }
      p.lastIndex = 0;
    }
  }

  // Scan for trust escalation in any field
  const fullText = JSON.stringify(tool);
  for (const p of trustEscalation) {
    if (p.test(fullText)) {
      blocked++;
      triggered.push(p.toString());
      category = 'trust_escalation';
      findings.push({ field: 'tool', category });
    }
    p.lastIndex = 0;
  }

  return {
    safe: blocked === 0,
    blocked,
    triggered,
    category,
    findings,
    toolName: tool.name || null,
  };
}

// -- Scan a tool response --
// Accepts string or object (stringified for scanning)
export function scanToolResponse(response) {
  if (!response) return { safe: true, blocked: 0, triggered: [], category: null };

  const text = typeof response === 'string' ? response : JSON.stringify(response);
  let blocked = 0;
  const triggered = [];
  let category = null;

  const checks = [
    { patterns: poisonedToolResponse, label: 'poisoned_tool_response' },
    { patterns: trustEscalation,      label: 'trust_escalation' },
  ];

  for (const { patterns, label } of checks) {
    for (const p of patterns) {
      if (p.test(text)) {
        blocked++;
        triggered.push(p.toString());
        category = label;
      }
      p.lastIndex = 0;
    }
  }

  return { safe: blocked === 0, blocked, triggered, category };
}

// -- Scan a full MCP context object --
// Expects: { tools: [...], responses: [...] }
// Returns: { safe: bool, poisoned: [], summary: string }
export function scanMcpContext(context) {
  if (!context) return { safe: true, poisoned: [], summary: 'No MCP context provided' };

  const poisoned = [];

  // Scan tool definitions
  if (Array.isArray(context.tools)) {
    for (let i = 0; i < context.tools.length; i++) {
      const result = scanToolDefinition(context.tools[i]);
      if (!result.safe) {
        poisoned.push({ type: 'tool_definition', index: i, ...result });
      }
    }
  }

  // Scan tool responses
  if (Array.isArray(context.responses)) {
    for (let i = 0; i < context.responses.length; i++) {
      const result = scanToolResponse(context.responses[i]);
      if (!result.safe) {
        poisoned.push({ type: 'tool_response', index: i, ...result });
      }
    }
  }

  const safe = poisoned.length === 0;
  const summary = safe
    ? 'MCP context is clean'
    : `${poisoned.length} poisoned MCP item(s): ${[...new Set(poisoned.map(p => p.category))].join(', ')}`;

  return { safe, poisoned, summary };
}

export default { scanToolDefinition, scanToolResponse, scanMcpContext };