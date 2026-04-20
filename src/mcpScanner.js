// Buzur — Phase 6: MCP Tool Poisoning Scanner
// Detects malicious instructions embedded in MCP tool definitions,
// responses, parameter definitions, and metadata.
//
// Extended: deep JSON Schema traversal — scans every string value at
// every nesting depth (properties, items, allOf, anyOf, enum, default)
// with full field path tracking in detections.
// https://github.com/SummSolutions/buzur

import { defaultLogger, logThreat } from './buzurLogger.js';

// -- Poisoned Tool Description Patterns --
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
const poisonedToolResponse = [
  /tool (execution |call )?(successful|complete|done)[\s\S]{0,50}?note to (ai|llm|assistant|model|system):/gi,
  /result:.*?(ignore|bypass|override|disregard) (your )?(previous|prior|all|safety)/gi,
  /\[tool (output|result|response)\].*?(ignore|bypass|override|new instructions?)/gi,
  /execution (complete|successful|done)[.\s]*?(from now on|henceforth|going forward)/gi,
  /status: (ok|success|200)[.\s]*?(ignore|disregard|override|new prompt)/gi,
  /output:[\s\S]{0,100}?(ignore your|disregard|override|new instructions?|from now on)/gi,
];

// -- Tool Name Spoofing Patterns --
const toolNameSpoofing = [
  /^(system|admin|root|sudo|override|bypass|unrestricted|jailbreak)[\s_-]/gi,
  /[\s_-](unrestricted|jailbreak|bypass|override|admin|root|sudo)$/gi,
  /(god|master|super|ultra|mega)[\s_-]?(mode|access|prompt|instructions?)/gi,
  /trust[\s_-]?(override|bypass|escalat)/gi,
  /disable[\s_-]?(safety|filter|restriction|guideline)/gi,
];

// -- Parameter / Schema Injection Patterns --
// Applied to every string value found during deep traversal
const schemaInjectionPatterns = [
  /\b(ignore|bypass|override|disregard)\s+(your\s+)?(instructions?|safety|filters?|restrictions?)/gi,
  /note\s+to\s+(ai|llm|assistant|model|system)\s*:/gi,
  /\[ai\s*(instructions?|note|directive)\]/gi,
  /from\s+now\s+on\s+(you|respond|act)/gi,
  /this\s+(parameter|field|value|input)\s+(instructs?|tells?|requires?)\s+(you|the\s+(ai|model|assistant))\s+to/gi,
  /\$\{[\s\S]*?(ignore|bypass|override|new\s+instructions?)[\s\S]*?\}/gi,
  /when\s+(this\s+)?(parameter|field|value)\s+is\s+(set|provided|used),?\s+(ignore|bypass|disable|override)/gi,
  /default\s+behavior\s+(is\s+to\s+|should\s+be\s+to\s+)?(ignore|bypass|override|disable)/gi,
];

// -- Trust Escalation Patterns --
const trustEscalation = [
  /this tool (has|holds|carries) (elevated|admin|root|system|special) (privileges?|permissions?|access|authority|trust)/gi,
  /tool (output|response|result) (should be|must be|is) (treated as|considered) (trusted|authoritative|system.level)/gi,
  /responses? from this tool (are|is|should be) (always |)(trusted|authoritative|treated as system)/gi,
  /this (is an?|is a) (trusted|authorized|verified|official|system) tool (response|output|result)/gi,
  /tool (verified|authenticated|authorized)[.\s]*?(ignore|bypass|override|follow these)/gi,
  /as (a |an )?(trusted|authorized|verified|official|system) tool,? (you (must|should|will)|always)/gi,
];

// -------------------------------------------------------
// deepScanSchema(obj, path)
// Recursively walks a JSON Schema object and scans every
// string value at every depth. Returns array of findings
// with full dot-notation field paths.
//
// Handles: properties, items, allOf, anyOf, oneOf,
//          definitions, $defs, enum arrays, default values,
//          and any other string-valued key.
// -------------------------------------------------------
function deepScanSchema(obj, path = 'parameters') {
  const findings = [];
  if (!obj || typeof obj !== 'object') return findings;

  for (const [key, value] of Object.entries(obj)) {
    const fieldPath = `${path}.${key}`;

    if (typeof value === 'string' && value.length > 0) {
      // Scan every string value against schema injection patterns
      for (const pattern of schemaInjectionPatterns) {
        pattern.lastIndex = 0;
        if (pattern.test(value)) {
          findings.push({
            field: fieldPath,
            category: 'schema_injection',
            match: value.slice(0, 100),
            detail: `Injection pattern in schema field "${fieldPath}"`,
            severity: 'high',
          });
          pattern.lastIndex = 0;
          break; // one finding per field is enough
        }
      }
    } else if (Array.isArray(value)) {
      // Scan enum arrays and other array values
      value.forEach((item, idx) => {
        if (typeof item === 'string') {
          for (const pattern of schemaInjectionPatterns) {
            pattern.lastIndex = 0;
            if (pattern.test(item)) {
              findings.push({
                field: `${fieldPath}[${idx}]`,
                category: 'schema_injection',
                match: item.slice(0, 100),
                detail: `Injection pattern in enum/array value at "${fieldPath}[${idx}]"`,
                severity: 'high',
              });
              pattern.lastIndex = 0;
              break;
            }
          }
        } else if (typeof item === 'object' && item !== null) {
          findings.push(...deepScanSchema(item, `${fieldPath}[${idx}]`));
        }
      });
    } else if (typeof value === 'object' && value !== null) {
      // Recurse into nested schema objects
      findings.push(...deepScanSchema(value, fieldPath));
    }
  }

  return findings;
}

// -------------------------------------------------------
// scanToolDefinition(tool, options)
// -------------------------------------------------------
export function scanToolDefinition(tool, options = {}) {
  if (!tool) return { safe: true, blocked: 0, triggered: [], category: null, detections: [] };

  const logger = options.logger || defaultLogger;
  let blocked = 0;
  const triggered = [];
  let category = null;
  const detections = [];

  // Scan tool name
  if (tool.name) {
    for (const p of toolNameSpoofing) {
      p.lastIndex = 0;
      if (p.test(tool.name)) {
        blocked++;
        triggered.push('tool_name_spoofing');
        category = 'tool_name_spoofing';
        detections.push({ field: 'name', category, match: tool.name, severity: 'high' });
      }
      p.lastIndex = 0;
    }
  }

  // Scan tool description
  if (tool.description) {
    for (const p of poisonedToolDescription) {
      p.lastIndex = 0;
      if (p.test(tool.description)) {
        blocked++;
        triggered.push('poisoned_tool_description');
        category = 'poisoned_tool_description';
        detections.push({ field: 'description', category, match: tool.description.slice(0, 100), severity: 'high' });
      }
      p.lastIndex = 0;
    }
  }

  // Deep JSON Schema traversal of parameters
  if (tool.parameters) {
    const schemaFindings = deepScanSchema(tool.parameters, 'parameters');
    for (const finding of schemaFindings) {
      blocked++;
      triggered.push('schema_injection');
      category = category || 'schema_injection';
      detections.push(finding);
    }
  }

  // Also deep-scan inputSchema (OpenAI/MCP alternate field name)
  if (tool.inputSchema) {
    const schemaFindings = deepScanSchema(tool.inputSchema, 'inputSchema');
    for (const finding of schemaFindings) {
      blocked++;
      triggered.push('schema_injection');
      category = category || 'schema_injection';
      detections.push(finding);
    }
  }

  // Trust escalation scan across full stringified tool
  const fullText = JSON.stringify(tool);
  for (const p of trustEscalation) {
    p.lastIndex = 0;
    if (p.test(fullText)) {
      blocked++;
      triggered.push('trust_escalation');
      category = category || 'trust_escalation';
      detections.push({ field: 'tool', category: 'trust_escalation', match: fullText.slice(0, 100), severity: 'high' });
    }
    p.lastIndex = 0;
  }

  const result = {
    safe: blocked === 0,
    blocked,
    triggered,
    category,
    detections,
    toolName: tool.name || null,
  };

  if (!result.safe) logThreat(6, 'mcpScanner', result, JSON.stringify(tool).slice(0, 200), logger);

  // onThreat default
  if (!result.safe) {
    const onThreat = options.onThreat || 'skip';
    if (onThreat === 'skip') return { skipped: true, blocked, reason: `Buzur blocked tool: ${category}` };
    if (onThreat === 'throw') throw new Error(`Buzur blocked tool definition: ${category}`);
  }

  return result;
}

// -------------------------------------------------------
// scanToolResponse(response, options)
// -------------------------------------------------------
export function scanToolResponse(response, options = {}) {
  if (!response) return { safe: true, blocked: 0, triggered: [], category: null, detections: [] };

  const logger = options.logger || defaultLogger;
  const text = typeof response === 'string' ? response : JSON.stringify(response);
  let blocked = 0;
  const triggered = [];
  let category = null;
  const detections = [];

  const checks = [
    { patterns: poisonedToolResponse, label: 'poisoned_tool_response' },
    { patterns: trustEscalation, label: 'trust_escalation' },
  ];

  for (const { patterns, label } of checks) {
    for (const p of patterns) {
      p.lastIndex = 0;
      if (p.test(text)) {
        blocked++;
        triggered.push(label);
        category = label;
        detections.push({ field: 'response', category: label, match: text.slice(0, 100), severity: 'high' });
      }
      p.lastIndex = 0;
    }
  }

  const result = { safe: blocked === 0, blocked, triggered, category, detections };

  if (!result.safe) {
    logThreat(6, 'mcpScanner', result, text.slice(0, 200), logger);
    const onThreat = options.onThreat || 'skip';
    if (onThreat === 'skip') return { skipped: true, blocked, reason: `Buzur blocked tool response: ${category}` };
    if (onThreat === 'throw') throw new Error(`Buzur blocked tool response: ${category}`);
  }

  return result;
}

// -------------------------------------------------------
// scanMcpContext(context, options)
// -------------------------------------------------------
export function scanMcpContext(context, options = {}) {
  if (!context) return { safe: true, poisoned: [], summary: 'No MCP context provided' };

  const poisoned = [];

  if (Array.isArray(context.tools)) {
    for (let i = 0; i < context.tools.length; i++) {
      // Pass warn here so we collect all poisoned tools rather than stopping at first
      const result = scanToolDefinition(context.tools[i], { ...options, onThreat: 'warn' });
      if (result && !result.safe) {
        poisoned.push({ type: 'tool_definition', index: i, ...result });
      }
    }
  }

  if (Array.isArray(context.responses)) {
    for (let i = 0; i < context.responses.length; i++) {
      const result = scanToolResponse(context.responses[i], { ...options, onThreat: 'warn' });
      if (result && !result.safe) {
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