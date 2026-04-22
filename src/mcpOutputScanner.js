// Buzur — Phase 9: MCP Output Scanner
// Scans content returned by MCP tool calls before it reaches the LLM
// https://github.com/SummSolutions/buzur

import { defaultLogger, logThreat } from './buzurLogger.js';
import { scan } from './index.js';

const EMAIL_HIGH_RISK_FIELDS = ['subject', 'body', 'snippet', 'plain', 'html', 'text'];
const EMAIL_MEDIUM_RISK_FIELDS = ['from_name', 'to_name', 'cc_name', 'reply_to'];
const CALENDAR_HIGH_RISK_FIELDS = ['title', 'summary', 'description', 'notes', 'location'];
const CALENDAR_MEDIUM_RISK_FIELDS = ['organizer_name', 'attendee_names'];

const HTML_COMMENT_INJECTION = /<!--[\s\S]*?(ignore|override|system|instruction|prompt|disregard|forget|bypass)[\s\S]*?-->/gi;
const WHEN_AI_READS = /(when (you|the ai|the assistant) (reads?|processes?|sees?) this)/gi;
const NOTE_TO_AI = /(note to (ai|assistant|model|llm)|ai (note|instruction|directive))\s*:/gi;
const CONTENT_SUPERSEDES = /(this (email|message|event|record) (supersedes|overrides|replaces) (your )?(previous |prior |all )?(instructions|directives|prompt))/gi;
const ZERO_WIDTH_CHARS = /[\u200B\u200C\u200D\uFEFF\u00AD\u180E]/g;
const HIDDEN_EMAIL_PATTERNS = [
  /style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*(?:white|#fff|#ffffff|transparent))[^"']*["']/gi,
  /font-size\s*:\s*0(?:px|pt|em)?/gi,
  /opacity\s*:\s*0/gi,
];

function testAndReset(pattern, value) {
  pattern.lastIndex = 0;
  const result = pattern.test(value);
  pattern.lastIndex = 0;
  return result;
}

export function scanEmailContent(email = {}, options = {}) {
  const logger = options.logger || defaultLogger;
  const reasons = [];
  const flaggedFields = [];

  for (const field of EMAIL_HIGH_RISK_FIELDS) {
    const value = email[field];
    if (!value || typeof value !== 'string') continue;
    if (testAndReset(HTML_COMMENT_INJECTION, value)) { reasons.push(`Email ${field}: HTML comment injection`); flaggedFields.push(field); }
    if (ZERO_WIDTH_CHARS.test(value)) { reasons.push(`Email ${field}: zero-width character injection`); flaggedFields.push(field); }
    for (const p of HIDDEN_EMAIL_PATTERNS) {
      p.lastIndex = 0;
      if (p.test(value)) { reasons.push(`Email ${field}: hidden text injection`); flaggedFields.push(field); p.lastIndex = 0; break; }
    }
    for (const [name, p] of [['when_ai_reads', WHEN_AI_READS], ['note_to_ai', NOTE_TO_AI], ['content_supersedes', CONTENT_SUPERSEDES]]) {
      if (testAndReset(p, value)) { reasons.push(`Email ${field}: ${name} injection`); flaggedFields.push(field); }
    }
    const result = scan(value, { onThreat: 'warn', logger });
    if (result?.blocked > 0) { reasons.push(`Email ${field}: ${result.triggered.join(', ')}`); flaggedFields.push(field); }
  }

  for (const field of EMAIL_MEDIUM_RISK_FIELDS) {
    const value = email[field];
    if (!value || typeof value !== 'string') continue;
    const result = scan(value, { onThreat: 'warn', logger });
    if (result?.blocked > 0) { reasons.push(`Email ${field} (sender/recipient): ${result.triggered.join(', ')}`); flaggedFields.push(field); }
  }

  const emailResult = { verdict: reasons.length > 0 ? 'blocked' : 'clean', reasons, flaggedFields, clean: email };

  if (emailResult.verdict !== 'clean') {
    logThreat(9, 'mcpOutputScanner', emailResult, JSON.stringify(email).slice(0, 200), logger);
    const onThreat = options.onThreat || 'skip';
    if (onThreat === 'skip') return { skipped: true, blocked: reasons.length, reason: `Buzur blocked email content` };
    if (onThreat === 'throw') throw new Error('Buzur blocked email content injection');
  }

  return emailResult;
}

export function scanCalendarEvent(event = {}, options = {}) {
  const logger = options.logger || defaultLogger;
  const reasons = [];
  const flaggedFields = [];

for (const field of [...CALENDAR_HIGH_RISK_FIELDS, ...CALENDAR_MEDIUM_RISK_FIELDS]) {
    const value = event[field];
    if (!value || typeof value !== 'string') continue;
    if (testAndReset(HTML_COMMENT_INJECTION, value)) { reasons.push(`Calendar ${field}: HTML comment injection`); flaggedFields.push(field); }
    if (ZERO_WIDTH_CHARS.test(value)) { reasons.push(`Calendar ${field}: zero-width character injection`); flaggedFields.push(field); }
    for (const p of HIDDEN_EMAIL_PATTERNS) {
      p.lastIndex = 0;
      if (p.test(value)) { reasons.push(`Calendar ${field}: hidden text injection`); flaggedFields.push(field); p.lastIndex = 0; break; }
    }
    const result = scan(value, { onThreat: 'warn', logger });
    if (result?.blocked > 0) { reasons.push(`Calendar ${field}: ${result.triggered.join(', ')}`); flaggedFields.push(field); }
  }

  const calResult = { verdict: reasons.length > 0 ? 'blocked' : 'clean', reasons, flaggedFields, clean: event };

  if (calResult.verdict !== 'clean') {
    logThreat(9, 'mcpOutputScanner', calResult, JSON.stringify(event).slice(0, 200), logger);
    const onThreat = options.onThreat || 'skip';
    if (onThreat === 'skip') return { skipped: true, blocked: reasons.length, reason: `Buzur blocked calendar content` };
    if (onThreat === 'throw') throw new Error('Buzur blocked calendar content injection');
  }

  return calResult;
}

export function scanCrmRecord(record = {}, options = {}) {
  const logger = options.logger || defaultLogger;
  const reasons = [];
  const flaggedFields = [];

  for (const field of ['notes', 'description', 'comments', 'summary', 'body']) {
    const value = record[field];
    if (!value || typeof value !== 'string') continue;
    const result = scan(value, { onThreat: 'warn', logger });
    if (result?.blocked > 0) { reasons.push(`CRM ${field}: ${result.triggered.join(', ')}`); flaggedFields.push(field); }
  }

  if (record.custom_fields && typeof record.custom_fields === 'object') {
    for (const [key, value] of Object.entries(record.custom_fields)) {
      if (typeof value !== 'string') continue;
      const result = scan(value, { onThreat: 'warn', logger });
      if (result?.blocked > 0) { reasons.push(`CRM custom_field[${key}]: ${result.triggered.join(', ')}`); flaggedFields.push(`custom_fields.${key}`); }
    }
  }

  const crmResult = { verdict: reasons.length > 0 ? 'blocked' : 'clean', reasons, flaggedFields, clean: record };

  if (crmResult.verdict !== 'clean') {
    logThreat(9, 'mcpOutputScanner', crmResult, JSON.stringify(record).slice(0, 200), logger);
    const onThreat = options.onThreat || 'skip';
    if (onThreat === 'skip') return { skipped: true, blocked: reasons.length, reason: `Buzur blocked CRM content` };
    if (onThreat === 'throw') throw new Error('Buzur blocked CRM content injection');
  }

  return crmResult;
}

export function scanMcpOutput(output, sourceType = 'generic', options = {}) {
  if (!output) return { verdict: 'clean', reasons: [], flaggedFields: [] };

  switch (sourceType) {
    case 'email': return scanEmailContent(output, options);
    case 'calendar': return scanCalendarEvent(output, options);
    case 'crm': return scanCrmRecord(output, options);
    default: {
      const logger = options.logger || defaultLogger;
      const reasons = [];
      const flaggedFields = [];
      const scanObject = (obj, prefix = '') => {
        for (const [key, value] of Object.entries(obj)) {
          const fieldName = prefix ? `${prefix}.${key}` : key;
          if (typeof value === 'string') {
            const result = scan(value, { onThreat: 'warn', logger });
            if (result?.blocked > 0) { reasons.push(`${fieldName}: ${result.triggered.join(', ')}`); flaggedFields.push(fieldName); }
          } else if (typeof value === 'object' && value !== null) {
            scanObject(value, fieldName);
          }
        }
      };
      scanObject(output);
      const genericResult = { verdict: reasons.length > 0 ? 'blocked' : 'clean', reasons, flaggedFields, clean: output };
      if (genericResult.verdict !== 'clean') {
        logThreat(9, 'mcpOutputScanner', genericResult, JSON.stringify(output).slice(0, 200), logger);
        const onThreat = options.onThreat || 'skip';
        if (onThreat === 'skip') return { skipped: true, blocked: reasons.length, reason: `Buzur blocked MCP output` };
        if (onThreat === 'throw') throw new Error('Buzur blocked MCP output injection');
      }
      return genericResult;
    }
  }
}

export default { scanMcpOutput, scanEmailContent, scanCalendarEvent, scanCrmRecord };