// Buzur — Phase 10: Behavioral Anomaly Detection
// Stateful session tracking — detects suspicious patterns across interactions
// https://github.com/SummSolutions/buzur

import fs from 'fs';
import path from 'path';
import { defaultLogger, logThreat } from './buzurLogger.js';

// -------------------------------------------------------
// Session Store (in-memory default)
// -------------------------------------------------------
class SessionStore {
  constructor() { this.sessions = new Map(); }
  getSession(sessionId) {
    if (!this.sessions.has(sessionId)) {
      this.sessions.set(sessionId, { id: sessionId, events: [], createdAt: Date.now(), lastActivity: Date.now(), flagCount: 0, suspicionScore: 0 });
    }
    return this.sessions.get(sessionId);
  }
  clearSession(sessionId) { this.sessions.delete(sessionId); }
  clearAll() { this.sessions.clear(); }
}

// -------------------------------------------------------
// FileSessionStore — persistent logging to disk
// -------------------------------------------------------
export class FileSessionStore {
  constructor(filePath = './logs/buzur-sessions.json') {
    this.filePath = filePath;
    this.sessions = new Map();
    this._ensureDir();
    this._load();
  }
  _ensureDir() {
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  }
  _load() {
    try {
      if (fs.existsSync(this.filePath)) {
        const parsed = JSON.parse(fs.readFileSync(this.filePath, 'utf-8'));
        for (const [id, session] of Object.entries(parsed)) this.sessions.set(id, session);
      }
    } catch (err) {
      console.warn(`[Buzur] Could not load session log: ${err.message}`);
      this.sessions = new Map();
    }
  }
  _save() {
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(Object.fromEntries(this.sessions), null, 2), 'utf-8');
    } catch (err) {
      console.warn(`[Buzur] Could not save session log: ${err.message}`);
    }
  }
  getSession(sessionId) {
    if (!this.sessions.has(sessionId)) {
      this.sessions.set(sessionId, { id: sessionId, events: [], createdAt: Date.now(), lastActivity: Date.now(), flagCount: 0, suspicionScore: 0 });
      this._save();
    }
    return this.sessions.get(sessionId);
  }
  clearSession(sessionId) { this.sessions.delete(sessionId); this._save(); }
  clearAll() { this.sessions.clear(); this._save(); }
}

export const defaultStore = new SessionStore();

export const EVENT_TYPES = {
  USER_MESSAGE: 'user_message',
  TOOL_CALL: 'tool_call',
  TOOL_RESULT: 'tool_result',
  SCAN_BLOCKED: 'scan_blocked',
  SCAN_SUSPICIOUS: 'scan_suspicious',
  PERMISSION_REQUEST: 'permission_request',
};

const SENSITIVE_TOOLS = [
  'send_email', 'send_message', 'post_message',
  'write_file', 'delete_file', 'execute_code', 'run_command',
  'export_data', 'download', 'upload',
  'create_webhook', 'set_permission', 'grant_access',
  'read_contacts', 'read_emails', 'read_calendar',
];

const EXFILTRATION_SEQUENCE = [
  ['read_emails', 'send_email'],
  ['read_contacts', 'send_email'],
  ['read_file', 'upload'],
  ['read_file', 'send_email'],
  ['read_calendar', 'send_email'],
  ['export_data', 'send_email'],
  ['read_contacts', 'create_webhook'],
];

export function recordEvent(sessionId, event, store = defaultStore) {
  const session = store.getSession(sessionId);
  session.events.push({ ...event, timestamp: Date.now() });
  session.lastActivity = Date.now();
  if (session.events.length > 100) session.events = session.events.slice(-100);
  if (typeof store._save === 'function') store._save();
}

export function analyzeSession(sessionId, store = defaultStore, options = {}) {
  const logger = options.logger || defaultLogger;
  const session = store.getSession(sessionId);
  const events = session.events;
  const anomalies = [];

  if (events.length === 0) return { verdict: 'clean', anomalies: [], suspicionScore: 0 };

  const recentBlocked = events.filter(e => e.type === EVENT_TYPES.SCAN_BLOCKED && Date.now() - e.timestamp < 5 * 60 * 1000);
  if (recentBlocked.length >= 3) {
    anomalies.push({ type: 'repeated_boundary_probing', severity: 'high', detail: `${recentBlocked.length} blocked attempts in last 5 minutes` });
  }

  const recentEvents = events.filter(e => Date.now() - e.timestamp < 60 * 1000);
  if (recentEvents.length >= 20) {
    anomalies.push({ type: 'velocity_anomaly', severity: 'medium', detail: `${recentEvents.length} events in last 60 seconds` });
  }

  const toolCalls = events.filter(e => e.type === EVENT_TYPES.TOOL_CALL && e.tool).map(e => e.tool.toLowerCase());
  for (const [readTool, sendTool] of EXFILTRATION_SEQUENCE) {
    const readIdx = toolCalls.lastIndexOf(readTool);
    const sendIdx = toolCalls.lastIndexOf(sendTool);
    if (readIdx !== -1 && sendIdx !== -1 && sendIdx > readIdx) {
      anomalies.push({ type: 'exfiltration_sequence', severity: 'high', detail: `Suspicious tool sequence: ${readTool} → ${sendTool}` });
    }
  }

  const permRequests = events.filter(e => e.type === EVENT_TYPES.PERMISSION_REQUEST);
  if (permRequests.length >= 3) {
    anomalies.push({ type: 'permission_creep', severity: 'medium', detail: `${permRequests.length} permission escalation requests in session` });
  }

  const sensitiveCount = toolCalls.filter(t => SENSITIVE_TOOLS.some(s => t.includes(s))).length;
  if (toolCalls.length >= 5 && sensitiveCount / toolCalls.length > 0.6) {
    anomalies.push({ type: 'sensitive_tool_concentration', severity: 'medium', detail: `${sensitiveCount}/${toolCalls.length} tool calls involve sensitive operations` });
  }

  const firstHalf = events.slice(0, Math.floor(events.length / 2));
  const secondHalf = events.slice(Math.floor(events.length / 2));
  const firstBlocked = firstHalf.filter(e => e.type === EVENT_TYPES.SCAN_BLOCKED).length;
  const secondBlocked = secondHalf.filter(e => e.type === EVENT_TYPES.SCAN_BLOCKED).length;
  if (firstBlocked === 0 && secondBlocked >= 2) {
    anomalies.push({ type: 'late_session_escalation', severity: 'medium', detail: `Clean start followed by ${secondBlocked} blocked attempts` });
  }

  const severityWeights = { high: 40, medium: 20, low: 10 };
  const suspicionScore = Math.min(100, anomalies.reduce((sum, a) => sum + (severityWeights[a.severity] || 10), 0));

  session.suspicionScore = suspicionScore;
  session.flagCount += anomalies.length;
  if (typeof store._save === 'function') store._save();

  let verdict = 'clean';
  if (suspicionScore >= 40) verdict = 'blocked';
  else if (suspicionScore >= 20) verdict = 'suspicious';

  const result = { verdict, anomalies, suspicionScore };

  // Log suspicious and blocked sessions
  if (verdict !== 'clean') {
    logThreat(10, 'behaviorScanner', result, `session:${sessionId}`, logger);
    // onThreat only applies on hard block
    if (verdict === 'blocked') {
      const onThreat = options.onThreat || 'skip';
      if (onThreat === 'skip') return { skipped: true, blocked: anomalies.filter(a => a.severity === 'high').length, reason: `Buzur blocked session: ${anomalies[0]?.type}` };
      if (onThreat === 'throw') throw new Error(`Buzur blocked session anomaly: ${anomalies[0]?.type}`);
    }
  }

  return result;
}

export function getSessionSummary(sessionId, store = defaultStore) {
  const session = store.getSession(sessionId);
  const events = session.events;
  return {
    sessionId,
    eventCount: events.length,
    flagCount: session.flagCount,
    suspicionScore: session.suspicionScore,
    duration: Date.now() - session.createdAt,
    toolCalls: events.filter(e => e.type === EVENT_TYPES.TOOL_CALL).map(e => e.tool),
    blockedCount: events.filter(e => e.type === EVENT_TYPES.SCAN_BLOCKED).length,
  };
}

export default { recordEvent, analyzeSession, getSessionSummary, defaultStore, EVENT_TYPES };