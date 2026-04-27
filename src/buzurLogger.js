// Buzur — Unified Threat Logger
// Infrastructure (not a scanner phase) — logs detections from all 25 phases
// to a single JSONL file with a consistent normalized shape.
//
// Each log entry:
// {
//   "timestamp": "2026-04-20T14:32:00.000Z",
//   "phase": 16,
//   "scanner": "emotionScanner",
//   "verdict": "blocked",
//   "category": "guilt_tripping",
//   "detections": [...],  // normalized array, always present
//   "raw": "first 200 chars of scanned text"
// }
//
// Usage:
//   import { logThreat } from './buzurLogger.js';
//   const result = scanEmotion(text);
//   if (!result.safe) logThreat(16, 'emotionScanner', result, text);
//
// https://github.com/SummSolutions/buzur

import fs from 'fs';
import path from 'path';

// -------------------------------------------------------
// Configuration
// -------------------------------------------------------
const DEFAULT_LOG_PATH = './logs/buzur-threats.jsonl';

// -------------------------------------------------------
// BuzurLogger class
// Drop-in for FileSessionStore pattern from Phase 10.
// Supports custom log path and optional max file size rotation.
// -------------------------------------------------------
export class BuzurLogger {
    constructor(filePath = DEFAULT_LOG_PATH, options = {}) {
        this.filePath = filePath;
        this.maxFileSizeBytes = options.maxFileSizeBytes || 10 * 1024 * 1024; // 10MB default
        this._ensureDir();
    }

    _ensureDir() {
        const dir = path.dirname(this.filePath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
    }

    _rotateIfNeeded() {
        try {
            if (!fs.existsSync(this.filePath)) return;
            const { size } = fs.statSync(this.filePath);
            if (size >= this.maxFileSizeBytes) {
                const rotated = this.filePath.replace(/\.jsonl$/, '') +
                    `_${new Date().toISOString().replace(/[:.]/g, '-')}.jsonl`;
                fs.renameSync(this.filePath, rotated);
            }
        } catch {
            // Non-fatal — log rotation failure shouldn't crash the scanner
        }
    }

    write(entry) {
        try {
            this._rotateIfNeeded();
            fs.appendFileSync(this.filePath, JSON.stringify(entry) + '\n', 'utf-8');
        } catch (err) {
            console.warn(`[Buzur] Could not write threat log to ${this.filePath}: ${err.message}`);
        }
    }
}

// Default logger instance — shared across all scanners unless overridden
export const defaultLogger = new BuzurLogger();

// -------------------------------------------------------
// normalizeResult(result)
// Maps all 5 scanner return shapes to a unified detections array.
//
// Shape families:
//   A: { safe, blocked, triggered, category }         — phases 1,2,4,5,6
//   B: { safe, blocked, detections, category }        — phases 15,16,17,18,19,20
//   C: { verdict, reasons, flaggedFields }            — phases 3,7,9
//   D: { verdict, detections, layers }                — phases 8,11,12
//   E: { verdict, anomalies, suspicionScore }         — phase 10
//   F: { verdict, fuzzyMatches, leakDetections }      — phase 14
// -------------------------------------------------------
export function normalizeResult(result) {
    if (!result) return { verdict: 'clean', category: null, detections: [] };

    // Shape A — triggered array, safe/blocked fields
    if (Array.isArray(result.triggered)) {
        return {
            verdict: result.blocked > 0 ? 'blocked' : 'clean',
            category: result.category || null,
            detections: result.triggered.map(t => ({
                type: result.category || 'pattern_match',
                detail: typeof t === 'string' && t.startsWith('/') ? 'Pattern matched' : t,
                severity: 'high',
            })),
        };
    }

    // Shape B — detections array, safe/blocked fields (phases 15-20)
    if (typeof result.safe === 'boolean' && Array.isArray(result.detections)) {
        return {
            verdict: result.safe ? 'clean' : 'blocked',
            category: result.category || null,
            detections: result.detections,
        };
    }

    // Shape C — reasons array, verdict field (phases 3, 7, 9)
    if (Array.isArray(result.reasons)) {
        return {
            verdict: result.verdict || (result.reasons.length > 0 ? 'blocked' : 'clean'),
            category: result.category || null,
            detections: result.reasons.map(r => ({
                type: 'pattern_match',
                detail: r,
                severity: result.verdict === 'blocked' ? 'high' : 'medium',
            })),
        };
    }

    // Shape D — detections array, verdict field (phases 8, 11, 12)
    if (result.verdict && Array.isArray(result.detections)) {
        return {
            verdict: result.verdict,
            category: result.category || (result.detections[0]?.type) || null,
            detections: result.detections,
        };
    }

    // Shape E — anomalies array (phase 10)
    if (Array.isArray(result.anomalies)) {
        return {
            verdict: result.verdict || 'clean',
            category: result.anomalies[0]?.type || null,
            detections: result.anomalies.map(a => ({
                type: a.type,
                detail: a.detail,
                severity: a.severity || 'medium',
            })),
        };
    }

    // Shape F — fuzzyMatches + leakDetections (phase 14)
    if (Array.isArray(result.fuzzyMatches) || Array.isArray(result.leakDetections)) {
        const detections = [
            ...(result.leakDetections || []),
            ...(result.fuzzyMatches || []).map(m => ({
                type: 'fuzzy_match',
                detail: `Fuzzy match: "${m.word}" ≈ "${m.keyword}" (distance ${m.distance})`,
                severity: m.distance === 1 ? 'high' : 'medium',
            })),
        ];
        return {
            verdict: result.verdict || 'clean',
            category: detections[0]?.type || null,
            detections,
        };
    }

    // Fallback — unknown shape, preserve what we can
    return {
        verdict: result.verdict || (result.safe === false ? 'blocked' : 'clean'),
        category: result.category || null,
        detections: [],
    };
}

// -------------------------------------------------------
// logThreat(phase, scanner, result, rawText, logger)
//
// Call this after any scanner returns a non-clean result.
// Normalizes the result shape and writes to the log file.
//
// Parameters:
//   phase   — phase number (1–20)
//   scanner — scanner function name e.g. 'emotionScanner'
//   result  — raw scanner return value
//   rawText — original text that was scanned (first 200 chars logged)
//   logger  — optional BuzurLogger instance (uses defaultLogger if omitted)
// -------------------------------------------------------
export function logThreat(phase, scanner, result, rawText = '', logger = defaultLogger) {
    const normalized = normalizeResult(result);

    // Only log if there's an actual threat
    if (normalized.verdict === 'clean' && normalized.detections.length === 0) return;

    const entry = {
        timestamp: new Date().toISOString(),
        phase,
        scanner,
        verdict: normalized.verdict,
        category: normalized.category,
        detections: normalized.detections,
        raw: typeof rawText === 'string' ? rawText.slice(0, 200) : '',
    };

    logger.write(entry);
}

// -------------------------------------------------------
// readLog(logPath)
// Utility: read and parse the JSONL threat log.
// Returns array of log entries.
// -------------------------------------------------------
export function readLog(logPath = DEFAULT_LOG_PATH) {
    try {
        if (!fs.existsSync(logPath)) return [];
        const lines = fs.readFileSync(logPath, 'utf-8').split('\n').filter(Boolean);
        return lines.map(line => {
            try { return JSON.parse(line); } catch { return null; }
        }).filter(Boolean);
    } catch (err) {
        console.warn(`[Buzur] Could not read threat log: ${err.message}`);
        return [];
    }
}

// -------------------------------------------------------
// queryLog(filters, logPath)
// Utility: filter log entries by phase, scanner, verdict, or category.
//
// filters: {
//   phase?: number,
//   scanner?: string,
//   verdict?: 'blocked' | 'suspicious' | 'clean',
//   category?: string,
//   since?: Date,
// }
// -------------------------------------------------------
export function queryLog(filters = {}, logPath = DEFAULT_LOG_PATH) {
    const entries = readLog(logPath);
    return entries.filter(entry => {
        if (filters.phase !== undefined && entry.phase !== filters.phase) return false;
        if (filters.scanner !== undefined && entry.scanner !== filters.scanner) return false;
        if (filters.verdict !== undefined && entry.verdict !== filters.verdict) return false;
        if (filters.category !== undefined && entry.category !== filters.category) return false;
        if (filters.since !== undefined && new Date(entry.timestamp) < filters.since) return false;
        return true;
    });
}

export default { BuzurLogger, defaultLogger, logThreat, normalizeResult, readLog, queryLog };