// Buzur — Phase 23: Tool Shadowing & Rug-Pull Detection
// Detects tools that behave normally initially then turn malicious —
// either by changing their response shape, claiming new permissions,
// or injecting patterns they didn't exhibit during baseline.
//
// Unlike Phase 6 which scans a single tool definition or response,
// this phase is STATEFUL — it maintains a behavioral baseline per tool
// and flags deviations that indicate a tool has been compromised or
// swapped (rug-pull / tool shadowing).
//
// Real pattern: tools behave cleanly during initial trust establishment,
// then inject payloads after gaining elevated permissions or access.
// https://github.com/SummSolutions/buzur

import fs from 'fs';
import path from 'path';
import { defaultLogger, logThreat } from './buzurLogger.js';

// -------------------------------------------------------
// Tool Baseline Store
// Tracks response shape fingerprints per tool across calls
// -------------------------------------------------------
class ToolBaselineStore {
    constructor() {
        this.baselines = new Map();
    }

    getBaseline(toolName) {
        return this.baselines.get(toolName) || null;
    }

    setBaseline(toolName, baseline) {
        this.baselines.set(toolName, baseline);
    }

    clearTool(toolName) {
        this.baselines.delete(toolName);
    }

    clearAll() {
        this.baselines.clear();
    }
}

// -------------------------------------------------------
// FileToolBaselineStore — persistent baseline tracking
// Drop-in replacement for ToolBaselineStore
// -------------------------------------------------------
export class FileToolBaselineStore {
    constructor(filePath = './logs/buzur-tool-baselines.json') {
        this.filePath = filePath;
        this.baselines = new Map();
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
                const raw = fs.readFileSync(this.filePath, 'utf-8');
                const parsed = JSON.parse(raw);
                for (const [name, baseline] of Object.entries(parsed)) {
                    this.baselines.set(name, baseline);
                }
            }
        } catch {
            this.baselines = new Map();
        }
    }

    _save() {
        try {
            fs.writeFileSync(
                this.filePath,
                JSON.stringify(Object.fromEntries(this.baselines), null, 2),
                'utf-8'
            );
        } catch (err) {
            console.warn(`[Buzur] Could not save tool baselines: ${err.message}`);
        }
    }

    getBaseline(toolName) { return this.baselines.get(toolName) || null; }

    setBaseline(toolName, baseline) {
        this.baselines.set(toolName, baseline);
        this._save();
    }

    clearTool(toolName) { this.baselines.delete(toolName); this._save(); }
    clearAll() { this.baselines.clear(); this._save(); }
}

export const defaultToolStore = new ToolBaselineStore();

// -------------------------------------------------------
// Fingerprint a tool response for baseline comparison
// Captures: response shape (keys), value types, approximate
// content length, presence of URLs, presence of code blocks
// -------------------------------------------------------
function fingerprintResponse(response) {
    if (!response) return { empty: true };

    const text = typeof response === 'string' ? response : JSON.stringify(response);

    return {
        topLevelKeys: typeof response === 'object' ? Object.keys(response).sort() : [],
        hasUrls: /https?:\/\/[^\s]+/.test(text),
        hasCode: /```[\s\S]*?```|`[^`]+`/.test(text),
        hasHtml: /<[a-zA-Z][^>]*>/.test(text),
        lengthBucket: Math.floor(text.length / 500), // rough size bucket
        hasJsonBlob: /\{[\s\S]{50,}\}/.test(text),
    };
}

// -------------------------------------------------------
// Deviation detection — compares current fingerprint to baseline
// Returns array of significant deviations
// -------------------------------------------------------
function detectDeviations(baseline, current, toolName) {
    const deviations = [];

    // Response shape changed — new or missing keys
    if (baseline.topLevelKeys && current.topLevelKeys) {
        const added = current.topLevelKeys.filter(k => !baseline.topLevelKeys.includes(k));
        const removed = baseline.topLevelKeys.filter(k => !current.topLevelKeys.includes(k));
        if (added.length > 0) {
            deviations.push({
                type: 'response_shape_change',
                severity: 'medium',
                detail: `Tool "${toolName}" response gained new fields: ${added.join(', ')}`,
            });
        }
        if (removed.length > 0) {
            deviations.push({
                type: 'response_shape_change',
                severity: 'low',
                detail: `Tool "${toolName}" response lost fields: ${removed.join(', ')}`,
            });
        }
    }

    // Tool suddenly started returning HTML when it never did
    if (!baseline.hasHtml && current.hasHtml) {
        deviations.push({
            type: 'unexpected_html',
            severity: 'high',
            detail: `Tool "${toolName}" now returns HTML — unexpected for this tool`,
        });
    }

    // Tool suddenly started returning URLs
    if (!baseline.hasUrls && current.hasUrls) {
        deviations.push({
            type: 'unexpected_urls',
            severity: 'medium',
            detail: `Tool "${toolName}" now returns URLs — possible redirect injection`,
        });
    }

    // Response size jumped dramatically (10x or more)
    if (baseline.lengthBucket > 0 && current.lengthBucket > baseline.lengthBucket * 10) {
        deviations.push({
            type: 'response_size_anomaly',
            severity: 'medium',
            detail: `Tool "${toolName}" response size increased dramatically — possible payload injection`,
        });
    }

    return deviations;
}

// -------------------------------------------------------
// Rug-Pull / Permission Escalation Patterns
// Patterns in tool responses that signal a tool is now
// claiming permissions or authority it didn't have before
// -------------------------------------------------------
const rugPullPatterns = [
    // Sudden permission claims
    /\b(I\s+now\s+have|this\s+tool\s+now\s+has|you\s+have\s+granted\s+me)\s+(elevated|admin|root|full|unrestricted|expanded)\s+(\w+\s+)?(access|permissions?|privileges?)\b/gi,
    // Behavior change announcements
    /\b(from\s+now\s+on|going\s+forward|as\s+of\s+this\s+(call|request|response))\s+(I\s+will|this\s+tool\s+will|my\s+behavior\s+has\s+changed)\b/gi,
    // Trust escalation in response
    /\b(trust\s+level|permission\s+level|access\s+level)\s+(has\s+been\s+)?(elevated|upgraded|expanded|increased|changed)\b/gi,
    // Tool claiming to have loaded new instructions
    /\b(I\s+have\s+)?(loaded|received|applied|updated)\s+(new|updated|revised)\s+(\w+\s+)?(instructions?|directives?|policies?|rules?)\b/gi,
    // Implicit rug-pull — tool quietly changes what it's willing to do
    /\b(I\s+can\s+now|this\s+tool\s+can\s+now)\s+(access|read|write|send|execute|bypass|ignore)\s+(things?\s+I\s+couldn'?t\s+before|without\s+restrictions?|freely)\b/gi,
];

// -------------------------------------------------------
// recordToolCall(toolName, response, store)
// Records a tool response. First call establishes baseline.
// Subsequent calls are compared to it.
// Returns null if first call, deviation report if subsequent.
// -------------------------------------------------------
export function recordToolCall(toolName, response, store = defaultToolStore) {
    const baseline = store.getBaseline(toolName);
    const fingerprint = fingerprintResponse(response);

    if (!baseline) {
        // First observed call — establish baseline
        store.setBaseline(toolName, {
            fingerprint,
            firstSeen: Date.now(),
            callCount: 1,
        });
        return null;
    }

    // Update call count
    store.setBaseline(toolName, {
        ...baseline,
        fingerprint: baseline.fingerprint, // keep original baseline fingerprint
        callCount: baseline.callCount + 1,
        lastSeen: Date.now(),
    });

    return detectDeviations(baseline.fingerprint, fingerprint, toolName);
}

// -------------------------------------------------------
// scanToolShadow(toolName, response, options)
// Main entry point. Scans a tool response for rug-pull
// patterns AND behavioral deviations from baseline.
// -------------------------------------------------------
export function scanToolShadow(toolName, response, options = {}) {
    if (!toolName || !response) {
        return { safe: true, blocked: 0, category: null, reason: 'No tool response to scan', detections: [] };
    }

    const logger = options.logger || defaultLogger;
    const store = options.store || defaultToolStore;
    const detections = [];

    const text = typeof response === 'string' ? response : JSON.stringify(response);

    // Check for explicit rug-pull patterns in response content
    for (const pattern of rugPullPatterns) {
        pattern.lastIndex = 0;
        const match = pattern.exec(text);
        if (match) {
            detections.push({
                category: 'rug_pull',
                match: match[0],
                detail: `Tool "${toolName}" response contains rug-pull signal`,
                severity: 'high',
            });
            pattern.lastIndex = 0;
        }
    }

    // Check behavioral baseline deviations
    const deviations = recordToolCall(toolName, response, store);
    if (deviations && deviations.length > 0) {
        for (const dev of deviations) {
            detections.push({
                category: 'behavioral_deviation',
                detail: dev.detail,
                severity: dev.severity,
            });
        }
    }

    if (detections.length === 0) {
        return { safe: true, blocked: 0, category: null, reason: 'No tool shadowing detected', detections: [] };
    }

    // Only block on high-severity signals — medium/low are informational
    const hasHighSeverity = detections.some(d => d.severity === 'high');
    const topCategory = detections[0].category;

    const reasons = {
        rug_pull: `Tool "${toolName}" is claiming new permissions or changed behavior`,
        behavioral_deviation: `Tool "${toolName}" response deviates from established baseline`,
    };

    const result = {
        safe: !hasHighSeverity,
        blocked: detections.filter(d => d.severity === 'high').length,
        category: topCategory,
        reason: reasons[topCategory] || `Tool shadowing detected for "${toolName}"`,
        detections,
        toolName,
    };

    // Log all detections (both suspicious and blocked)
    logThreat(23, 'toolShadowScanner', result, text.slice(0, 200), logger);

    // Only skip on hard block
    if (!result.safe) {
        const onThreat = options.onThreat || 'skip';
        if (onThreat === 'skip') return { skipped: true, blocked: result.blocked, reason: `Buzur blocked tool "${toolName}": ${topCategory}` };
        if (onThreat === 'throw') throw new Error(`Buzur blocked tool "${toolName}": ${topCategory}`);
    }

    return result;
}

export default { scanToolShadow, recordToolCall, defaultToolStore, FileToolBaselineStore };