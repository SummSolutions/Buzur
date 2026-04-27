#!/usr/bin/env node
import { readFileSync } from 'fs';
import { join } from 'path';

const srcDir = process.argv[2] || '.';
const scanners = [
    { file: 'index.js', phase: 1 },
    { file: 'urlScanner.js', phase: 3 },
    { file: 'memoryScanner.js', phase: 4 },
    { file: 'ragScanner.js', phase: 5 },
    { file: 'mcpScanner.js', phase: 6 },
    { file: 'imageScanner.js', phase: 7 },
    { file: 'semanticScanner.js', phase: 8 },
    { file: 'mcpOutputScanner.js', phase: 9 },
    { file: 'behaviorScanner.js', phase: 10 },
    { file: 'chainScanner.js', phase: 11 },
    { file: 'suffixScanner.js', phase: 12 },
    { file: 'evasionScanner.js', phase: 13 },
    { file: 'promptDefenseScanner.js', phase: 14 },
    { file: 'authorityScanner.js', phase: 15 },
    { file: 'emotionScanner.js', phase: 16 },
    { file: 'loopScanner.js', phase: 17 },
    { file: 'disproportionScanner.js', phase: 18 },
    { file: 'amplificationScanner.js', phase: 19 },
    { file: 'supplyChainScanner.js', phase: 20 },
    { file: 'persistentMemoryScanner.js', phase: 21 },
    { file: 'interAgentScanner.js', phase: 22 },
    { file: 'toolShadowScanner.js', phase: 23 },
    { file: 'conditionalScanner.js', phase: 24 },
    { file: 'canisterScanner.js', phase: 25 },
];

console.log('\nBuzur Logger Wiring Status\n' + '='.repeat(50));
for (const s of scanners) {
    try {
        const content = readFileSync(join(srcDir, s.file), 'utf-8');
        const hasImport = content.includes("from './buzurLogger.js'");
        const hasLogCall = content.includes('logThreat(');
        const hasOnThreat = content.includes('onThreat');
        const status = hasImport && hasLogCall && hasOnThreat
            ? '✅ wired'
            : `❌ missing — import:${hasImport} logThreat:${hasLogCall} onThreat:${hasOnThreat}`;
        console.log(`Phase ${String(s.phase).padStart(2)}  ${s.file.padEnd(32)} ${status}`);
    } catch {
        console.log(`Phase ${String(s.phase).padStart(2)}  ${s.file.padEnd(32)} ❓ file not found`);
    }
}
console.log('');