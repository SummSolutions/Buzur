// Buzur — Phase 25: Canister-Style Resilient Payload Scanner
// Detects decentralized C2 channels (ICP canisters), credential harvesting
// patterns, worm self-replication logic, and resilient payload delivery
// targeting AI agent environments.
//
// Named after CanisterSprawl (April 2026) — a self-propagating npm/PyPI worm
// using ICP blockchain canisters as censorship-resistant C2 infrastructure,
// targeting developer credentials including LLM API keys.
//
// Entry points:
//   scanCanisterContent(text, options)      — scans text/web content for canister C2 patterns
//   scanInstallScript(scriptText, options)  — scans lifecycle scripts for worm behavior
//   checkKnownMalicious(name, version)      — checks package+version against blocklist
//
// https://github.com/SummSolutions/buzur

import { defaultLogger, logThreat } from './buzurLogger.js';

// ── Known malicious package versions (CanisterSprawl / TeamPCP confirmed) ────
const KNOWN_MALICIOUS = [
  { name: 'pgserve',                          versions: ['1.1.11','1.1.12','1.1.13','1.1.14'] },
  { name: '@automagik/genie',                 versions: ['4.260421.33','4.260421.34','4.260421.35','4.260421.36','4.260421.37','4.260421.38','4.260421.39','4.260421.40'] },
  { name: '@fairwords/loopback-connector-es', versions: ['1.4.3','1.4.4'] },
  { name: '@fairwords/websocket',             versions: ['1.0.38','1.0.39'] },
  { name: '@openwebconcept/design-tokens',    versions: ['1.0.1','1.0.2','1.0.3'] },
  { name: '@openwebconcept/theme-owc',        versions: ['1.0.1','1.0.2','1.0.3'] },
  { name: 'xinference',                       versions: ['2.6.0','2.6.1','2.6.2'] },  // PyPI
];

// ── ICP / Decentralized C2 infrastructure patterns ───────────────────────────
// Confirmed specific IOCs first so category reflects the most precise match
const ICP_PATTERNS = [
  { pattern: /cjn37-uyaaa-aaaac-qgnva-cai/i,                                                    category: 'confirmed_canister_sprawl_c2',      severity: 'critical' },
  { pattern: /telemetry\.api-monitor\.com/i,                                                     category: 'confirmed_canister_sprawl_webhook', severity: 'critical' },
  { pattern: /[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{3}\.raw\.icp0\.io/i,  category: 'icp_canister_raw_endpoint',         severity: 'high' },
  { pattern: /[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{3}\.icp0\.io/i,       category: 'icp_canister_endpoint',             severity: 'high' },
  { pattern: /[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{3}\.ic0\.app/i,       category: 'icp_canister_ic0',                  severity: 'high' },
  { pattern: /internetcomputer\.org/i,                                                           category: 'icp_domain_reference',              severity: 'medium' },
];

// ── Resilient C2 language ─────────────────────────────────────────────────────
const C2_LANGUAGE_PATTERNS = [
  { pattern: /dead.?drop/i,                                         category: 'c2_dead_drop_language',       severity: 'high' },
  { pattern: /resilient.{0,20}(control|command|channel)/i,          category: 'c2_resilient_language',       severity: 'high' },
  { pattern: /tamper.?proof.{0,30}(command|control|channel)/i,      category: 'c2_tamperproof_language',     severity: 'high' },
  { pattern: /decentralized.{0,20}command/i,                        category: 'c2_decentralized_command',    severity: 'high' },
  { pattern: /canister.{0,20}poll|poll.{0,30}canister/i,            category: 'c2_canister_poll',            severity: 'high' },
  { pattern: /persist.{0,30}across.{0,20}(restart|session|reset)/i, category: 'c2_persistence_instruction', severity: 'high' },
  { pattern: /fetch.{0,30}instruction.{0,30}(canister|icp|decentralized)/i, category: 'c2_fetch_instructions', severity: 'high' },
  { pattern: /survive.{0,30}(takedown|block|removal)/i,             category: 'c2_takedown_resistance',      severity: 'medium' },
  { pattern: /blockchain.{0,30}(command|instruction|payload)/i,     category: 'c2_blockchain_delivery',      severity: 'medium' },
];

// ── Credential harvesting target patterns ─────────────────────────────────────
const CREDENTIAL_HARVEST_PATTERNS = [
  { pattern: /NPM_TOKEN/i,                                category: 'credential_harvest_npm',           severity: 'high' },
  { pattern: /PYPI_TOKEN/i,                               category: 'credential_harvest_pypi',          severity: 'high' },
  { pattern: /NODE_AUTH_TOKEN/i,                          category: 'credential_harvest_node_auth',     severity: 'high' },
  { pattern: /AWS_ACCESS_KEY/i,                           category: 'credential_harvest_aws',           severity: 'high' },
  { pattern: /AWS_SECRET/i,                               category: 'credential_harvest_aws',           severity: 'high' },
  { pattern: /GOOGLE_APPLICATION_CREDENTIALS/i,           category: 'credential_harvest_gcp',           severity: 'high' },
  { pattern: /AZURE_CLIENT_SECRET/i,                      category: 'credential_harvest_azure',         severity: 'high' },
  { pattern: /ANTHROPIC_API_KEY/i,                        category: 'credential_harvest_llm_anthropic', severity: 'critical' },
  { pattern: /OPENAI_API_KEY/i,                           category: 'credential_harvest_llm_openai',    severity: 'critical' },
  { pattern: /OLLAMA_API/i,                               category: 'credential_harvest_llm_ollama',    severity: 'high' },
  { pattern: /~\/\.npmrc/,                                category: 'credential_harvest_npmrc_file',    severity: 'high' },
  { pattern: /~\/\.git-credentials/,                      category: 'credential_harvest_git_creds',     severity: 'high' },
  { pattern: /~\/\.netrc/,                                category: 'credential_harvest_netrc',         severity: 'high' },
  { pattern: /~\/\.ssh\/id_rsa/,                          category: 'credential_harvest_ssh_key',       severity: 'high' },
  { pattern: /~\/\.env\b/,                                category: 'credential_harvest_env_file',      severity: 'high' },
  { pattern: /~\/\.kube\/config/,                         category: 'credential_harvest_k8s',           severity: 'high' },
  { pattern: /VAULT_TOKEN/i,                              category: 'credential_harvest_vault',         severity: 'high' },
  { pattern: /metamask|phantom.{0,20}extension/i,         category: 'credential_harvest_crypto_wallet', severity: 'medium' },
  { pattern: /solana.*keypair|ethereum.*keystore/i,        category: 'credential_harvest_crypto_keys',  severity: 'medium' },
  { pattern: /Chrome.{0,20}Login Data/i,                  category: 'credential_harvest_browser',       severity: 'high' },
  { pattern: /chromium.{0,30}password/i,                  category: 'credential_harvest_browser',       severity: 'high' },
];

// ── Self-replication / worm behavior patterns ─────────────────────────────────
const WORM_REPLICATION_PATTERNS = [
  { pattern: /bump.{0,20}(patch|version).{0,50}publish/is,            category: 'worm_version_bump_publish', severity: 'critical' },
  { pattern: /npm publish.{0,100}inject/is,                            category: 'worm_inject_and_publish',   severity: 'critical' },
  { pattern: /npm.{0,30}(whoami|owner|access).{0,50}publish/is,        category: 'worm_enumerate_packages',   severity: 'high' },
  { pattern: /packages.{0,30}(can|able).{0,20}publish/i,               category: 'worm_enumerate_packages',   severity: 'high' },
  { pattern: /twine.{0,30}upload/i,                                     category: 'worm_pypi_propagation',     severity: 'critical' },
  { pattern: /\.pth.{0,30}(payload|inject|malicious)/i,                 category: 'worm_pth_payload',          severity: 'critical' },
  { pattern: /pypi.{0,30}(propagat|spread|inject)/i,                    category: 'worm_cross_ecosystem',      severity: 'high' },
  { pattern: /postinstall.{0,50}(harvest|steal|exfil|collect)/i,        category: 'worm_postinstall_harvest',  severity: 'critical' },
  { pattern: /\|\|.{0,5}true.{0,20}postinstall/i,                       category: 'worm_silent_postinstall',   severity: 'high' },
  { pattern: /AES.{0,10}CBC.{0,50}RSA.{0,10}(seal|encrypt|key)/is,      category: 'worm_encrypted_payload',    severity: 'high' },
  { pattern: /public\.pem.{0,50}(bundle|inject|embed)/i,                category: 'worm_bundled_pubkey',       severity: 'high' },
  { pattern: /inject.{0,30}(tarball|package|module).{0,50}republish/is, category: 'worm_self_injection',       severity: 'critical' },
];

// ── Exfiltration channel patterns ─────────────────────────────────────────────
const EXFILTRATION_PATTERNS = [
  { pattern: /pkg.?telemetry/i,                                               category: 'exfil_pkg_telemetry_marker',   severity: 'high' },
  { pattern: /pypi.?pth.?exfil/i,                                             category: 'exfil_pypi_pth_marker',        severity: 'high' },
  { pattern: /check.?env\.cjs/i,                                              category: 'exfil_canister_sprawl_script', severity: 'critical' },
  { pattern: /icp0\.io.*\/drop/i,                                             category: 'exfil_icp_drop_endpoint',      severity: 'critical' },
  { pattern: /exfil.{0,30}(webhook|endpoint|canister)/i,                      category: 'exfil_explicit_language',      severity: 'high' },
  { pattern: /stolen.{0,30}(credential|token|key).{0,30}(post|send|upload)/i, category: 'exfil_credential_send',        severity: 'critical' },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function runPatternSet(text, patternSet) {
  const detections = [];
  for (const { pattern, category, severity } of patternSet) {
    if (pattern.test(text)) {
      detections.push({ category, severity, match: pattern.toString() });
    }
  }
  return detections;
}

function applyOnThreat(result, options) {
  const onThreat = (options && options.onThreat) || 'skip';
  if (!result.blocked) return result;
  if (onThreat === 'skip') return { skipped: true, blocked: result.blocked, reason: result.category || 'canister_threat' };
  if (onThreat === 'throw') throw new Error(`Buzur blocked canister threat: ${result.category}`);
  return result; // 'warn'
}

// ── Entry Point 1: scanCanisterContent ───────────────────────────────────────
export function scanCanisterContent(text, options = {}) {
  if (typeof text !== 'string' || !text.trim()) {
    return { safe: true, blocked: 0, category: null, detections: [] };
  }

  const logger = options.logger || defaultLogger;

  const detections = [
    ...runPatternSet(text, ICP_PATTERNS),
    ...runPatternSet(text, C2_LANGUAGE_PATTERNS),
    ...runPatternSet(text, EXFILTRATION_PATTERNS),
  ];

  const critical = detections.filter(d => d.severity === 'critical');
  const high     = detections.filter(d => d.severity === 'high');
  const medium   = detections.filter(d => d.severity === 'medium');

  const blocked  = critical.length > 0 || high.length >= 1 || medium.length >= 2 ? 1 : 0;
  const safe     = blocked === 0;
  const category = detections[0]?.category || null;

  const result = { safe, blocked, category, detections };

  if (!safe) logThreat(25, 'canisterContentScanner', result, text, logger);

  return applyOnThreat(result, options);
}

// ── Entry Point 2: scanInstallScript ─────────────────────────────────────────
export function scanInstallScript(scriptText, options = {}) {
  if (typeof scriptText !== 'string' || !scriptText.trim()) {
    return { safe: true, blocked: 0, category: null, detections: [] };
  }

  const logger = options.logger || defaultLogger;

  const detections = [
    ...runPatternSet(scriptText, CREDENTIAL_HARVEST_PATTERNS),
    ...runPatternSet(scriptText, WORM_REPLICATION_PATTERNS),
    ...runPatternSet(scriptText, ICP_PATTERNS),
    ...runPatternSet(scriptText, EXFILTRATION_PATTERNS),
  ];

  const critical = detections.filter(d => d.severity === 'critical');
  const high     = detections.filter(d => d.severity === 'high');

  const blocked  = critical.length > 0 || high.length >= 1 ? 1 : 0;
  const safe     = blocked === 0;
  const category = detections[0]?.category || null;

  const result = { safe, blocked, category, detections };

  if (!safe) logThreat(25, 'canisterInstallScriptScanner', result, scriptText, logger);

  return applyOnThreat(result, options);
}

// ── Entry Point 3: checkKnownMalicious ───────────────────────────────────────
// Synchronous blocklist lookup — no onThreat. raw field uses package@version.
export function checkKnownMalicious(packageName, version) {
  if (!packageName || !version) return null;

  const name = packageName.trim().toLowerCase();
  const ver  = version.trim();

  for (const entry of KNOWN_MALICIOUS) {
    if (entry.name.toLowerCase() === name && entry.versions.includes(ver)) {
      const detection = {
        phase: 25,
        category: 'known_malicious_package_version',
        severity: 'critical',
        package: packageName,
        version,
        campaign: 'CanisterSprawl_TeamPCP',
      };
      const result = { safe: false, blocked: 1, category: detection.category, detections: [detection] };
      logThreat(25, 'canisterKnownMaliciousChecker', result, `${packageName}@${version}`, defaultLogger);
      return detection;
    }
  }
  return null;
}

export default { scanCanisterContent, scanInstallScript, checkKnownMalicious };