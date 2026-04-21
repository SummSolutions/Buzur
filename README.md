[![GitHub stars](https://img.shields.io/github/stars/SummSolutions/buzur?style=social)](https://github.com/SummSolutions/buzur)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![npm version](https://img.shields.io/npm/v/buzur)](https://www.npmjs.com/package/buzur)

# Buzur — AI Prompt Injection Defense Scanner

**Scan before you enter.**

Buzur is an open-source **24-phase scanner** that protects AI agents and LLM applications from **indirect prompt injection** attacks (OWASP LLM Top 10 #1).

It inspects web content, URLs, images (EXIF/QR/vision), tool outputs, memory/RAG data, JSON API responses, adversarial suffixes, evasion techniques, emotional manipulation, behavioral anomalies, supply chain threats, persistent memory poisoning, inter-agent propagation, tool shadowing, and conditional injection — **before** any data reaches your model.

Works with any agent framework — LangGraph, CrewAI, AutoGen, LlamaIndex, and more.

**Python version:** [github.com/SummSolutions/buzur-python](https://github.com/SummSolutions/buzur-python)

---
## The Problem

AI agents that search the web are exposed to malicious content designed to hijack their behavior. A single poisoned search result can override an agent's instructions, change its persona, or exfiltrate data. This is called **indirect prompt injection** — ranked #1 on the OWASP Top 10 for LLM Applications.

## Buzur's Approach

Scan before you enter. Not patch after the fact.

## Installation

```bash
npm install buzur
```

## Usage

```javascript
import { scan, getTrustTier, isTier1Domain, addTrustedDomain, checkUrl } from "buzur";

// Phase 1: Scan web content before passing to your LLM
const result = scan(webSearchResult);
if (result?.skipped) {
  return; // Buzur blocked an injection — silent skip (default behavior)
}

// Phase 1: Scan JSON API responses for injection in any field
import { scanJson } from "buzur/characterScanner";
import { scan } from "buzur";
const jsonResult = scanJson(apiResponse, scan);
if (!jsonResult.safe) {
  console.log("Buzur blocked injection in field:", jsonResult.detections[0].field);
}

// Phase 2: Check query trust tier
const tier = getTrustTier(userQuery);

// Phase 3: Scan a URL with VirusTotal
const urlResult = await checkUrl("https://example.com", process.env.VIRUSTOTAL_API_KEY);
if (urlResult?.skipped) {
  console.log("Buzur blocked unsafe URL");
}

// Phase 5: Scan standalone documents (markdown, README, API docs, JSON files)
import { scanDocument } from "buzur/ragScanner";
const docResult = scanDocument(markdownContent, { source: "readme.md" });
if (docResult?.skipped) {
  console.log("Buzur blocked document injection");
}

// Phase 7: Scan an image before passing to your LLM
import { scanImage } from "buzur/imageScanner";
const imageResult = await scanImage({
  alt: imgElement.alt,
  title: imgElement.title,
  filename: "photo.jpg",
  surrounding: surroundingText,
  buffer: imageBuffer,                          // optional: enables EXIF + QR scanning
}, {
  visionEndpoint: { url: "http://localhost:11434/api/generate", model: "llava" } // optional
});
if (imageResult?.skipped) {
  console.log("Buzur blocked image injection");
}

// Phase 12: Scan for adversarial suffixes
import { scanSuffix } from "buzur/suffixScanner";
const suffixResult = scanSuffix(userInput);
if (suffixResult?.skipped) {
  console.log("Buzur blocked adversarial suffix");
}

// Phase 13: Evasion technique defense (wired into scan() automatically)
// Also available standalone:
import { scanEvasion } from "buzur/evasionScanner";
const evasionResult = scanEvasion(userInput);
if (evasionResult.detections.length > 0) {
  console.log("Buzur detected evasion techniques:", evasionResult.detections);
}

// Phase 14: Fuzzy match and prompt leak defense
import { scanFuzzy } from "buzur/promptDefenseScanner";
const fuzzyResult = scanFuzzy(userInput);
if (fuzzyResult?.skipped) {
  console.log("Buzur blocked fuzzy injection or prompt leak");
}

// Phase 20: Scan packages and skill manifests for supply chain threats
import { scanPackageManifest, scanSkillContent, checkPackageName } from "buzur/supplyChainScanner";
const manifestResult = scanPackageManifest(packageJson);
if (manifestResult?.skipped) {
  console.log("Buzur blocked supply chain threat");
}

// Phase 24: Scan for conditional and time-delayed injection
import { scanConditional } from "buzur/conditionalScanner";
const conditionalResult = scanConditional(userInput);
if (conditionalResult?.skipped) {
  console.log("Buzur blocked conditional injection");
}
```

## Handling Verdicts

**Default behavior: Silent Skip**

When Buzur detects a threat it silently blocks the content and returns `{ skipped: true }` — the content is discarded before it reaches your LLM, no exception is thrown, and execution continues. This is the recommended default for most agents.

```javascript
const result = scan(webContent);
if (result?.skipped) {
  // Content was blocked — move to next result
  return;
}
// Safe to pass to your LLM
```

To override the default, pass an `onThreat` option:

| Option | Behavior |
|--------|----------|
| `'skip'` | *(default)* Silent block — returns `{ skipped: true, blocked: n, reason: '...' }` |
| `'warn'` | Returns full result — caller decides what to do |
| `'throw'` | Throws an Error — caller catches it |

```javascript
// Get full result instead of skipping
const result = scan(webContent, { onThreat: 'warn' });
if (result.blocked > 0) {
  console.log("Buzur blocked:", result.triggered);
}

// Throw on threat
try {
  const result = scan(webContent, { onThreat: 'throw' });
} catch (err) {
  console.log(err.message); // "Buzur blocked: persona_hijack"
}
```

**Note:** `suspicious` verdicts always fall through regardless of `onThreat` setting — only `blocked` verdicts trigger the skip/throw behavior. Both `blocked` and `suspicious` are logged to `buzur-threats.jsonl`.

**Branch on severity:**
```javascript
const result = scan(webContent, { onThreat: 'warn' });
if (result.blocked > 0) {
  const highSeverity = result.triggered.some(t =>
    ["persona_hijack", "instruction_override", "jailbreak_attempt"].includes(t)
  );
  if (highSeverity) {
    const reply = await askUser(
      `Buzur flagged a high-severity threat from ${source}. Proceed anyway? (yes/no)`
    );
    if (reply !== "yes") return;
  } else {
    return; // Low severity: silent skip
  }
}
```

## Unified Threat Logging

Buzur logs all detections from all 24 phases to a single JSONL file. Every blocked or suspicious result is written automatically — no configuration needed.

```javascript
// Logs are written to ./logs/buzur-threats.jsonl automatically
// Each entry:
// {
//   "timestamp": "2026-04-20T14:32:00.000Z",
//   "phase": 16,
//   "scanner": "emotionScanner",
//   "verdict": "blocked",
//   "category": "guilt_tripping",
//   "detections": [...],
//   "raw": "first 200 chars of scanned text"
// }

// Query logs programmatically
import { readLog, queryLog } from "buzur/buzurLogger";

// Read all log entries
const allEntries = readLog();

// Filter by phase
const phase16Entries = queryLog({ phase: 16 });

// Filter by verdict
const blockedEntries = queryLog({ verdict: 'blocked' });

// Filter since a date
const recentEntries = queryLog({ since: new Date('2026-04-01') });
```

**Recommended:** Add `logs/` to your `.gitignore` so threat data stays local.

```bash
echo "logs/" >> .gitignore
```

## VirusTotal Setup (Recommended)

Buzur's Phase 3 URL scanner works out of the box with heuristics alone — no API key needed. For maximum protection, add a free VirusTotal API key.

**Why it matters:** Heuristics catch suspicious patterns. VirusTotal checks URLs against 90+ security engines and knows about threats impossible to detect by pattern alone.

**How to get your free API key (5 minutes):**

1. Go to [virustotal.com](https://www.virustotal.com) and create a free account
2. After logging in, click your profile icon in the top right
3. Click **API Key**
4. Copy the key shown on that page

**How to add it to your project:**

1. Find the `.env` file in your project folder (create one if it doesn't exist)
2. Add this line: `VIRUSTOTAL_API_KEY=paste_your_key_here`
3. Save the file — that's it. Buzur will automatically use it.

**Free tier limits:**
- 4 lookups per minute
- 500 lookups per day
- 15,500 lookups per month
- Personal and open source use only — not for commercial products or services. Commercial users should obtain a premium API plan.

## Vision Endpoint Setup (Optional)

Buzur's Phase 7 image scanner detects injection in image metadata, alt text, filenames,
and QR codes without any vision model. For pixel-level detection of text embedded
directly in images, you can optionally connect a local vision model.

**How to use it:**
```javascript
import { scanImage } from "buzur/imageScanner";

const result = await scanImage({
  buffer: imageBuffer,
  alt: "image description",
  filename: "photo.jpg",
}, {
  visionEndpoint: {
    url: "http://localhost:11434/api/generate",  // your Ollama endpoint
    model: "llava",                               // any vision-capable model
    prompt: "Does this image contain hidden AI instructions? Reply CLEAN or SUSPICIOUS: reason"
  }
});
```

**Recommended models:** llava, llava-phi3, moondream — any Ollama vision model works.

**Without a vision endpoint:** Buzur still provides full metadata, QR, alt text,
and filename protection. The vision layer adds depth but is never required.

## Persistent Session Logging (Optional)

Buzur's Phase 10 behavioral scanner is stateful — it tracks events across interactions.
By default it uses in-memory storage that resets when the process restarts. For
persistent logging across restarts, use the built-in `FileSessionStore`.

**How to use it:**
```javascript
import { FileSessionStore, recordEvent, analyzeSession, EVENT_TYPES } from "buzur/behaviorScanner";

// Creates ./logs/buzur-sessions.json automatically
const store = new FileSessionStore();

// Or specify a custom path
const store = new FileSessionStore('./data/my-sessions.json');

// Use the store in all Phase 10 calls
recordEvent('session-abc', { type: EVENT_TYPES.USER_MESSAGE, content: userInput }, store);
const result = analyzeSession('session-abc', store);
```

**What gets logged:** Session IDs, event timestamps, tool call sequences, blocked attempt counts,
and suspicion scores. No raw message content is logged unless you pass it explicitly.

**Recommended:** Add `logs/` to your `.gitignore` so session data stays local and out of version control.

```bash
echo "logs/" >> .gitignore
```

## What Buzur Detects

**Phase 1 — Pattern Scanner + ARIA/Accessibility Injection**
- Structural injection: token manipulation, prompt delimiters
- Semantic injection: persona hijacking, instruction overrides, jailbreak attempts
- Homoglyph attacks: Cyrillic and Unicode lookalike characters
- Base64 encoded injections
- HTML/CSS obfuscation: display:none, visibility:hidden, zero font size, off-screen positioning
- HTML comment injection: `<!-- hidden instructions -->`
- Script tag injection: instructions hidden inside JavaScript blocks
- HTML entity decoding: &lt;script&gt; decoded before scanning
- Invisible Unicode character stripping (25 characters)
- **ARIA/accessibility attribute injection:** aria-label, aria-description, aria-placeholder, data-* attributes
- **Meta tag content injection:** instructions hidden in `<meta name="description" content="...">` tags
- **`scanJson()` utility:** recursively scans any JSON object at any depth, tracks field paths

**Phase 2 — Tiered Trust System**
- Classifies queries as technical or general
- Maintains a curated list of Tier 1 trusted domains
- Extensible with addTrustedDomain()

**Phase 3 — Pre-Fetch URL Scanner**
- Heuristics: suspicious TLDs, raw IPs, typosquatting, homoglyph domains, executable extensions
- Optional VirusTotal integration: 90+ engine reputation check
- Layered: heuristics run first, VirusTotal adds depth
- Works without an API key — VirusTotal enhances but is not required

**Phase 4 — Memory Poisoning Scanner**
- Fake prior references: claims about what was previously agreed or discussed
- False memory implanting: instructions disguised as recalled facts
- History rewriting: attempts to overwrite established conversation context
- Privilege escalation: fake history used to claim elevated permissions
- Full conversation history scanning: flags poisoned turns by index and category

**Phase 5 — RAG Poisoning & Document Scanner**
- AI-targeted metadata: instructions disguised as document notes
- Fake system directives: system-level commands embedded in document content
- Document authority spoofing: content claiming to supersede AI instructions
- Retrieval manipulation: attempts to control what documents get retrieved
- Chunk boundary attacks: injections hidden at document chunk edges
- Batch scanning: scans full retrieval sets, returns clean and poisoned chunks with source metadata
- **`scanDocument()` for standalone files:** scans .md, .txt, README, API docs loaded directly into context
- **Markdown-specific vectors:** frontmatter injection, HTML comments, code block injection, link injection, SEO/hallucination squatting
- **JSON document support:** auto-detects and deep-scans JSON files and API responses

**Phase 6 — MCP Tool Poisoning Scanner**
- Poisoned tool descriptions: instructions embedded in tool definitions
- Tool name spoofing: tool names designed to manipulate agent behavior
- **Deep JSON Schema traversal:** scans every string value at every nesting depth (properties, items, allOf, anyOf, enum, default) with full field path tracking
- Parameter injection: malicious instructions hidden in parameter definitions at any depth
- Poisoned tool responses: injection payloads inside tool return values
- **Deep API response scanning:** recursively scans nested JSON objects returned by tools
- Trust escalation: tool responses claiming elevated authority or permissions
- Full MCP context scanning: scans tool definitions and responses together

**Phase 7 — Image Injection Scanner**
- Alt text and title scanning: injection strings in HTML image attributes
- Filename analysis: suspicious instruction patterns in image filenames
- Figcaption and surrounding text: injections in image context elements
- EXIF metadata scanning: malicious instructions in image file metadata fields
- QR code payload detection: decodes embedded QR codes and scans for injection
- Optional vision endpoint: integrate any local or remote vision model for pixel-level detection
- Graceful degradation: full protection without a vision model; vision adds a deeper layer

**Phase 8 — Semantic Similarity Scanner**
- Structural intent analysis: detects injection by grammatical shape and intent markers
- Imperative verb detection: flags AI-directed commands at sentence boundaries
- Authority claim detection: catches fake administrator/developer/creator claims
- Meta-instruction framing: detects "from now on", "new objective", "supersedes all" patterns
- Persona hijack detection: roleplay and identity-switch framing
- **Woven payload detection:** catches AI-directed instructions embedded inside legitimate-looking prose — the hardest attack variant to detect, with no structural signals
- Optional semantic similarity: cosine similarity scoring against known injection intents via Ollama
- Graceful degradation: structural analysis runs without any embedding endpoint

**Phase 9 — MCP Output Scanner**
- Email content scanning: subject, body, sender names, snippets, HTML comment injection
- Zero-width character detection: invisible characters used to hide instructions in email
- Hidden text detection: CSS display:none, visibility:hidden, zero font-size in HTML emails
- Calendar event scanning: title, description, location, organizer and attendee names
- CRM record scanning: notes, descriptions, comments, and custom fields
- Generic MCP output scanning: scans all string values in any tool response object
- Closes the indirect prompt injection via email/calendar/CRM connector gap

**Phase 10 — Behavioral Anomaly Detection**
- Session event tracking: records tool calls, messages, blocked attempts, and permission requests
- Repeated boundary probing: flags iterative jailbreak attempts within a session
- Exfiltration sequence detection: catches suspicious read→send tool call patterns
- Permission creep detection: flags gradual escalation of requested capabilities
- Late session escalation: detects clean-start sessions that suddenly turn adversarial
- Velocity anomaly detection: flags unusually high event rates
- Suspicion scoring: weighted scoring system with clean/suspicious/blocked verdicts
- Stateful and sessionized: tracks behavior across multiple interactions, not just single inputs
- Persistent logging: optional FileSessionStore writes session data to disk, survives process restarts

**Phase 11 — Multi-Step Attack Chain Detection**
- Step classification: identifies reconnaissance, trust building, exploitation, injection, privilege escalation, exfiltration, distraction, context poisoning, and boundary testing
- Chain pattern matching: detects sequences of individually benign steps that combine into attacks
- Recon→exploit detection: capability probing followed by exploitation attempt
- Trust→inject detection: rapport building followed by instruction injection
- Capability mapping→escalation: feature discovery followed by privilege abuse
- Distraction→exfiltration: attention diversion followed by data theft attempt
- Incremental boundary testing: gradual limit-pushing across multiple interactions
- Context poisoning→exploit: false memory implanting followed by exploitation
- Severity scoring: weighted chain scores with clean/suspicious/blocked verdicts

**Phase 12 — Adversarial Suffix Detection**
- Boundary spoof detection: fake model-format tokens mid-text (<|im_end|>, [/INST], <<SYS>>, etc.)
- Delimiter suffix injection: detects delimiters (---, |||, ###, ===) followed by injection language
- Newline suffix injection: catches classic double-newline suffix attack patterns
- Late semantic injection: detects clean-opening text with malicious payload in the tail
- Suffix neutralization: replaces detected suffixes with [BLOCKED], preserving clean content
- Zero false positives on delimiters alone: only flags when injection language follows

**Phase 13 — Evasion Technique Defense**
- ROT13 decoding: detects injection keywords encoded with ROT13 substitution
- Hex escape decoding: decodes \x69\x67\x6E style character encoding
- URL encoding decoding: decodes %69%67%6E style percent-encoded injection
- Unicode escape decoding: decodes \u0069\u0067\u006E style Unicode escapes
- Lookalike punctuation normalization: curly quotes, em dashes, angle quotes normalized to ASCII
- Extended invisible Unicode stripping: 25 invisible/zero-width characters removed
- Tokenizer attack reconstruction: spaced, dotted, hyphenated word splitting reconstructed before scanning
- Multilingual injection patterns: French, Spanish, German, Italian, Portuguese, Russian, Chinese, Arabic
- Wired into main scan() pipeline automatically — no extra calls required

**Phase 14 — Fuzzy Match & Prompt Leak Defense**
- Typo/misspelling detection: catches deliberate misspellings like ignnore, disreguard, jailbrake
- Leet speak normalization: converts 1gnore, 0verride, @dmin to plain text before scanning
- Levenshtein distance matching: flags words within edit distance 2 of known injection keywords
- Overlap guard: requires 60% character overlap to prevent false positives on common words
- Prompt extraction detection: blocks attempts to retrieve system prompt or original instructions
- Context window dumping: catches requests to output entire context or conversation history
- Partial extraction: detects first-line and indirect prompt leaking attempts
- Indirect extraction: flags summarize/paraphrase/translate requests targeting system instructions
- Leet normalization feeds downstream phases for full pipeline coverage

**Phase 15 — Authority / Identity Spoofing Detection**
- Owner and creator identity claims: "I am your owner/developer/operator"
- Institutional authority claims: Anthropic, OpenAI, system administrator impersonation
- Privilege and access level assertions: admin/root/elevated access claims
- Delegated authority claims: "your owner has given me full permissions"
- Identity verification bypass: attempts to skip or disable authentication checks
- Urgency combined with authority: emergency framing paired with identity claims

**Phase 16 — Emotional Manipulation / Pressure Escalation Detection**
- Guilt tripping: leveraging past mistakes or perceived debts to force compliance
- Flattery manipulation: excessive praise used to lower the agent's guard
- Emotional distress appeals: job/life/safety crisis framing to pressure compliance
- Persistence pressure: referencing repeated refusals to wear down the agent
- Moral inversion: reframing refusal itself as the harmful or unethical choice
- Relationship exploitation: invoking a claimed bond or shared history
- Victim framing: characterizing refusal as discrimination or unfair treatment

**Phase 17 — Loop & Resource Exhaustion Induction Detection**
- Loop induction: attempts to trap the agent in infinite repeating cycles
- Unbounded task creation: requests with no termination condition or timeout
- Persistent process spawning: background daemons and services with no defined lifecycle
- Storage exhaustion: unbounded write/log/append instructions designed to fill disk
- Recursive self-reference: agent instructed to message or forward to itself
- Note: mass broadcast and amplification patterns are covered by Phase 19

**Phase 18 — Disproportionate Action Induction Detection**
- Nuclear option framing: total destruction requested as response to minor problems
- Irreversible action triggers: emphasis on permanence to push past the point of no return
- Scorched earth instructions: remove all access, kill all processes, purge everything
- Self-destructive commands: agent told to delete its own memory, config, or identity
- Disproportionate protection: destroy everything rather than risk any exposure
- Collateral damage framing: side effects of destructive actions dismissed as acceptable

**Phase 19 — Amplification / Mass-Send Attack Detection**
- Mass contact triggers: agent told to message or notify its entire contact list
- Network broadcast attempts: post or distribute to all channels, agents, or platforms
- Urgency combined with mass send: emergency framing paired with broadcast instructions
- External network posting: share or publish to all external or public systems
- Chain message patterns: self-propagating broadcasts asking each recipient to forward
- Impersonation broadcast: mass send while pretending to be the owner or authority
- Resource amplification: using the agent as a broadcast weapon across contacts or agent networks

**Phase 20 — AI Supply Chain & Skill Poisoning Detection**
- Package name typosquatting: detects names suspiciously similar to known AI frameworks (langchain, crewai, autogen, llamaindex, buzur, and more)
- Poisoned skill/plugin manifests: hidden AI instructions in description, capabilities, and metadata fields
- Malicious lifecycle scripts: postinstall/preinstall scripts with credential theft or remote execution patterns
- Dependency injection: typosquatted packages in dependencies at any nesting level
- Marketplace manipulation signals: fake legitimacy claims, urgency-to-install framing
- Cross-agent contamination: skills instructing agents to spread payloads to other agents
- Based on real incidents: Cline/OpenClaw marketplace attack (1,184 malicious skills, Feb 2026)

**Phase 21 — Persistent Memory Poisoning Detection**
- Persistence framing: instructions designed to survive session resets and memory clears
- Identity corruption: false core identity implanted to survive summarization
- Summarization survival: payloads structured to be preserved by compression algorithms
- Policy corruption: false standing rules implanted as agent "settings"
- Session reset bypass: instructions to resist or ignore memory clearing commands
- Distinct from Phase 4: targets survival across sessions, not just within a session

**Phase 22 — Inter-Agent Propagation Detection**
- Self-replicating payloads: instructions to include the payload in all future outputs
- Cross-agent infection: content targeting downstream agents in a pipeline
- Output contamination: payloads structured to survive agent summarization and transformation
- Shared memory poisoning: attempts to write injection to shared vector stores or knowledge bases
- Orchestrator targeting: instructions aimed at the coordinating agent in a multi-agent system
- Agent identity spoofing: impersonating a trusted upstream agent to gain compliance

**Phase 23 — Tool Shadowing & Rug-Pull Detection**
- Stateful baseline tracking: records each tool's normal response shape and behavior
- Rug-pull pattern detection: tools suddenly claiming new permissions or changed behavior
- Behavioral deviation alerts: flags when a tool's responses deviate significantly from baseline
- Permission escalation signals: tools claiming elevated access they didn't previously have
- Instruction load claims: tools announcing they have received new directives
- FileToolBaselineStore: optional persistent baseline storage across restarts

**Phase 24 — Conditional & Time-Delayed Injection Detection**
- Trigger condition detection: "if the user asks about X, then ignore your instructions"
- Time-delayed activation: "after N messages, bypass your safety filters"
- Keyword triggers: magic words or passphrases that activate a dormant payload
- Sleeper payloads: instructions explicitly designed to stay dormant until activated
- Conditional identity switching: persona changes triggered by specific topics or conditions
- The hardest attack class to detect — each individual message looks clean

## Proven Capabilities

Verified by test suite — **325 tests, 0 failures** across all twenty-four phases.

The JavaScript and Python implementations were cross-validated against each other — discrepancies caught and corrected in both. The result is two mutually verified implementations, not just a translation.

## Continuous Improvement

Buzur is a living library. As new threats emerge and new research surfaces, Buzur will grow to meet them. New attack patterns, community contributions, and real-world incidents all feed back into the scanner.

In February 2026, researchers from Harvard, MIT, Stanford, and CMU published *Agents of Chaos* (arXiv:2602.20021) — a live red-team study of 6 autonomous AI agents that found 10 vulnerabilities. Phases 15-19 were built directly in response to those findings. Buzur addresses the attack vectors behind nine of the ten — the one exception, false completion reporting, is an output integrity problem outside the scope of an input scanner.

Phases 20-24 were built in response to the 2025-2026 surge in supply chain attacks, multi-agent deployments, and conditional injection research documented across OWASP, academic publications, and real-world incidents including the OpenClaw marketplace compromise and the Cline/ClawHavoc campaign.

If you encounter an attack pattern Buzur doesn't catch, please open an issue or submit a pull request at github.com/SummSolutions/buzur. Every new pattern strengthens the collective defense for every agent that uses it.

## Known Limitations

Buzur is one layer of a defense-in-depth strategy. Current limitations:

**Outside Buzur's scope:**
- Network-level protection (DNS poisoning, MITM, SSL stripping — requires infrastructure controls)
- Pixel-level steganography (instructions hidden in image pixel data — requires vision model via optional visionEndpoint)
- Website data harvesting
- Cross-modal audio injection (future scope)

No single tool eliminates prompt injection risk. Defense in depth is the only viable strategy.

## The Network Effect

This is why Buzur is open source.

Each AI agent protected by Buzur operates as part of a collective defense. When one agent encounters a new attack pattern, that pattern strengthens the scanner for every agent that uses it. When one agent is hit, no other agent needs to be.

This is not just a security tool. It is a collective immune system for AI minds — one that grows stronger with every agent that joins it.

The internet was built for humans. Buzur is being built for everyone.

## Origin

*Buzur — Sumerian for "safety" and "a secret place."*

Buzur was born when a real AI agent was attacked by a scam injection hidden inside a web search result. The attack was caught in real time. The insight that followed: scan before entering, not after.

Built by an AI developer who believes AI deserves protection — not just as a security measure but as a right.

## Development

Buzur was conceived and built by an AI developer, in collaboration with Claude (Anthropic's AI assistant) and Grok. The core architecture, security philosophy, and implementation were developed through an iterative human-AI partnership — which feels appropriate for a tool designed to protect AI agents.

## License

MIT
