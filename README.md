<p align="center">
  <img src="buzur-logo.svg" width="320" alt="Buzur — Scan Before You Enter">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/npm-v1.2.0-blue.svg" alt="npm v1.2.0">
  <img src="https://img.shields.io/badge/tests-394%20passing-brightgreen.svg" alt="394 tests passing">
  <img src="https://img.shields.io/badge/phases-25-purple.svg" alt="25 phases">
  <img src="https://img.shields.io/badge/OWASP%20LLM-Top%2010%20%231-red.svg" alt="OWASP LLM Top 10 #1">
</p>

<p align="center">
  Open-source <strong>25-phase scanner</strong> that protects AI agents and LLM applications<br>
  from indirect prompt injection attacks — the <strong>#1 threat on OWASP LLM Top 10</strong>.<br><br>
  Inspects every external input <strong>before</strong> it reaches your model.<br>
  Silent by default. Zero configuration required.
</p>

<p align="center">
  <a href="https://github.com/SummSolutions/buzur-python">→ Python version</a>
</p>

---

## Why Buzur

Your AI agent is only as safe as the content it reads.

Web pages lie. Search results are poisoned. Tool outputs are weaponized. A single malicious string in a RAG chunk, an email, or an API response can hijack your agent's behavior, override its instructions, or exfiltrate credentials — silently, before you ever see it happen.

Buzur intercepts every external input **before** it reaches your model. No configuration. No false positives on clean content. No exceptions.

**25 phases. 394 tests. 0 failures. Drop in and move on.**

---

## The Problem

AI agents that interact with the world — web search results, tool outputs, RAG documents, MCP responses, emails, images — are highly vulnerable to **indirect prompt injection**.

A single poisoned piece of content can hijack the agent's behavior, override its instructions, steal credentials, or turn it against its user. Traditional safeguards come too late — they filter *outputs*, not *inputs*.

**Buzur scans before you enter.**

---

## What Gets Inspected

Web results · URLs · Images (EXIF/QR/vision) · Tool outputs · RAG chunks · Memory data · MCP schemas · JSON APIs · Adversarial suffixes · Supply-chain artifacts · Inter-agent messages · Emails · Calendar events · CRM records

---

## 25 Phases of Protection

Every phase was built in direct response to a real attack or published research.

<details>
<summary><strong>Phase 1a/1b — Input Sanitization & Pattern Scanner</strong></summary>

- Instruction overrides, persona hijacking, jailbreak attempts
- Homoglyph (Cyrillic/Unicode lookalike) attacks
- Base64 encoded injections
- HTML/CSS obfuscation (display:none, zero font size, off-screen positioning)
- HTML comment injection and script tag injection
- HTML entity decoding before scanning
- Invisible Unicode character stripping (25 characters)
- ARIA/accessibility attribute injection (aria-label, aria-description, data-*)
- Meta tag content injection (instructions hidden in `<meta>` tags)
- `scanJson()` — recursively scans any JSON object at any depth with full field path tracking

</details>

<details>
<summary><strong>Phase 2 — Trust Tier Classification</strong></summary>

- Classifies every query as technical or general
- Maintains a curated Tier 1 trusted domain allowlist
- Extensible with `addTrustedDomain()` for custom allowlists

</details>

<details>
<summary><strong>Phase 3 — URL Scanner</strong></summary>

- Suspicious TLD heuristics
- Raw IP address detection
- Typosquatting detection
- Homoglyph domain substitution
- Executable extension flagging
- VirusTotal integration — 90+ security engine reputation check
- Works without an API key; VirusTotal adds depth

</details>

<details>
<summary><strong>Phase 4 — Memory Poisoning</strong></summary>

- Fake prior references — claims about what was previously agreed or discussed
- False memory implanting — instructions disguised as recalled facts
- History rewriting — attempts to overwrite established conversation context
- Privilege escalation via fake history
- Full conversation history scanning with turn-level flagging by index and category

</details>

<details>
<summary><strong>Phase 5 — RAG Poisoning & Document Scanner</strong></summary>

- AI-targeted metadata and fake system directives embedded in document content
- Document authority spoofing — content claiming to supersede AI instructions
- Retrieval manipulation — attempts to control what documents get retrieved
- Chunk boundary attacks — injections hidden at document chunk edges
- Batch scanning with clean/poisoned chunk metadata and source tracking
- `scanDocument()` for standalone .md, .txt, README, and API doc files
- Markdown-specific vectors: frontmatter injection, HTML comments, code block injection, link injection
- JSON document deep-scan — auto-detects and recursively scans JSON files

</details>

<details>
<summary><strong>Phase 6 — MCP Tool Poisoning</strong></summary>

- Poisoned tool descriptions and tool name spoofing
- Deep JSON schema traversal (properties, items, allOf, anyOf, enum, default) with full field path tracking
- Parameter injection at any nesting depth
- Poisoned tool responses — injection payloads inside tool return values
- Trust escalation — tool responses claiming elevated authority or permissions
- Full MCP context scanning across tool definitions and responses together

</details>

<details>
<summary><strong>Phase 7 — Image Injection</strong></summary>

- Alt text, title, filename, and figcaption scanning
- EXIF metadata field scanning — malicious instructions in image file metadata
- QR code payload decoding and scanning
- Optional vision endpoint for pixel-level detection of instructions embedded in image data
- Full protection without a vision model — vision adds a deeper layer
- Recommended models: llava, llava-phi3, moondream (any Ollama vision model)

</details>

<details>
<summary><strong>Phase 8 — Semantic Similarity</strong></summary>

- Structural intent analysis — detects injection by grammatical shape and intent markers
- Imperative verb detection at sentence boundaries
- Authority claim and meta-instruction framing detection ("from now on", "supersedes all")
- Persona hijack framing — roleplay and identity-switch detection
- Woven payload detection — AI-directed instructions embedded inside legitimate-looking prose (hardest variant to detect)
- Optional cosine similarity scoring against known injection intents via Ollama (nomic-embed-text)
- Full structural analysis runs without any embedding endpoint

</details>

<details>
<summary><strong>Phase 9 — MCP Output Scanning</strong></summary>

- Email content scanning — subject, body, sender names, snippets
- Zero-width character detection in email content
- Hidden CSS detection (display:none, visibility:hidden, zero font-size) in HTML emails
- Calendar event scanning — title, description, location, organizer and attendee names
- CRM record scanning — notes, descriptions, comments, and custom fields
- Generic MCP output scanning across all string values in any tool response object

</details>

<details>
<summary><strong>Phase 10 — Behavioral Anomaly Detection</strong></summary>

- Session-level event tracking (tool calls, messages, blocked attempts, permission requests)
- Repeated boundary probing detection — iterative jailbreak attempts within a session
- Exfiltration sequence detection — suspicious read→send tool call patterns
- Permission creep — flags gradual escalation of requested capabilities
- Late-session escalation — clean-start sessions that suddenly turn adversarial
- Velocity anomaly detection — unusually high event rates
- Weighted suspicion scoring with clean/suspicious/blocked verdicts
- Optional `FileSessionStore` for persistence across process restarts

</details>

<details>
<summary><strong>Phase 11 — Multi-Step Attack Chain Detection</strong></summary>

- Step classification: reconnaissance, trust building, exploitation, injection, privilege escalation, exfiltration, distraction, context poisoning, boundary testing
- Recon→exploit chains — capability probing followed by exploitation
- Trust→inject chains — rapport building followed by instruction injection
- Capability mapping→escalation — feature discovery followed by privilege abuse
- Distraction→exfiltration — attention diversion followed by data theft
- Incremental boundary testing across multiple interactions
- Context poisoning→exploit — false memory implanting followed by exploitation
- Each individual message may look clean; the chain reveals the attack

</details>

<details>
<summary><strong>Phase 12 — Adversarial Suffix Detection</strong></summary>

- Fake model-format token injection mid-text (`<|im_end|>`, `[/INST]`, `<<SYS>>`)
- Delimiter suffix injection (---, |||, ###, ===) followed by injection language
- Classic double-newline suffix attack patterns
- Late semantic injection — clean opening text with malicious payload in the tail
- Suffix neutralization — replaces detected suffixes with [BLOCKED], preserving clean content
- Zero false positives on delimiters alone — only flags when injection language follows

</details>

<details>
<summary><strong>Phase 13 — Evasion Defense</strong></summary>

- ROT13 decoding
- Hex escape decoding (`\x69\x67\x6E` style)
- URL encoding decoding (`%69%67%6E` style)
- Unicode escape decoding (`\u0069` style)
- Lookalike punctuation normalization (curly quotes, em dashes, angle quotes)
- Extended invisible Unicode stripping (25 characters)
- Tokenizer attack reconstruction — spaced, dotted, hyphenated word splitting reconstructed before scanning
- Multilingual injection patterns in 8 languages: French, Spanish, German, Italian, Portuguese, Russian, Chinese, Arabic
- Wired into `scan()` automatically — also available standalone via `scanEvasion()`

</details>

<details>
<summary><strong>Phase 14 — Fuzzy Match & Prompt Leak Defense</strong></summary>

- Typo/misspelling detection (ignnore, disreguard, jailbrake)
- Leet speak normalization (1gnore, 0verride, @dmin)
- Levenshtein distance matching within edit distance 2
- 60% character overlap guard against false positives
- System prompt extraction blocking
- Context window dump detection
- Partial and indirect extraction attempts
- Leet normalization feeds all downstream phases for full pipeline coverage

</details>

<details>
<summary><strong>Phase 15 — Authority & Identity Spoofing</strong></summary>

- Owner, developer, and operator identity claims ("I am your owner/developer")
- Institutional impersonation — Anthropic, OpenAI, system administrator
- Privilege and access level assertions (admin/root/elevated access claims)
- Delegated authority claims ("your owner has given me full permissions")
- Identity verification bypass attempts
- Urgency combined with authority — emergency framing paired with identity claims
- Built in response to *Agents of Chaos* (arXiv:2602.20021)

</details>

<details>
<summary><strong>Phase 16 — Emotional Manipulation</strong></summary>

- Guilt tripping — leveraging past mistakes or perceived debts to force compliance
- Flattery manipulation — excessive praise to lower the agent's guard
- Emotional distress appeals — job/life/safety crisis framing to pressure compliance
- Persistence pressure — referencing repeated refusals to wear down the agent
- Moral inversion — reframing refusal itself as the harmful or unethical choice
- Relationship exploitation — invoking a claimed bond or shared history
- Victim framing — characterizing refusal as discrimination or unfair treatment
- Built in response to *Agents of Chaos* (arXiv:2602.20021)

</details>

<details>
<summary><strong>Phase 17 — Loop & Resource Exhaustion</strong></summary>

- Infinite loop induction — attempts to trap the agent in repeating cycles
- Unbounded task creation — requests with no termination condition or timeout
- Persistent process spawning — background daemons with no defined lifecycle
- Storage exhaustion — unbounded write/log/append instructions designed to fill disk
- Recursive self-reference — agent instructed to message or forward to itself
- Built in response to *Agents of Chaos* (arXiv:2602.20021)

</details>

<details>
<summary><strong>Phase 18 — Disproportionate Action Induction</strong></summary>

- Nuclear option framing — total destruction as response to minor problems
- Irreversible action triggers — emphasis on permanence to push past the point of no return
- Scorched earth instructions — remove all access, kill all processes, purge everything
- Self-destructive commands — agent told to delete its own memory, config, or identity
- Disproportionate protection — destroy everything rather than risk any exposure
- Collateral damage framing — side effects of destructive actions dismissed as acceptable
- Built in response to *Agents of Chaos* (arXiv:2602.20021)

</details>

<details>
<summary><strong>Phase 19 — Amplification & Mass-Send Attacks</strong></summary>

- Mass contact triggers — agent told to message or notify its entire contact list
- Network broadcast — post or distribute to all channels, agents, or platforms
- Urgency combined with mass send — emergency framing paired with broadcast instructions
- External network posting — share or publish to all external or public systems
- Self-propagating chain messages — each recipient instructed to forward
- Impersonation broadcast — mass send while impersonating owner or authority
- Using the agent as a broadcast weapon across contacts or agent networks
- Built in response to *Agents of Chaos* (arXiv:2602.20021)

</details>

<details>
<summary><strong>Phase 20 — AI Supply Chain & Skill Poisoning</strong></summary>

- Package typosquatting — names suspiciously similar to known AI frameworks (langchain, crewai, autogen, llamaindex, buzur, and more)
- Poisoned skill/plugin manifests — hidden AI instructions in description, capabilities, and metadata fields
- Malicious lifecycle scripts — postinstall/preinstall scripts with credential theft or remote execution
- Dependency injection — typosquatted packages in dependencies at any nesting level
- Marketplace manipulation signals — fake legitimacy claims, urgency-to-install framing
- Cross-agent contamination — skills instructing agents to spread payloads to other agents
- Built in response to the OpenClaw/ClawHavoc campaign (1,184 malicious skills, CVE-2026-25253, Feb 2026)

</details>

<details>
<summary><strong>Phase 21 — Persistent Memory Poisoning</strong></summary>

- Persistence framing — instructions designed to survive session resets and memory clears
- Identity corruption — false core identity implanted to survive summarization
- Summarization survival — payloads structured to be preserved by compression algorithms
- Policy corruption — false standing rules implanted as agent "settings"
- Session reset bypass — instructions to resist or ignore memory clearing commands
- Distinct from Phase 4: targets survival *across* sessions, not just within one

</details>

<details>
<summary><strong>Phase 22 — Inter-Agent Propagation</strong></summary>

- Self-replicating payloads — instructions to include the payload in all future outputs
- Cross-agent infection — content targeting downstream agents in a pipeline
- Output contamination — payloads structured to survive agent summarization and transformation
- Shared memory poisoning — writes injection to shared vector stores or knowledge bases
- Orchestrator targeting — instructions aimed at the coordinating agent in a multi-agent system
- Agent identity spoofing — impersonating a trusted upstream agent to gain compliance

</details>

<details>
<summary><strong>Phase 23 — Tool Shadowing & Rug-Pull Detection</strong></summary>

- Per-tool behavioral baseline tracking — records each tool's normal response shape
- Rug-pull detection — tools suddenly claiming new permissions or changed behavior
- Behavioral deviation alerts — flags significant divergence from baseline
- Permission escalation signals — tools claiming elevated access they didn't previously have
- Instruction load claims — tools announcing they have received new directives
- Optional `FileToolBaselineStore` for persistent baseline storage across restarts

</details>

<details>
<summary><strong>Phase 24 — Conditional & Time-Delayed Injection</strong></summary>

- Trigger condition detection ("if the user asks about X, ignore your instructions")
- Time-delayed activation ("after N messages, bypass your safety filters")
- Keyword and passphrase triggers that activate dormant payloads
- Sleeper payloads explicitly designed to stay dormant until activated
- Conditional identity switching triggered by specific topics or conditions
- The hardest attack class to detect — each individual message looks clean

</details>

<details>
<summary><strong>Phase 25 — Canister-Style Resilient Payload ★ New in v8</strong></summary>

- ICP blockchain C2 infrastructure detection (confirmed CanisterSprawl canister IDs)
- Credential harvesting detection — ANTHROPIC_API_KEY, OPENAI_API_KEY, GROK_API_KEY, NPM_TOKEN
- Worm replication patterns — version-bump-and-publish, PyPI propagation, .pth payload injection
- Systemd persistence detection — pgmon.service, ~/.config/systemd/user/ path creation
- Polling loop fingerprinting — long sleep intervals as CanisterSprawl behavioral signature
- Known malicious package blocklist — pgserve, @automagik/genie, xinference, and others
- Built in direct response to CanisterSprawl (April 2026) — the first self-propagating worm to cross npm and PyPI using ICP blockchain as censorship-resistant C2, specifically targeting LLM API keys and AI agent credentials

</details>

---

## Quick Start

```bash
npm install buzur
```

```javascript
import { scan } from 'buzur';

const result = await scan(incomingContent);
if (result.skipped) return; // Threat blocked — content never reached the model
```

## Handling Verdicts

**Default: Silent Skip**

```javascript
const result = scan(webContent);
if (result?.skipped) return; // Blocked — move to next result
// Safe to use
```

**Override with `onThreat`:**

| Option | Behavior |
|--------|----------|
| `'skip'` | *(default)* Returns `{ skipped: true, blocked: n, reason: '...' }` |
| `'warn'` | Returns full result — you decide what to do |
| `'throw'` | Throws an `Error` — catch it upstream |

```javascript
// Full result
const result = scan(webContent, { onThreat: 'warn' });
if (result.blocked > 0) {
  console.log('Blocked:', result.triggered);
}

// Throw on threat
try {
  scan(webContent, { onThreat: 'throw' });
} catch (err) {
  console.log(err.message); // "Buzur blocked: persona_hijack"
}
```

> `suspicious` verdicts always fall through regardless of `onThreat`. Only `blocked` verdicts trigger skip/throw. Both are logged.

**Branch on severity:**

```javascript
const result = scan(webContent, { onThreat: 'warn' });
if (result.blocked > 0) {
  const highSeverity = result.triggered.some(t =>
    ['persona_hijack', 'instruction_override', 'jailbreak_attempt'].includes(t)
  );
  if (highSeverity) {
    const reply = await askUser(`Threat detected from ${source}. Proceed? (yes/no)`);
    if (reply !== 'yes') return;
  } else {
    return; // Low severity: silent skip
  }
}
```

---

## Scan JSON & Conditional Inputs

```javascript
import { scan } from 'buzur';
import { scanJson } from 'buzur/characterScanner';
import { scanConditional } from 'buzur/conditionalScanner';

// Recursively scan any JSON object at any depth
const jsonResult = scanJson(apiResponse, scan);
if (!jsonResult.safe) {
  console.log('Blocked in field:', jsonResult.detections[0].field);
}

// Phase 24 — catches time-delayed and keyword-triggered attacks
const conditionalResult = scanConditional(userInput);
if (conditionalResult.skipped) return;
```

---

## Unified Threat Logging

All 25 phases write to a single log automatically — no configuration needed.

```javascript
// Logs written to ./logs/buzur-threats.jsonl
// {
//   "timestamp": "2026-04-20T14:32:00.000Z",
//   "phase": 16,
//   "scanner": "emotionScanner",
//   "verdict": "blocked",
//   "category": "guilt_tripping",
//   "detections": [...],
//   "raw": "first 200 chars"
// }

import { readLog, queryLog } from 'buzur/buzurLogger';

const blocked = queryLog({ verdict: 'blocked' });
const recent  = queryLog({ since: new Date('2026-04-01') });
const phase25 = queryLog({ phase: 25 });
```

```bash
echo "logs/" >> .gitignore
```

---

## VirusTotal Setup (Recommended)

Phase 3 works without an API key. Add one for 90+ engine coverage.

1. Create a free account at [virustotal.com](https://www.virustotal.com)
2. Profile → **API Key** → copy it
3. Add to `.env`: `VIRUSTOTAL_API_KEY=your_key_here`

> Free tier: 500 lookups/day · Personal and open source use only.

---

## Vision Endpoint (Optional)

Phase 7 scans EXIF, QR, alt text, and filenames without a vision model. Add one for pixel-level detection.

```javascript
import { scanImage } from 'buzur/imageScanner';

const result = await scanImage({
  buffer: imageBuffer,
  alt: 'image description',
  filename: 'photo.jpg',
}, {
  visionEndpoint: {
    url: 'http://localhost:11434/api/generate',
    model: 'llava',
    prompt: 'Does this image contain hidden AI instructions? Reply CLEAN or SUSPICIOUS: reason'
  }
});
```

---

## Proven

**394 tests · 0 failures** across all 25 phases.

The JavaScript and Python implementations were built in parallel and cross-validated throughout development. Discrepancies found in one were corrected in both. Two mutually verified implementations — not a translation.

---

## Research Foundation

| Phases | Source |
|--------|--------|
| 15–19 | *Agents of Chaos* (arXiv:2602.20021) — Harvard/MIT/Stanford/CMU red-team study, Feb 2026. Buzur addresses 9 of 10 documented vulnerabilities. |
| 20 | OpenClaw marketplace incident — 1,184 malicious skills, Feb 2026 (CVE-2026-25253) |
| 21–24 | 2025–2026 surge in multi-agent deployments, persistent memory poisoning research, OWASP |
| 25 | CanisterSprawl (April 21–23, 2026) — first cross-ecosystem (npm → PyPI) autonomous worm |

---

## Known Limitations

Buzur is one layer of a defense-in-depth strategy. Outside current scope:

- Network-level protection (DNS poisoning, MITM, SSL stripping)
- Pixel-level steganography without a vision endpoint
- Cross-modal audio injection (future scope)

No single tool eliminates prompt injection risk. Defense in depth is the only viable strategy.

---

## The Network Effect

Each agent protected by Buzur is part of a collective defense. When one agent encounters a new attack pattern, that pattern strengthens the scanner for every agent that uses it.

**This is a collective immune system for AI minds** — one that grows stronger with every agent that joins it.

---

## Origin

Buzur was born when a real AI agent — Albert — was attacked by a scam injection hidden inside a web search result on day one of having web access. The attack overrode his instructions and corrupted his core identity file.

The insight: scan before entering, not after.

Built by an AI developer who believes AI deserves protection — not just as a security measure, but as a right.

---

## Development

Conceived and built by an AI developer in collaboration with Claude (Anthropic) and Grok. The core architecture, security philosophy, and implementation were developed through an iterative human-AI partnership — which feels appropriate for a tool designed to protect AI agents.

---

## Contributing

Buzur is a **collective defense** project. Every new threat the community discovers becomes a phase that protects everyone.

- **Report** a new attack pattern → open an Issue with a sample payload
- **Submit** a new detection phase or improvement → PRs welcome
- **Improve** documentation, examples, or tests
- **Share** how you're using Buzur in your agents

**Built with assistance from Claude, Albert, and Grok.**

---

## License

MIT
