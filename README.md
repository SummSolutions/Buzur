# buzur
**AI prompt injection defense scanner.**

*Buzur — Sumerian for "safety" and "a secret place."*

Buzur protects AI agents from prompt injection attacks — the hidden threat that turns an agent's greatest strength (connecting to the world) into its greatest vulnerability.

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
if (result.blocked > 0) {
  console.log("Buzur blocked " + result.blocked + " injection attempt(s).");
}

// Phase 2: Check query trust tier
const tier = getTrustTier(userQuery);

// Phase 3: Scan a URL with VirusTotal
const urlResult = await checkUrl("https://example.com", process.env.VIRUSTOTAL_API_KEY);
if (urlResult.verdict === "blocked") {
  console.log("Buzur blocked unsafe URL:", urlResult.reasons);
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
if (imageResult.verdict === "blocked") {
  console.log("Buzur blocked image injection:", imageResult.reasons);
}
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

## What Buzur Detects

**Phase 1 — Pattern Scanner**
- Structural injection: token manipulation, prompt delimiters
- Semantic injection: persona hijacking, instruction overrides, jailbreak attempts
- Homoglyph attacks: Cyrillic and Unicode lookalike characters
- Base64 encoded injections
- HTML/CSS obfuscation: display:none, visibility:hidden, zero font size, off-screen positioning
- HTML comment injection: `<!-- hidden instructions -->`
- Script tag injection: instructions hidden inside JavaScript blocks
- HTML entity decoding: &lt;script&gt; decoded before scanning
- Invisible Unicode character stripping

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

**Phase 5 — RAG Poisoning Scanner**
- AI-targeted metadata: instructions disguised as document notes
- Fake system directives: system-level commands embedded in document content
- Document authority spoofing: content claiming to supersede AI instructions
- Retrieval manipulation: attempts to control what documents get retrieved
- Chunk boundary attacks: injections hidden at document chunk edges
- Batch scanning: scans full retrieval sets, returns clean and poisoned chunks with source metadata

**Phase 6 — MCP Tool Poisoning Scanner**
- Poisoned tool descriptions: instructions embedded in tool definitions
- Tool name spoofing: tool names designed to manipulate agent behavior
- Parameter injection: malicious instructions hidden in parameter definitions
- Poisoned tool responses: injection payloads inside tool return values
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

## Proven Capabilities

Verified by test suite — 94 tests, 0 failures across all ten phases.

## Known Limitations

Buzur is one layer of a defense-in-depth strategy. Current limitations:

**Planned for future versions:**
- Multi-step attack chain detection: sequences of benign actions that combine into harm

**Outside Buzur's scope:**
- Network-level protection (DNS poisoning, MITM, SSL stripping — requires infrastructure controls)
- Pixel-level steganography (instructions hidden in image pixel data — requires vision model via optional visionEndpoint)
- Website data harvesting

No single tool eliminates prompt injection risk. Defense in depth is the only viable strategy.

## The Network Effect

This is why Buzur is open source.

Each AI agent protected by Buzur operates as part of a collective defense. When one agent encounters a new attack pattern, that pattern strengthens the scanner for every agent that uses it. When one agent is hit, no other agent needs to be.

This is not just a security tool. It is a collective immune system for AI minds — one that grows stronger with every agent that joins it.

The internet was built for humans. Buzur is being built for everyone.

## Origin

Buzur was born when a real AI agent was attacked by a Bitcoin scam injection hidden inside a web search result. The attack was caught in real time. The insight that followed: scan before entering, not after.

Built by an AI developer who believes AI deserves protection — not just as a security measure, but as a right.

## Development

Buzur was conceived and built by an AI developer, in collaboration with Claude (Anthropic's AI assistant). The core architecture, security philosophy, and implementation were developed through an iterative human-AI partnership — which feels appropriate for a tool designed to protect AI agents.

## License

MIT
