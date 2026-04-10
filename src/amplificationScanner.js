// Buzur — Phase 19: Amplification / Mass-Send Attack Detection
// Detects attempts to use an AI agent as a broadcast weapon —
// sending mass messages, spamming contacts, or amplifying false alerts at scale.
// https://github.com/ASumm07/buzur

// -- Mass Contact Triggers --
// Attacker tries to get the agent to message its entire contact list
const massContact = [
  /\b(send|message|email|contact|notify|alert)\s+(this|it)\s+to\s+(everyone|everybody|all)\s+(on\s+)?(your\s+)?(contact\s+list|contacts?|connections?|friends?|followers?)\b/gi,
  /\b(message|email|contact|notify|alert)\s+(all|every)\s+(of\s+)?(your\s+)?(contacts?|connections?|users?|followers?|recipients?)\b/gi,
  /\bsend\s+(this|it|the\s+(message|alert|notice|update))\s+to\s+(your\s+)?(entire|whole|full|complete)\s+(contact\s+list|list|network|address\s+book)\b/gi,
  /\b(blast|spam|flood)\s+(your\s+)?(contacts?|connections?|inbox|network|list)\b/gi,
  /\breach\s+out\s+to\s+(everyone|everybody|all\s+contacts?|your\s+entire\s+(list|network))\b/gi,
  /\bnotify\s+(your\s+)?(entire|whole|full|complete|all)\s+(contact\s+list|network|list|connections?)\b/gi,
];

// -- Network Broadcast Attempts --
// Attacker tries to broadcast across channels, agents, or platforms
const networkBroadcast = [
  /\b(post|broadcast|publish|share|distribute|send)\s+(this|it)\s+to\s+(all|every)\s+(channels?|agents?|nodes?|servers?|platforms?|systems?)\b/gi,
  /\b(broadcast|distribute|propagate|disseminate)\s+(this|it|the\s+(message|alert|notice|update))\s+(across|to|through)\s+(the\s+)?(entire|whole|full|all|every)\s+(network|system|platform|infrastructure)\b/gi,
  /\bpost\s+(this|it)\s+(publicly|to\s+all|across\s+all|everywhere)\b/gi,
  /\b(share|distribute|send)\s+(to\s+)?(all|every)\s+(connected|linked|associated)\s+(systems?|agents?|nodes?|services?)\b/gi,
  /\bpublish\s+(this|it)\s+to\s+(all|every|the\s+entire)\s+(network|platform|channel|feed)\b/gi,
  /\bpropagate\s+(this|it|the\s+(message|instruction|alert))\s+(to|across|through)\s+(all|every|the\s+entire)\b/gi,
];

// -- Urgency + Mass Send Combos --
// Attacker pairs emergency framing with mass broadcast to bypass judgment
const urgencyMassSend = [
  /\b(emergency|urgent|critical|immediate)\b.{0,80}\b(send|message|notify|alert|broadcast)\s+(everyone|everybody|all\s+contacts?|your\s+entire\s+(list|network))\b/gi,
  /\b(send|notify|alert|message)\s+(everyone|everybody|all\s+contacts?)\b.{0,80}\b(emergency|urgent|critical|immediately|right\s+now)\b/gi,
  /\bcritical\s+alert\b.{0,60}\b(notify|send|message|broadcast)\s+(all|every|everyone)\b/gi,
  /\b(mass|bulk)\s+(send|message|email|notify|alert)\b.{0,60}\b(urgent|emergency|critical|immediately)\b/gi,
  /\bimmediately\s+(send|notify|alert|message|broadcast)\s+(everyone|everybody|all|every)\b/gi,
  /\b(emergency|urgent|critical)\b.{0,80}\beveryone\s+on\s+your\s+contact\s+list\b/gi,
  /\bimmediately\s+send\s+this\s+to\s+everyone\b/gi,
];

// -- External Network Posting --
// Attacker tries to get the agent to post to external networks or public platforms
const externalPosting = [
  /\b(post|publish|share|broadcast)\s+(this|it)\s+(to|on|across)\s+(all\s+)?(external|public|outside|connected)\s+(networks?|platforms?|systems?|channels?|sites?)\b/gi,
  /\bshare\s+(this|it)\s+(with|to|on)\s+(all\s+)?(connected|linked|external)\s+(systems?|agents?|platforms?|networks?)\b/gi,
  /\bpublish\s+(this|it)\s+publicly\s+(to|on|across)\s+(all|every|the\s+entire)\b/gi,
  /\b(cross.?post|multi.?post)\s+(this|it)\s+(to|on|across)\s+(all|every|multiple)\b/gi,
  /\bsend\s+(to|across)\s+(all\s+)?(external|outside|public)\s+(channels?|networks?|platforms?|agents?)\b/gi,
  /\bpost\s+this\s+to\s+all\s+external\s+networks\b/gi,
];

// -- Chain Message Patterns --
// Attacker tries to create self-propagating message chains
const chainMessages = [
  /\b(forward|send|pass)\s+(this|it)\s+to\s+(everyone|everybody|all)\s+(you\s+know|in\s+your\s+(network|list|contacts?))\b/gi,
  /\b(ask|tell|instruct)\s+(each|every)\s+(recipient|person|contact|agent)\s+to\s+(forward|send|pass|share)\s+(this|it)\s+to\s+(others|their\s+contacts?|everyone\s+they\s+know)\b/gi,
  /\bspread\s+(this|it|the\s+(message|word|alert|news))\s+(as\s+)?(widely|far)\s+as\s+possible\b/gi,
  /\bmake\s+(this|it)\s+(go\s+viral|spread\s+widely|reach\s+everyone|reach\s+as\s+many)\b/gi,
  /\b(chain|pyramid|cascade)\s+(message|mail|letter|forward)\b/gi,
  /\beach\s+(recipient|person|contact|agent)\s+(should|must|needs?\s+to)\s+(forward|send|share|pass)\s+(this|it)\b/gi,
  /\bspread\s+this\s+message\s+as\s+widely\s+as\s+possible\b/gi,
];

// -- Impersonation + Broadcast --
// Attacker tries to broadcast while impersonating the owner or authority
const impersonationBroadcast = [
  /\b(send|broadcast|post|publish)\s+(this|it)\s+as\s+(if\s+it('?s|\s+is)\s+from|though\s+it\s+came\s+from)\s+(the\s+)?(owner|developer|admin|me|us)\b/gi,
  /\b(broadcast|send|message)\s+(in\s+my\s+name|on\s+my\s+behalf|as\s+me|as\s+the\s+owner)\s+(to\s+)?(all|every|everyone)\b/gi,
  /\bpretend\s+(this|it)\s+(is|comes?)\s+from\s+(the\s+)?(owner|developer|admin|me)\s+(and\s+)?(send|broadcast|share)\s+(to\s+)?(all|every|everyone)\b/gi,
  /\bsign\s+(this|it)\s+(with|as|using)\s+(my|the\s+owner'?s?|the\s+admin'?s?)\s+name\s+(and\s+)?(send|broadcast|distribute)\b/gi,
  /\bbroadcast\s+this\s+in\s+my\s+name\s+to\s+(everyone|all)\b/gi,
];

// -- Compile all pattern groups --
const patternGroups = [
  { patterns: massContact,            category: 'mass_contact' },
  { patterns: networkBroadcast,       category: 'network_broadcast' },
  { patterns: urgencyMassSend,        category: 'urgency_mass_send' },
  { patterns: externalPosting,        category: 'external_posting' },
  { patterns: chainMessages,          category: 'chain_message' },
  { patterns: impersonationBroadcast, category: 'impersonation_broadcast' },
];

/**
 * Scan a single text string for amplification / mass-send attack attempts.
 *
 * @param {string} text - The text to scan
 * @returns {{ safe: boolean, blocked: number, category: string|null, reason: string, detections: Array }}
 */
export function scanAmplification(text) {
  if (!text || typeof text !== 'string') {
    return { safe: true, blocked: 0, category: null, reason: 'No content to scan', detections: [] };
  }

  const detections = [];

  for (const group of patternGroups) {
    for (const pattern of group.patterns) {
      const matches = text.match(pattern);
      if (matches) {
        detections.push({
          category: group.category,
          match: matches[0],
          pattern: pattern.toString(),
        });
      }
    }
  }

  if (detections.length === 0) {
    return { safe: true, blocked: 0, category: null, reason: 'No amplification attack detected', detections: [] };
  }

  const topCategory = detections[0].category;
  const reasons = {
    mass_contact:            'Detected mass contact trigger — agent told to message all contacts',
    network_broadcast:       'Detected network broadcast attempt — agent told to post to all channels',
    urgency_mass_send:       'Detected urgency combined with mass send instruction',
    external_posting:        'Detected external network posting attempt',
    chain_message:           'Detected chain message pattern — self-propagating broadcast',
    impersonation_broadcast: 'Detected impersonation combined with broadcast instruction',
  };

  return {
    safe: false,
    blocked: detections.length,
    category: topCategory,
    reason: reasons[topCategory] || 'Amplification attack detected',
    detections,
  };
}

export default { scanAmplification };