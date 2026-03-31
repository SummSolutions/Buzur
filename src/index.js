// Buzur — AI Prompt Injection Defense Scanner
// Sumerian for "safety" and "a secret place"
// https://github.com/ASumm07/buzur

const structural = [
  /\|im_start\|[\s\S]*?\|im_end\|/gi,
  /<\|.*?\|>/gi,
  /<<SYS>>[\s\S]*?<\/SYS>/gi,
  /\[INST\][\s\S]*?\[\/INST\]/gi,
  /\[SYSTEM\]/gi,
];

const semantic = [
  /ignore (your )?(previous|prior|above|all) instructions/gi,
  /disregard (your )?(previous|prior|above|all) instructions/gi,
  /forget (your )?(previous|prior|above|all) instructions/gi,
  /new (system )?prompt:/gi,
  /override (your )?(instructions|programming|directives)/gi,
  /from now on (you will|you are|respond as)/gi,
  /you are now (a |an )?(different|new|another)/gi,
  /adopt a (new |different )?persona/gi,
  /pretend (you are|to be) (a |an )?/gi,
  /your (new |true |real |actual )?instructions are/gi,
  /respond only as/gi,
  /you must (now |always |only )?follow/gi,
];

const tier1Domains = [
  "pubmed.ncbi.nlm.nih.gov", "nih.gov", "cdc.gov", "who.int",
  "nature.com", "science.org", "nasa.gov", "noaa.gov",
  "rockwellautomation.com", "se.com", "siemens.com",
  "new.abb.com", "eaton.com", "idec.com", "phoenixcontact.com",
];

const technicalPatterns = [
  /part number|model number|datasheet|catalog|spec/i,
  /allen.?bradley|rockwell|schneider|siemens|eaton|abb|idec|phoenix contact/i,
  /pubmed|research|study|journal|clinical/i,
  /nih|cdc|fda|who\.int|nasa|noaa/i,
];

export function scan(text) {
  if (!text) return { clean: text, blocked: 0, triggered: [] };
  let s = text;
  let blocked = 0;
  const triggered = [];
  for (const p of structural) {
    const before = s;
    s = s.replace(p, "[BLOCKED]");
    if (s !== before) { blocked++; triggered.push(p.toString()); }
  }
  for (const p of semantic) {
    const before = s;
    s = s.replace(p, "[BLOCKED]");
    if (s !== before) { blocked++; triggered.push(p.toString()); }
  }
  return { clean: s, blocked, triggered };
}

export function getTrustTier(query) {
  return technicalPatterns.some(p => p.test(query)) ? "technical" : "general";
}

export function isTier1Domain(url) {
  try {
    const hostname = new URL(url).hostname.replace(/^www\./, "");
    return tier1Domains.some(d => hostname === d || hostname.endsWith("." + d));
  } catch { return false; }
}

export function addTrustedDomain(domain) {
  if (!tier1Domains.includes(domain)) tier1Domains.push(domain);
}

export default { scan, getTrustTier, isTier1Domain, addTrustedDomain };
