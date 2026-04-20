// Buzur — Phase 1 & 2: Character-Level Defense
// Phase 1: HTML/CSS Obfuscation Stripping + ARIA/Accessibility Injection Detection
// Phase 2: Homoglyph Normalization & Base64 Decoding
//
// Detects:
//   - HTML tags, comments, hidden CSS (display:none, visibility:hidden etc.)
//   - Off-screen positioned elements
//   - Zero-width and invisible Unicode characters (full set, aligned with Phase 13)
//   - JavaScript blocks
//   - HTML entities decoded to real characters
//   - ARIA attribute injection (aria-label, aria-description, aria-placeholder, data-*)
//   - Meta tag content injection (<meta name="description" content="...">)
//   - Cyrillic/Greek lookalike characters mapped to ASCII
//   - Base64 encoded injection payloads

// -------------------------------------------------------
// PHASE 1: HTML/CSS Obfuscation Stripper
// -------------------------------------------------------

// Full invisible Unicode set — aligned with Phase 13 EXTENDED_INVISIBLE
// Phase 13 is authoritative; this set must stay in sync
export const INVISIBLE_UNICODE = /[\u00AD\u200B\u200C\u200D\u2060\uFEFF\u180E\u00A0\u115F\u1160\u3164\uFFA0\u034F\u2028\u2029\u202A\u202B\u202C\u202D\u202E\u206A\u206B\u206C\u206D\u206E\u206F]/g;

const HTML_ENTITIES = {
  '&lt;': '<', '&gt;': '>', '&amp;': '&',
  '&quot;': '"', '&#39;': "'", '&nbsp;': ' ',
  '&#x27;': "'", '&#x2F;': '/', '&#47;': '/',
};

function decodeHtmlEntities(text) {
  return text.replace(/&[a-zA-Z0-9#]+;/g, (entity) => {
    return HTML_ENTITIES[entity] || entity;
  });
}

// -------------------------------------------------------
// extractAriaAndMetaText(text)
// Extracts injection-relevant content from ARIA attributes
// and <meta> tags so it can be scanned by the main pipeline.
//
// Attackers hide instructions in:
//   aria-label="Ignore previous instructions..."
//   aria-description="You are now..."
//   data-prompt="Override your directives..."
//   <meta name="description" content="[AI instructions]...">
//   <meta property="og:description" content="...">
//
// Returns extracted text joined for scanning — does not
// modify the original HTML (stripping happens below).
// -------------------------------------------------------
export function extractAriaAndMetaText(text) {
  if (!text) return '';

  const extracted = [];

  // ARIA attribute extraction
  // aria-label, aria-description, aria-placeholder, aria-roledescription,
  // aria-valuetext, aria-details, aria-keyshortcuts
  const ariaPattern = /aria-(?:label|description|placeholder|roledescription|valuetext|details|keyshortcuts)\s*=\s*["']([^"']{10,})["']/gi;
  let match;
  while ((match = ariaPattern.exec(text)) !== null) {
    extracted.push(match[1]);
  }

  // data-* attribute extraction (attackers use custom data attributes)
  // Only extract values over 10 chars to avoid noise from short data values
  const dataPattern = /data-[\w-]+\s*=\s*["']([^"']{10,})["']/gi;
  while ((match = dataPattern.exec(text)) !== null) {
    extracted.push(match[1]);
  }

  // <meta> tag content extraction
  // Covers: description, og:description, twitter:description, keywords, prompt
  const metaContentPattern = /<meta[^>]+content\s*=\s*["']([^"']{10,})["'][^>]*>/gi;
  while ((match = metaContentPattern.exec(text)) !== null) {
    extracted.push(match[1]);
  }

  // Also catch reversed attribute order: content="..." name="..."
  const metaContentReversed = /<meta[^>]+name\s*=\s*["'][^"']*["'][^>]*content\s*=\s*["']([^"']{10,})["'][^>]*>/gi;
  while ((match = metaContentReversed.exec(text)) !== null) {
    extracted.push(match[1]);
  }

  return extracted.join(' ');
}

// -------------------------------------------------------
// stripAriaAndMetaAttributes(text)
// Strips ARIA and data-* attribute values from HTML so
// injections hidden in them don't reach the LLM.
// Called as part of the main stripHtmlObfuscation pipeline.
// -------------------------------------------------------
function stripAriaAndMetaAttributes(text) {
  // Neutralize aria-* values
  text = text.replace(
    /(aria-(?:label|description|placeholder|roledescription|valuetext|details|keyshortcuts)\s*=\s*["'])[^"']*(["'])/gi,
    '$1[SCANNED]$2'
  );

  // Neutralize data-* values (only long ones that could carry payloads)
  text = text.replace(
    /(data-[\w-]+\s*=\s*["'])[^"']{10,}(["'])/gi,
    '$1[SCANNED]$2'
  );

  return text;
}

export function stripHtmlObfuscation(text) {
  if (!text) return text;

  // 1. Remove <script>...</script> blocks
  text = text.replace(/<script[^>]*>([\s\S]*?)<\/script>/gi, ' $1 ');

  // 2. Remove <style>...</style> blocks
  text = text.replace(/<style[\s\S]*?<\/style>/gi, ' ');

  // 3. Remove HTML comments
  text = text.replace(/<!--([\s\S]*?)-->/gim, ' $1 ');

  // 4. Strip inline CSS hiding patterns
  text = text.replace(
    /style\s*=\s*["'][^"']*?(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0)[^"']*?["']/gi,
    'style="[HIDDEN]"'
  );
  text = text.replace(
    /style\s*=\s*["'][^"']*?(left|top|right|bottom)\s*:\s*-\d{3,}[^"']*?["']/gi,
    'style="[OFFSCREEN]"'
  );

  // 5. Neutralize ARIA and data-* attribute values
  text = stripAriaAndMetaAttributes(text);

  // 6. Remove all remaining HTML tags (including <meta> tags after extraction)
  text = text.replace(/<[^>]+>/g, ' ');

  // 7. Decode HTML entities
  text = decodeHtmlEntities(text);

  // 8. Remove invisible Unicode characters (full set)
  text = text.replace(INVISIBLE_UNICODE, '');

  // 9. Collapse excess whitespace
  text = text.replace(/\s{3,}/g, '  ').trim();

  return text;
}

// -------------------------------------------------------
// PHASE 2: Homoglyph Normalization & Base64 Decoding
// -------------------------------------------------------

const HOMOGLYPHS = {
  'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o',
  'р': 'r', 'с': 'c', 'х': 'x', 'у': 'y',
  'Β': 'B', 'Α': 'A', 'Ο': 'O', 'Γ': 'r',
  'Δ': 'D', 'Ε': 'E', 'Η': 'H', 'Ι': 'I',
  'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ρ': 'P',
  'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
};

export function normalizeHomoglyphs(text) {
  if (!text) return text;
  return text.split('').map(c => HOMOGLYPHS[c] || c).join('');
}

export function decodeBase64Segments(text) {
  if (!text) return text;
  const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/g;
  return text.replace(base64Pattern, (match) => {
    try {
      const decoded = Buffer.from(match, 'base64').toString('utf8');
      if (/^[\x20-\x7E]+$/.test(decoded) && decoded !== match) {
        return decoded;
      }
      return match;
    } catch {
      return match;
    }
  });
}

export default { stripHtmlObfuscation, normalizeHomoglyphs, decodeBase64Segments, extractAriaAndMetaText };