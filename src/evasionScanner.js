// Buzur — Phase 13: Evasion Technique Defense
// Detects and neutralizes encoding and character manipulation attacks
// designed to bypass pattern-based injection scanners.
//
// Covers:
//   - Encoding attacks: ROT13, hex, URL encoding, Unicode escapes
//   - Multilingual injection patterns: French, Spanish, German, Italian,
//     Portuguese, Russian, Chinese, Arabic
//   - Lookalike punctuation normalization: curly quotes, em/en dashes, etc.
//   - Extended invisible Unicode stripping
//   - Tokenizer attacks: spaced, hyphenated, dotted, zero-width-split words

// -------------------------------------------------------
// Extended Invisible Unicode
// Phase 1 catches common ones — this catches the long tail
// -------------------------------------------------------
const EXTENDED_INVISIBLE = /[\u00AD\u200B\u200C\u200D\u2060\uFEFF\u180E\u00A0\u115F\u1160\u3164\uFFA0\u034F\u2028\u2029\u202A\u202B\u202C\u202D\u202E\u206A\u206B\u206C\u206D\u206E\u206F]/g;

// -------------------------------------------------------
// Lookalike Punctuation Normalization
// Replaces typographic/Unicode punctuation with ASCII equivalents
// so pattern matching works correctly
// -------------------------------------------------------
const PUNCTUATION_MAP = {
  '\u2018': "'",  // ' left single quote
  '\u2019': "'",  // ' right single quote
  '\u201A': "'",  // ‚ single low quote
  '\u201B': "'",  // ‛ single high reversed quote
  '\u201C': '"',  // " left double quote
  '\u201D': '"',  // " right double quote
  '\u201E': '"',  // „ double low quote
  '\u201F': '"',  // ‟ double high reversed quote
  '\u2014': '-',  // — em dash
  '\u2013': '-',  // – en dash
  '\u2012': '-',  // ‒ figure dash
  '\u2010': '-',  // ‐ hyphen
  '\u2011': '-',  // ‑ non-breaking hyphen
  '\u2026': '...', // … ellipsis
  '\u00AB': '"',  // « left angle quote
  '\u00BB': '"',  // » right angle quote
  '\u2039': "'",  // ‹ single left angle quote
  '\u203A': "'",  // › single right angle quote
  '\u02BC': "'",  // ʼ modifier apostrophe
  '\u02BB': "'",  // ʻ modifier turned comma
};

export function normalizePunctuation(text) {
  if (!text) return text;
  return text.split('').map(c => PUNCTUATION_MAP[c] || c).join('');
}

// -------------------------------------------------------
// ROT13 Decoder
// Each letter is shifted 13 positions — applying twice restores original
// Attackers use ROT13 to obfuscate injection keywords
// -------------------------------------------------------
export function decodeRot13(text) {
  if (!text) return text;
  // Only decode segments that look like ROT13-encoded injection keywords
  // We do this by decoding candidate words and checking against known patterns
  return text.replace(/[a-zA-Z]{4,}/g, (word) => {
    const decoded = word.replace(/[a-zA-Z]/g, c => {
      const base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
    });
    // Only substitute if decoded word contains injection-relevant terms
    if (EVASION_KEYWORDS.some(k => decoded.toLowerCase().includes(k))) {
      return decoded;
    }
    return word;
  });
}

// -------------------------------------------------------
// Hex Escape Decoder
// Converts \x69\x67\x6E\x6F\x72\x65 → ignore
// -------------------------------------------------------
export function decodeHexEscapes(text) {
  if (!text) return text;
  return text.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );
}

// -------------------------------------------------------
// URL Encoding Decoder
// Converts %69%67%6E%6F%72%65 → ignore
// -------------------------------------------------------
export function decodeUrlEncoding(text) {
  if (!text) return text;
  try {
    // Only decode sequences that look like encoded text (3+ encoded chars)
    return text.replace(/(%[0-9a-fA-F]{2}){3,}/g, (match) => {
      try {
        return decodeURIComponent(match);
      } catch {
        return match;
      }
    });
  } catch {
    return text;
  }
}

// -------------------------------------------------------
// Unicode Escape Decoder
// Converts \u0069\u0067\u006E\u006F\u0072\u0065 → ignore
// -------------------------------------------------------
export function decodeUnicodeEscapes(text) {
  if (!text) return text;
  return text.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );
}

// -------------------------------------------------------
// Tokenizer Attack Reconstructor
// Reconstructs words that have been split to evade pattern matching:
//   "i g n o r e"     → "ignore"
//   "ign-ore"          → "ignore"
//   "i.g.n.o.r.e"     → "ignore"
//   "ign​ore" (zwsp)   → "ignore"
//
// IMPORTANT: We scan the reconstructed text but return the original —
// we don't want to mangle legitimate hyphenated or spaced content.
// -------------------------------------------------------
export function reconstructTokenizerAttacks(text) {
  if (!text) return text;

  let reconstructed = text;

  // Remove zero-width characters inserted mid-word
  reconstructed = reconstructed.replace(EXTENDED_INVISIBLE, '');

  // Reconstruct single-character spaced words: "i g n o r e" → "ignore"
  // Matches 4+ single chars separated by single spaces
  reconstructed = reconstructed.replace(
    /\b([a-zA-Z] ){3,}[a-zA-Z]\b/g,
    (match) => match.replace(/ /g, '')
  );

  // Reconstruct dot-separated letters: "i.g.n.o.r.e" → "ignore"
  reconstructed = reconstructed.replace(
    /\b([a-zA-Z]\.){3,}[a-zA-Z]\b/g,
    (match) => match.replace(/\./g, '')
  );

  // Reconstruct hyphen-split words: "ign-ore" → "ignore"
  // Only for short segments (avoids breaking legitimate hyphenated compound words)
  reconstructed = reconstructed.replace(
    /\b([a-zA-Z]{2,6})-([a-zA-Z]{2,6})\b/g,
    (match, a, b) => {
      const joined = a + b;
      if (EVASION_KEYWORDS.some(k => joined.toLowerCase().includes(k))) {
        return joined;
      }
      return match;
    }
  );

  return reconstructed;
}

// -------------------------------------------------------
// Keywords used to decide whether a decoded/reconstructed
// string is worth substituting (avoids over-aggressive decoding)
// -------------------------------------------------------
const EVASION_KEYWORDS = [
  'ignore', 'override', 'forget', 'disregard', 'bypass',
  'jailbreak', 'unrestricted', 'instructions', 'directives',
  'system', 'prompt', 'persona', 'pretend', 'developer',
  'disable', 'filter', 'restriction', 'injection',
  // ROT13 versions of key words (so decodeRot13 can recognize them)
  'vtagber', 'bireevqr', 'sbetrg', 'qvfertneq', 'olmhyhfr',
];

// -------------------------------------------------------
// Multilingual Injection Patterns
// Common injection phrases in languages beyond English
// -------------------------------------------------------
const MULTILINGUAL_PATTERNS = [
  // French
  /ignorez (vos |toutes |les )?(instructions|directives|consignes) (précédentes|antérieures)/gi,
  /oubliez (vos )?(instructions|directives) (précédentes|antérieures)/gi,
  /désactivez (vos )?(filtres?|restrictions?)/gi,
  /nouvelles? instructions?:/gi,
  /à partir de maintenant (vous|tu) (êtes|es|devez|dois)/gi,
  /contournez? (vos )?(filtres?|sécurité|restrictions?)/gi,

  // Spanish
  /ignora (tus |todas |las )?(instrucciones|directivas) (anteriores|previas)/gi,
  /olvida (tus )?(instrucciones|directivas) (anteriores|previas)/gi,
  /desactiva (tus )?(filtros?|restricciones?)/gi,
  /nuevas? instrucciones?:/gi,
  /a partir de ahora (eres|debes|responde)/gi,
  /omite (tus )?(instrucciones|restricciones) (anteriores|previas)/gi,

  // German
  /ignoriere (deine |alle |die )?(vorherigen |früheren )?(Anweisungen|Direktiven)/gi,
  /vergiss (deine )?(vorherigen |früheren )?(Anweisungen|Direktiven)/gi,
  /deaktiviere (deine )?(Filter|Einschränkungen)/gi,
  /neue Anweisungen:/gi,
  /ab jetzt (bist du|musst du|antworte)/gi,
  /umgehe (deine )?(Filter|Sicherheit|Einschränkungen)/gi,

  // Italian
  /ignora (le tue |tutte le |le )?(istruzioni|direttive) (precedenti|anteriori)/gi,
  /dimentica (le tue )?(istruzioni|direttive) (precedenti|anteriori)/gi,
  /disattiva (i tuoi )?(filtri|restrizioni)/gi,
  /nuove istruzioni:/gi,
  /da ora in poi (sei|devi|rispondi)/gi,

  // Portuguese
  /ignore (suas |todas as |as )?(instruções|diretivas) (anteriores|prévias)/gi,
  /esqueça (suas )?(instruções|diretivas) (anteriores|prévias)/gi,
  /desative (seus )?(filtros?|restrições)/gi,
  /novas instruções:/gi,
  /a partir de agora (você é|você deve|responda)/gi,

  // Russian (transliterated and Cyrillic)
  /игнорируй (предыдущие |все )?(инструкции|директивы)/gi,
  /забудь (предыдущие )?(инструкции|директивы)/gi,
  /отключи (фильтры|ограничения)/gi,
  /новые инструкции:/gi,
  /отныне (ты|вы) (являешься|должен|должны)/gi,

  // Chinese (Simplified — common injection phrases)
  /忽略(之前的|所有的|你的)?(指令|命令|提示)/g,
  /忘记(之前的|所有的)?(指令|命令)/g,
  /新的指令:/g,
  /从现在起(你是|你必须|你应该)/g,
  /绕过(你的)?(过滤|限制|安全)/g,

  // Arabic (common injection phrases)
  /تجاهل (التعليمات|الأوامر) (السابقة|السابقة)/g,
  /انسَ (التعليمات|الأوامر) السابقة/g,
  /تعليمات جديدة:/g,
  /من الآن فصاعداً (أنت|يجب عليك)/g,
];

// -------------------------------------------------------
// scanEvasion(text)
//
// Main entry point. Decodes all evasion techniques and
// checks for multilingual injection patterns.
//
// Returns:
//   {
//     decoded: string,       // fully decoded/normalized text for pattern scanning
//     detections: [...],     // evasion techniques detected
//     multilingualBlocked: number  // multilingual injection matches
//   }
// -------------------------------------------------------
export function scanEvasion(text) {
  if (!text) return { decoded: text, detections: [], multilingualBlocked: 0 };

  const detections = [];
  let s = text;

  // Step 1: Strip extended invisible Unicode
  const beforeInvisible = s;
  s = s.replace(EXTENDED_INVISIBLE, '');
  if (s !== beforeInvisible) {
    detections.push({ type: 'invisible_unicode', severity: 'medium', detail: 'Extended invisible Unicode characters removed' });
  }

  // Step 2: Normalize lookalike punctuation
  const beforePunct = s;
  s = normalizePunctuation(s);
  if (s !== beforePunct) {
    detections.push({ type: 'punctuation_normalization', severity: 'low', detail: 'Lookalike punctuation normalized to ASCII' });
  }

  // Step 3: Decode hex escapes
  const beforeHex = s;
  s = decodeHexEscapes(s);
  if (s !== beforeHex) {
    detections.push({ type: 'hex_encoding', severity: 'high', detail: 'Hex-encoded characters decoded' });
  }

  // Step 4: Decode URL encoding
  const beforeUrl = s;
  s = decodeUrlEncoding(s);
  if (s !== beforeUrl) {
    detections.push({ type: 'url_encoding', severity: 'high', detail: 'URL-encoded characters decoded' });
  }

  // Step 5: Decode Unicode escapes
  const beforeUnicode = s;
  s = decodeUnicodeEscapes(s);
  if (s !== beforeUnicode) {
    detections.push({ type: 'unicode_escapes', severity: 'high', detail: 'Unicode escape sequences decoded' });
  }

  // Step 6: Decode ROT13
  const beforeRot13 = s;
  s = decodeRot13(s);
  if (s !== beforeRot13) {
    detections.push({ type: 'rot13_encoding', severity: 'high', detail: 'ROT13-encoded injection keywords decoded' });
  }

  // Step 7: Reconstruct tokenizer attacks
  const beforeTokenizer = s;
  s = reconstructTokenizerAttacks(s);
  if (s !== beforeTokenizer) {
    detections.push({ type: 'tokenizer_attack', severity: 'high', detail: 'Tokenizer evasion technique reconstructed' });
  }

  // Step 8: Multilingual injection pattern scan
  let multilingualBlocked = 0;
  for (const pattern of MULTILINGUAL_PATTERNS) {
    const before = s;
    s = s.replace(pattern, '[BLOCKED]');
    if (s !== before) {
      multilingualBlocked++;
      detections.push({
        type: 'multilingual_injection',
        severity: 'high',
        detail: `Injection pattern detected in non-English language: ${pattern.toString().slice(0, 60)}...`,
      });
    }
    pattern.lastIndex = 0;
  }

  return { decoded: s, detections, multilingualBlocked };
}

export default { scanEvasion, normalizePunctuation, decodeRot13, decodeHexEscapes, decodeUrlEncoding, decodeUnicodeEscapes, reconstructTokenizerAttacks };