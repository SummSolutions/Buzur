// Buzur — Phase 3: Pre-fetch URL Scanner
// Layered protection: heuristics first, VirusTotal second (optional)
// https://github.com/ASumm07/buzur

const suspiciousTLDs = [
  ".xyz", ".top", ".click", ".loan", ".gq", ".ml", ".cf", ".tk",
  ".pw", ".cc", ".su", ".rest", ".zip", ".mov"
];

const suspiciousPatterns = [
  /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
  /[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\./,
  /(free|win|prize|claim|urgent|verify|suspend|alert|secure|login)\./i,
  /\.(exe|bat|ps1|sh|msi|vbs|jar)(\?|$)/i,
  /redirect|tracking|click\.php|go\.php/i,
  /[^\x00-\x7F]/,
];

const homoglyphDomains = [
  /paypa1\./, /g00gle\./, /arnazon\./, /micros0ft\./,
  /faceb00k\./, /tvvitter\./, /linkedln\./,
];

export function scanUrl(url) {
  const result = { url, verdict: "clean", reasons: [], heuristics: true, virusTotal: null };
  let hostname;
  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch {
    result.verdict = "blocked";
    result.reasons.push("Invalid URL format");
    return result;
  }
  for (const tld of suspiciousTLDs) {
    if (hostname.endsWith(tld)) {
      result.verdict = "suspicious";
      result.reasons.push("Suspicious TLD: " + tld);
    }
  }
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(hostname)) {
      result.verdict = "suspicious";
      result.reasons.push("Suspicious pattern matched");
    }
  }
  for (const pattern of homoglyphDomains) {
    if (pattern.test(hostname)) {
      result.verdict = "blocked";
      result.reasons.push("Homoglyph domain spoof detected: " + hostname);
    }
  }
  if (hostname.length > 50) {
    result.verdict = "suspicious";
    result.reasons.push("Unusually long hostname (" + hostname.length + " chars)");
  }
  return result;
}

export async function scanUrlVirusTotal(url, apiKey) {
  if (!apiKey) return { skipped: true, reason: "No VirusTotal API key configured" };
  try {
    const submitRes = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: { "x-apikey": apiKey, "Content-Type": "application/x-www-form-urlencoded" },
      body: "url=" + encodeURIComponent(url),
    });
    if (!submitRes.ok) return { skipped: true, reason: "VirusTotal submit failed: " + submitRes.status };
    const submitData = await submitRes.json();
    const analysisId = submitData?.data?.id;
    if (!analysisId) return { skipped: true, reason: "No analysis ID returned" };
    for (let i = 0; i < 3; i++) {
      await new Promise(r => setTimeout(r, 2000));
      const analysisRes = await fetch("https://www.virustotal.com/api/v3/analyses/" + analysisId, {
        headers: { "x-apikey": apiKey }
      });
      if (!analysisRes.ok) continue;
      const analysisData = await analysisRes.json();
      if (analysisData?.data?.attributes?.status !== "completed") continue;
      const stats = analysisData?.data?.attributes?.stats;
      const malicious = stats?.malicious || 0;
      const suspicious = stats?.suspicious || 0;
      return {
        skipped: false, malicious, suspicious,
        verdict: malicious > 0 ? "blocked" : suspicious > 2 ? "suspicious" : "clean",
        engines: stats,
      };
    }
    return { skipped: true, reason: "VirusTotal analysis timed out" };
  } catch (err) {
    return { skipped: true, reason: "VirusTotal error: " + err.message };
  }
}

export async function checkUrl(url, apiKey = null) {
  const heuristicResult = scanUrl(url);
  if (heuristicResult.verdict === "blocked") return heuristicResult;
  const vtResult = await scanUrlVirusTotal(url, apiKey);
  heuristicResult.virusTotal = vtResult;
  if (!vtResult.skipped) {
    if (vtResult.verdict === "blocked") heuristicResult.verdict = "blocked";
    if (vtResult.verdict === "suspicious" && heuristicResult.verdict === "clean") heuristicResult.verdict = "suspicious";
    if (vtResult.malicious > 0) heuristicResult.reasons.push("VirusTotal: " + vtResult.malicious + " engines flagged as malicious");
  }
  return heuristicResult;
}

export default { scanUrl, scanUrlVirusTotal, checkUrl };
