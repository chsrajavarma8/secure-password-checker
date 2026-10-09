// ==========================
// CYBERSHIELD PASSWORD TOOL
// ==========================
//
// Security design:
//  - All analysis runs locally. The password is never stored, logged or persisted.
//  - Breach check uses HIBP k-anonymity: only the first 5 hex chars of the SHA-1
//    hash leave the device, with response padding enabled so the reply size
//    reveals nothing.
//  - Password generation uses crypto.getRandomValues() with rejection sampling
//    (no modulo bias), never Math.random().
//  - No innerHTML anywhere: all dynamic text goes through textContent.

(() => {
  "use strict";

  // ===== CONFIG =====

  const CONFIG = Object.freeze({
    ANALYZE_DEBOUNCE_MS: 250,
    BREACH_DEBOUNCE_MS: 800,
    BREACH_TIMEOUT_MS: 8000,
    REVEAL_AUTO_HIDE_MS: 20000,
    CLIPBOARD_CLEAR_MS: 30000,
    ZXCVBN_MAX_LEN: 100,              // zxcvbn is super-linear; cap its input
    HIBP_URL: "https://api.pwnedpasswords.com/range/",
    ATTACK_RATES: Object.freeze({     // guesses per second
      online: 10,                     // rate-limited login form
      offline: 1e10                   // fast unsalted hash on a GPU rig
    })
  });

  const CHARSETS = Object.freeze({
    upper:   "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    lower:   "abcdefghijklmnopqrstuvwxyz",
    digits:  "0123456789",
    symbols: "!@#$%^&*()-_=+[]{}<>?/.,;:~|"
  });

  const AMBIGUOUS = /[0Oo1lI|]/g;

  const LEVELS = Object.freeze([
    { label: "Very Weak",   cls: "weak" },
    { label: "Weak",        cls: "weak" },
    { label: "Fair",        cls: "fair" },
    { label: "Strong",      cls: "strong" },
    { label: "Very Strong", cls: "very-strong" }
  ]);

  // Fallback list, used only if zxcvbn fails to load.
  const COMMON_PASSWORDS = new Set([
    "123456", "123456789", "12345678", "12345", "1234567", "1234567890",
    "password", "password1", "password123", "qwerty", "qwerty123", "abc123",
    "111111", "000000", "123123", "letmein", "admin", "welcome", "monkey",
    "dragon", "iloveyou", "football", "baseball", "sunshine", "princess",
    "master", "shadow", "superman", "trustno1", "passw0rd", "login", "root"
  ]);

  // ===== DOM =====

  const $ = (id) => document.getElementById(id);

  const el = {
    input:         $("password"),
    strengthText:  $("strength-text"),
    strengthBar:   $("strength-bar"),
    strengthFill:  $("strength-fill"),
    scoreValue:    $("score-value"),
    scoreCircle:   $("score-circle"),
    entropy:       $("entropy"),
    crackOnline:   $("crack-online"),
    crackOffline:  $("crack-offline"),
    pattern:       $("pattern-warning"),
    feedback:      $("feedback"),
    breach:        $("breach-result"),
    breachEnabled: $("breach-enabled"),
    status:        $("status-msg"),
    toggleBtn:     $("toggle-password"),
    copyBtn:       $("copy-password"),
    generateBtn:   $("generate-btn"),
    clearBtn:      $("clear-btn"),
    genLength:     $("gen-length"),
    genLengthOut:  $("gen-length-value"),
    genUpper:      $("gen-upper"),
    genLower:      $("gen-lower"),
    genDigits:     $("gen-digits"),
    genSymbols:    $("gen-symbols"),
    genAmbiguous:  $("gen-ambiguous")
  };

  // ===== STATE (never holds the password itself) =====

  let analyzeTimer = 0;
  let breachTimer = 0;
  let revealTimer = 0;
  let clipboardTimer = 0;
  let statusTimer = 0;
  let breachController = null;
  let analysisSeq = 0;

  // ==========================
  // SECURE RANDOMNESS
  // ==========================

  // Uniform integer in [0, max) using rejection sampling to avoid modulo bias.
  function secureRandomInt(max) {
    if (!Number.isInteger(max) || max <= 0 || max > 0x100000000) {
      throw new RangeError("secureRandomInt: invalid range");
    }
    const limit = 0x100000000 - (0x100000000 % max);
    const buf = new Uint32Array(1);
    let x;
    do {
      crypto.getRandomValues(buf);
      x = buf[0];
    } while (x >= limit);
    return x % max;
  }

  function secureShuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = secureRandomInt(i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  }

  // ==========================
  // PASSWORD GENERATOR
  // ==========================

  function getGeneratorOptions() {
    const length = clamp(parseInt(el.genLength.value, 10) || 20, 12, 64);
    const pools = [];

    if (el.genUpper.checked)   pools.push(CHARSETS.upper);
    if (el.genLower.checked)   pools.push(CHARSETS.lower);
    if (el.genDigits.checked)  pools.push(CHARSETS.digits);
    if (el.genSymbols.checked) pools.push(CHARSETS.symbols);

    const cleaned = el.genAmbiguous.checked
      ? pools.map((p) => p.replace(AMBIGUOUS, "")).filter(Boolean)
      : pools;

    return { length, pools: cleaned };
  }

  function generatePassword() {
    const { length, pools } = getGeneratorOptions();

    if (pools.length === 0) {
      showStatus("Select at least one character type", "error");
      return;
    }

    const all = pools.join("");

    // Guarantee at least one character from every selected pool,
    // then fill the rest uniformly and shuffle so positions are random.
    const chars = pools.map((p) => p[secureRandomInt(p.length)]);
    while (chars.length < length) {
      chars.push(all[secureRandomInt(all.length)]);
    }
    secureShuffle(chars);

    el.input.value = chars.join("");

    scheduleAnalysis(0);
    showStatus(`Generated ${length}-character password`, "ok");
  }

  // ==========================
  // ANALYSIS
  // ==========================

  function charsetSize(pwd) {
    let size = 0;
    if (/[a-z]/.test(pwd)) size += 26;
    if (/[A-Z]/.test(pwd)) size += 26;
    if (/[0-9]/.test(pwd)) size += 10;
    if (/[\x20-\x2F\x3A-\x40\x5B-\x60\x7B-\x7E]/.test(pwd)) size += 33;
    if (/[^\x00-\x7F]/.test(pwd)) size += 100; // conservative estimate for Unicode
    return size;
  }

  // Theoretical brute-force entropy (upper bound). Uses length * log2(N)
  // instead of log2(N^length), which overflows to Infinity for long inputs.
  function bruteForceEntropy(pwd) {
    const n = charsetSize(pwd);
    return n > 0 ? [...pwd].length * Math.log2(n) : 0;
  }

  function detectPatternsFallback(pwd) {
    const lower = pwd.toLowerCase();
    const found = [];

    if (/(.)\1{2,}/.test(lower)) found.push("repeated characters");
    if (/(qwert|werty|asdf|sdfg|zxcv|xcvb|1qaz|2wsx|qazwsx)/.test(lower)) found.push("keyboard pattern");
    if (hasSequence(lower, 4)) found.push("sequence");
    if (/(19|20)\d{2}/.test(lower)) found.push("year");
    if (/(password|passw0rd|admin|login|welcome|letmein)/.test(deLeet(lower))) found.push("common word");

    return found;
  }

  function hasSequence(str, minLen) {
    let up = 1;
    let down = 1;
    for (let i = 1; i < str.length; i++) {
      const d = str.charCodeAt(i) - str.charCodeAt(i - 1);
      up = d === 1 ? up + 1 : 1;
      down = d === -1 ? down + 1 : 1;
      if (up >= minLen || down >= minLen) return true;
    }
    return false;
  }

  function deLeet(s) {
    return s
      .replace(/[@4]/g, "a").replace(/3/g, "e").replace(/[1!|]/g, "i")
      .replace(/0/g, "o").replace(/[$5]/g, "s").replace(/7/g, "t");
  }

  // Returns a plain result object. The password is not retained.
  function analyze(pwd) {
    const maxBits = bruteForceEntropy(pwd);
    const length = [...pwd].length;
    let log10Guesses;
    let patterns = [];
    let warning = "";
    let suggestions = [];

    if (typeof window.zxcvbn === "function") {
      const r = window.zxcvbn(pwd.slice(0, CONFIG.ZXCVBN_MAX_LEN));
      // Conservative: characters beyond the cap get no extra credit
      // (they are often repeats). 100 chars is already far past any real attack.
      log10Guesses = r.guesses_log10;

      patterns = [...new Set(
        r.sequence
          .filter((m) => m.pattern !== "bruteforce")
          .map(describeMatch)
      )];
      warning = r.feedback.warning || "";
      suggestions = r.feedback.suggestions || [];
    } else {
      const fallbackPatterns = detectPatternsFallback(pwd);
      const isCommon = COMMON_PASSWORDS.has(pwd.toLowerCase()) ||
                       COMMON_PASSWORDS.has(deLeet(pwd.toLowerCase()));
      let bits = maxBits - fallbackPatterns.length * 10;
      if (isCommon) bits = Math.min(bits, 10);
      log10Guesses = Math.max(0, bits) * Math.LOG10E * Math.LN2;
      patterns = fallbackPatterns;
      if (isCommon) warning = "This is a very common password";
    }

    // Our own heuristics, applied in both modes.
    if (length < 8) suggestions.unshift("Use at least 14 characters");
    else if (length < 14) suggestions.unshift("Increase length to 14+ characters");

    const effectiveBits = log10Guesses / Math.log10(2);

    return {
      length,
      maxBits,
      effectiveBits,
      log10Guesses,
      patterns,
      warning,
      suggestions: [...new Set(suggestions)]
    };
  }

  function describeMatch(m) {
    switch (m.pattern) {
      case "dictionary":
        if (m.l33t) return "dictionary word with l33t substitutions";
        if (m.reversed) return "reversed dictionary word";
        return m.dictionary_name === "passwords"
          ? "common password"
          : m.dictionary_name === "user_inputs" ? "personal info" : "dictionary word";
      case "spatial":    return "keyboard pattern";
      case "repeat":     return "repeated characters";
      case "sequence":   return "sequence (abc / 123)";
      case "regex":      return "recent year";
      case "date":       return "date";
      default:           return m.pattern;
    }
  }

  // Map guesses to a 0–4 level and a 0–100 score.
  function rate(result, breachCount) {
    const g = result.log10Guesses;
    let level =
      g >= 14 ? 4 :
      g >= 10 ? 3 :
      g >= 8  ? 2 :
      g >= 6  ? 1 : 0;

    if (result.length < 8) level = Math.min(level, 1);

    let score = clamp(Math.round((g / 18) * 100), 0, 100);

    if (breachCount > 0) {
      level = 0;
      score = Math.min(score, 5);
    }

    return { level, score };
  }

  // ==========================
  // CRACK TIME
  // ==========================

  function crackTime(log10Guesses, guessesPerSecond) {
    // Average case: half the keyspace. Work in log space to avoid overflow.
    const log10Seconds = log10Guesses - Math.log10(2) - Math.log10(guessesPerSecond);
    return formatDuration(log10Seconds);
  }

  function formatDuration(log10Seconds) {
    if (log10Seconds < 0) return "instantly";

    const s = Math.pow(10, log10Seconds);
    const units = [
      [60, "second"],
      [60, "minute"],
      [24, "hour"],
      [365.25, "day"],
      [100, "year"]
    ];

    let value = s;
    for (const [size, name] of units) {
      if (value < size) return plural(Math.max(1, Math.round(value)), name);
      value /= size;
    }

    // value is now centuries
    if (value < 1000) return plural(Math.round(value), "century", "centuries");
    const log10Centuries = log10Seconds - Math.log10(3155760000);
    return `~10^${Math.floor(log10Centuries)} centuries`;
  }

  function plural(n, singular, pluralForm = singular + "s") {
    return `${n.toLocaleString()} ${n === 1 ? singular : pluralForm}`;
  }

  // ==========================
  // BREACH CHECK (HIBP k-anonymity)
  // ==========================

  async function sha1Hex(str) {
    const buf = new TextEncoder().encode(str);
    const digest = await crypto.subtle.digest("SHA-1", buf);
    const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
    buf.fill(0);
    return hex.toUpperCase();
  }

  async function checkBreach(pwd, seq) {
    if (breachController) breachController.abort();
    const controller = new AbortController();
    breachController = controller;
    const timeout = setTimeout(() => controller.abort(), CONFIG.BREACH_TIMEOUT_MS);

    try {
      const hash = await sha1Hex(pwd);
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);

      const res = await fetch(CONFIG.HIBP_URL + prefix, {
        method: "GET",
        headers: { "Add-Padding": "true" },
        mode: "cors",
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        signal: controller.signal
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const text = await res.text();
      let count = 0;

      for (const line of text.split(/\r?\n/)) {
        const sep = line.indexOf(":");
        if (sep !== 35) continue; // suffix is always 35 hex chars
        if (line.slice(0, sep) === suffix) {
          count = parseInt(line.slice(sep + 1), 10) || 0;
          break;
        }
      }

      return seq === analysisSeq ? { ok: true, count } : null;
    } catch (err) {
      if (err.name === "AbortError" && seq !== analysisSeq) return null; // superseded
      return seq === analysisSeq ? { ok: false } : null;
    } finally {
      clearTimeout(timeout);
      if (breachController === controller) breachController = null;
    }
  }

  // ==========================
  // ORCHESTRATION
  // ==========================

  function scheduleAnalysis(delay = CONFIG.ANALYZE_DEBOUNCE_MS) {
    clearTimeout(analyzeTimer);
    analyzeTimer = setTimeout(runAnalysis, delay);
  }

  function runAnalysis() {
    const seq = ++analysisSeq;
    const pwd = el.input.value; // never trimmed: spaces are valid password characters

    clearTimeout(breachTimer);
    if (breachController) breachController.abort();

    if (!pwd) {
      resetUI();
      return;
    }

    const result = analyze(pwd);
    renderResult(result, 0);

    if (!el.breachEnabled.checked) {
      setBreachText("Breach check disabled", "muted");
      return;
    }

    setBreachText("Waiting to check…", "muted");

    breachTimer = setTimeout(async () => {
      if (seq !== analysisSeq) return;
      const current = el.input.value;
      if (current !== pwd) return; // input changed; a newer run will handle it

      setBreachText("Checking known breaches…", "muted");

      const breach = await checkBreach(current, seq);
      if (!breach) return; // stale

      if (!breach.ok) {
        setBreachText("Breach service unavailable — result unknown", "warn");
        return;
      }

      if (breach.count > 0) {
        setBreachText(
          `Found ${breach.count.toLocaleString()} times in data breaches — do not use this password`,
          "bad"
        );
      } else {
        setBreachText("Not found in known breaches", "good");
      }
      renderResult(result, breach.count);
    }, CONFIG.BREACH_DEBOUNCE_MS);
  }

  // ==========================
  // UI
  // ==========================

  function renderResult(result, breachCount) {
    const { level, score } = rate(result, breachCount);
    const lvl = LEVELS[level];

    el.strengthText.textContent = lvl.label;
    el.strengthText.className = `strength-label ${lvl.cls}`;
    el.strengthFill.style.width = `${Math.max(score, 4)}%`;
    el.strengthFill.className = lvl.cls;
    el.strengthBar.setAttribute("aria-valuenow", String(score));
    el.strengthBar.setAttribute("aria-valuetext", `${lvl.label}, ${score} out of 100`);
    el.scoreValue.textContent = String(score);
    el.scoreCircle.className = `score-circle ${lvl.cls}`;

    el.entropy.textContent =
      `${result.effectiveBits.toFixed(1)} bits effective ` +
      `(${result.maxBits.toFixed(1)} bits brute-force max)`;

    el.crackOnline.textContent = crackTime(result.log10Guesses, CONFIG.ATTACK_RATES.online);
    el.crackOffline.textContent = crackTime(result.log10Guesses, CONFIG.ATTACK_RATES.offline);

    if (result.patterns.length) {
      el.pattern.textContent = `Predictable patterns: ${result.patterns.join(", ")}`;
      el.pattern.className = "warn";
    } else {
      el.pattern.textContent = "No predictable patterns detected";
      el.pattern.className = "good";
    }

    const items = [];
    if (breachCount > 0) items.push("This password is publicly leaked — attackers try it first");
    if (result.warning) items.push(result.warning);
    items.push(...result.suggestions);
    if (items.length === 0) items.push("Excellent — store it in a password manager");
    setFeedback(items);
  }

  function resetUI() {
    el.strengthText.textContent = "—";
    el.strengthText.className = "strength-label";
    el.strengthFill.style.width = "0%";
    el.strengthFill.className = "";
    el.strengthBar.setAttribute("aria-valuenow", "0");
    el.strengthBar.removeAttribute("aria-valuetext");
    el.scoreValue.textContent = "0";
    el.scoreCircle.className = "score-circle";
    el.entropy.textContent = "—";
    el.crackOnline.textContent = "—";
    el.crackOffline.textContent = "—";
    el.pattern.textContent = "No patterns detected";
    el.pattern.className = "";
    setFeedback(["Use at least 14 characters — a long passphrase is best"]);
    setBreachText("Breach scan not started", "");
  }

  function setFeedback(items) {
    const frag = document.createDocumentFragment();
    for (const text of items) {
      const li = document.createElement("li");
      li.textContent = text;
      frag.appendChild(li);
    }
    el.feedback.replaceChildren(frag);
  }

  function setBreachText(text, cls) {
    el.breach.textContent = text;
    el.breach.className = cls;
  }

  function showStatus(text, kind = "ok") {
    clearTimeout(statusTimer);
    el.status.textContent = text;
    el.status.className = `status-msg ${kind}`;
    statusTimer = setTimeout(() => {
      el.status.textContent = "";
      el.status.className = "status-msg";
    }, 4000);
  }

  function setIcon(button, id) {
    const use = button.querySelector("use");
    if (use) use.setAttribute("href", `#${id}`);
  }

  // ==========================
  // VISIBILITY TOGGLE
  // ==========================

  function setRevealed(revealed) {
    el.input.type = revealed ? "text" : "password";
    el.toggleBtn.setAttribute("aria-pressed", String(revealed));
    const label = revealed ? "Hide password" : "Show password";
    el.toggleBtn.setAttribute("aria-label", label);
    el.toggleBtn.title = label;
    setIcon(el.toggleBtn, revealed ? "i-eye-off" : "i-eye");

    clearTimeout(revealTimer);
    if (revealed) {
      // Shoulder-surfing protection: auto-hide after a while.
      revealTimer = setTimeout(() => setRevealed(false), CONFIG.REVEAL_AUTO_HIDE_MS);
    }
  }

  // ==========================
  // CLIPBOARD
  // ==========================

  async function copyPassword() {
    const pwd = el.input.value;
    if (!pwd) {
      showStatus("No password to copy", "error");
      return;
    }

    if (!navigator.clipboard || !window.isSecureContext) {
      showStatus("Clipboard requires HTTPS or localhost", "error");
      return;
    }

    try {
      await navigator.clipboard.writeText(pwd);
      setIcon(el.copyBtn, "i-check");
      setTimeout(() => setIcon(el.copyBtn, "i-copy"), 1500);
      showStatus(`Copied — clipboard clears in ${CONFIG.CLIPBOARD_CLEAR_MS / 1000}s`, "ok");

      clearTimeout(clipboardTimer);
      clipboardTimer = setTimeout(clearClipboard, CONFIG.CLIPBOARD_CLEAR_MS);
    } catch {
      showStatus("Copy failed — clipboard permission denied", "error");
    }
  }

  async function clearClipboard() {
    try {
      await navigator.clipboard.writeText("");
    } catch {
      // Page not focused; browsers block clipboard writes in background tabs.
      // Retry once the user returns.
      window.addEventListener("focus", clearClipboard, { once: true });
    }
  }

  // ==========================
  // CLEAR / LIFECYCLE
  // ==========================

  function clearAll() {
    el.input.value = "";
    setRevealed(false);
    scheduleAnalysis(0);
    el.input.focus();
  }

  // Don't let the back/forward cache restore a typed password.
  function wipeOnLeave() {
    el.input.value = "";
    setRevealed(false);
    resetUI();
  }

  // ==========================
  // UTIL
  // ==========================

  function clamp(n, min, max) {
    return Math.min(max, Math.max(min, n));
  }

  // ==========================
  // EVENTS
  // ==========================

  el.input.addEventListener("input", () => scheduleAnalysis());

  // Prevent dragging the password text out of the field into other apps.
  el.input.addEventListener("dragstart", (e) => e.preventDefault());

  el.toggleBtn.addEventListener("click", () => setRevealed(el.input.type === "password"));
  el.copyBtn.addEventListener("click", copyPassword);
  el.generateBtn.addEventListener("click", generatePassword);
  el.clearBtn.addEventListener("click", clearAll);
  el.breachEnabled.addEventListener("change", () => scheduleAnalysis(0));

  el.genLength.addEventListener("input", () => {
    el.genLengthOut.textContent = el.genLength.value;
  });

  window.addEventListener("pagehide", wipeOnLeave);
  window.addEventListener("pageshow", (e) => { if (e.persisted) wipeOnLeave(); });

  // ===== INIT =====

  if (!window.crypto || !crypto.getRandomValues) {
    el.generateBtn.disabled = true;
    showStatus("Secure random generator unavailable in this browser", "error");
  }

  if (!window.crypto || !crypto.subtle) {
    el.breachEnabled.checked = false;
    el.breachEnabled.disabled = true;
  }

  if (typeof window.zxcvbn !== "function") {
    console.warn("[CyberShield] zxcvbn not loaded — using built-in fallback estimator.");
  }

  resetUI();
})();
