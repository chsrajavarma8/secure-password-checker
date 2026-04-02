// ===== DOM =====
const input = document.getElementById("password");
const strengthText = document.getElementById("strength-text");
const strengthFill = document.getElementById("strength-fill");
const feedback = document.getElementById("feedback");
const breachText = document.getElementById("breach-result");
const entropyText = document.getElementById("entropy");

let timeout;
let keystrokes = [];

// ===== COMMON PASSWORD LIST =====
const commonPasswords = ["123456","password","qwerty","abc123","letmein","admin"];

// ===== PASSWORD HISTORY (reuse detection) =====
let passwordHistory = [];

// ===== EVENT =====
input.addEventListener("keydown", () => {
  keystrokes.push(Date.now());
});

input.addEventListener("input", () => {
  clearTimeout(timeout);
  timeout = setTimeout(analyzePassword, 400);
});

// ===== MAIN ANALYSIS =====
async function analyzePassword() {
  const pwd = input.value.trim();
  if (!pwd) return;

  // ===== ENTROPY =====
  const entropy = calculateEntropy(pwd);

  // ===== PATTERN DETECTION =====
  const pattern = detectPatterns(pwd);

  // ===== DICTIONARY CHECK =====
  const isCommon = commonPasswords.includes(pwd.toLowerCase());

  // ===== GUESS ESTIMATION =====
  const guesses = Math.pow(2, entropy);

  // ===== CRACK TIME =====
  const crack = estimateCrackTime(guesses);

  // ===== SCORE (REALISTIC) =====
  let score = 0;

  if (entropy > 60) score = 4;
  else if (entropy > 50) score = 3;
  else if (entropy > 40) score = 2;
  else if (entropy > 30) score = 1;

  if (pattern) score--;
  if (isCommon) score = 0;

  score = Math.max(0, Math.min(4, score));

  updateUI(score, crack);

  entropyText.textContent = `Entropy: ${entropy.toFixed(2)} bits`;

  // ===== FEEDBACK =====
  feedback.textContent = generateFeedback(pwd, pattern, isCommon);

  // ===== BREACH CHECK =====
  await checkBreach(pwd);

  // ===== REUSE DETECTION =====
  if (passwordHistory.includes(pwd)) {
    feedback.textContent += " | ⚠️ Password reused";
  } else {
    passwordHistory.push(pwd);
  }

  // ===== TYPING ANALYSIS =====
  analyzeTyping();
}

// ===== ENTROPY =====
function calculateEntropy(pwd) {
  let charset = 0;

  if (/[a-z]/.test(pwd)) charset += 26;
  if (/[A-Z]/.test(pwd)) charset += 26;
  if (/[0-9]/.test(pwd)) charset += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) charset += 32;

  return Math.log2(Math.pow(charset, pwd.length));
}

// ===== PATTERN DETECTION =====
function detectPatterns(pwd) {
  const patterns = [
    /1234/, /abcd/, /qwerty/,
    /(.)\1{2,}/,
    /password/, /admin/
  ];

  for (let p of patterns) {
    if (p.test(pwd.toLowerCase())) {
      return true;
    }
  }
  return false;
}

// ===== CRACK TIME =====
function estimateCrackTime(guesses) {
  const offlineFast = guesses / 1e10;
  const onlineSlow = guesses / 100;

  return {
    offline: formatTime(offlineFast),
    online: formatTime(onlineSlow)
  };
}

function formatTime(seconds) {
  if (seconds < 1) return "seconds";
  if (seconds < 60) return `${Math.round(seconds)} sec`;
  if (seconds < 3600) return `${Math.round(seconds/60)} min`;
  if (seconds < 86400) return `${Math.round(seconds/3600)} hrs`;
  if (seconds < 31536000) return `${Math.round(seconds/86400)} days`;
  return `${Math.round(seconds/31536000)} years`;
}

// ===== UI =====
function updateUI(score, crack) {
  const labels = ["Very Weak","Weak","Fair","Good","Strong"];
  const percent = [10,30,50,75,95];
  const colors = ["#ef4444","#f97316","#eab308","#22c55e","#16a34a"];

  strengthFill.style.width = percent[score] + "%";
  strengthFill.style.background = colors[score];

  strengthText.textContent =
    `${labels[score]} | Offline: ${crack.offline} | Online: ${crack.online}`;
}

// ===== FEEDBACK =====
function generateFeedback(pwd, pattern, isCommon) {
  let msg = [];

  if (pwd.length < 12)
    msg.push("Increase length to 12+");

  if (!/[A-Z]/.test(pwd))
    msg.push("Add uppercase letters");

  if (!/[0-9]/.test(pwd))
    msg.push("Include numbers");

  if (!/[!@#$%^&*]/.test(pwd))
    msg.push("Add symbols");

  if (pattern)
    msg.push("Contains predictable pattern");

  if (isCommon)
    msg.push("Common password (dictionary attack risk)");

  return msg.join(" | ");
}

// ===== BREACH CHECK =====
async function checkBreach(pwd) {
  try {
    const hash = await sha1(pwd);
    const prefix = hash.substring(0, 5);
    const suffix = hash.substring(5).toUpperCase();

    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    const text = await res.text();

    const lines = text.split("\n");
    let count = 0;

    for (let line of lines) {
      const [h, num] = line.split(":");
      if (h === suffix) {
        count = parseInt(num);
        break;
      }
    }

    breachText.textContent =
      count > 0
        ? `⚠️ Found ${count} times in breaches`
        : "✅ Not found in breaches";

  } catch {
    breachText.textContent = "Error checking breaches";
  }
}

// ===== SHA-1 =====
async function sha1(str) {
  const buf = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest("SHA-1", buf);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// ===== PASSWORD GENERATOR (SMART) =====
function generatePassword() {
  const words = ["Tiger","Rocket","Shadow","Quantum","Nova","Storm"];
  const symbols = "!@#$%^&*";

  let pwd =
    words[Math.floor(Math.random()*words.length)] +
    symbols[Math.floor(Math.random()*symbols.length)] +
    Math.floor(Math.random()*100) +
    words[Math.floor(Math.random()*words.length)];

  input.value = pwd;
  analyzePassword();
}

// ===== TYPING ANALYSIS =====
function analyzeTyping() {
  if (keystrokes.length < 2) return;

  let intervals = [];
  for (let i = 1; i < keystrokes.length; i++) {
    intervals.push(keystrokes[i] - keystrokes[i - 1]);
  }

  const avg = intervals.reduce((a,b)=>a+b,0)/intervals.length;

  if (avg < 50) {
    feedback.textContent += " | ⚠️ Typing too fast (possible bot)";
  }
}
