import { useState, useEffect, useRef } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Eye,
  EyeOff,
  RefreshCw,
  Undo2,
  RotateCcw,
  Copy,
  Check,
  Lock,
  Sparkles,
  AlertTriangle,
  CheckCircle2,
  Info,
  X,
  Zap,
  Download,
  UserCheck,
} from "lucide-react";

// ---- Data ----
const COMMON_PASSWORDS = new Set([
  "password", "123456", "123456789", "qwerty", "letmein", "admin",
  "welcome", "monkey", "football", "iloveyou", "abc123", "111111",
  "password1", "1234567", "sunshine", "master", "dragon",
]);

const LEET_MAP = {
  a: "4", e: "3", i: "1", o: "0", s: "5", t: "7",
};

// ---- Shared common-password pattern detection ----
// Real attackers don't just brute-force randomly — they run dictionary +
// rule-based attacks first (common word, common word + digits, leetspeak
// swaps, etc). This catches those patterns, not just exact matches, so
// something like "password123" is correctly flagged even though the exact
// string isn't in the raw list.
function isCommonPasswordPattern(pw) {
  const lower = pw.toLowerCase();
  if (COMMON_PASSWORDS.has(lower)) return true;

  const undoLeet = lower
    .replace(/4/g, "a").replace(/3/g, "e").replace(/1/g, "i")
    .replace(/0/g, "o").replace(/5/g, "s").replace(/7/g, "t");
  if (COMMON_PASSWORDS.has(undoLeet)) return true;

  // Strip digits/symbols to catch "password123", "password!", "123password", etc
  const stripped = lower.replace(/[^a-z]/g, "");
  const strippedLeet = undoLeet.replace(/[^a-z]/g, "");
  if (COMMON_PASSWORDS.has(stripped) || COMMON_PASSWORDS.has(strippedLeet)) return true;

  return false;
}

// ---- Scoring logic ----
// Score is now derived from entropy (bits of randomness), the same math
// crack-time estimates use — so a password that takes billions of years
// to crack will actually score close to 10, not get capped by flat point buckets.
function scorePassword(pw) {
  const feedback = [];

  if (!pw) {
    return {
      score: 0,
      feedback: ["Enter a password to see its score"],
      breakdown: null,
    };
  }

  const hasLower = /[a-z]/.test(pw);
  const hasUpper = /[A-Z]/.test(pw);
  const hasDigit = /[0-9]/.test(pw);
  const hasSymbol = /[^a-zA-Z0-9]/.test(pw);

  if (!hasUpper) feedback.push("Add an uppercase letter");
  if (!hasDigit) feedback.push("Add a number");
  if (!hasSymbol) feedback.push("Add a symbol like ! @ # $");
  if (pw.length < 8) feedback.push("Too short — aim for 12+ characters");

  // --- Character pool size, based on what character types are actually used ---
  let poolSize = 0;
  if (hasLower) poolSize += 26;
  if (hasUpper) poolSize += 26;
  if (hasDigit) poolSize += 10;
  if (hasSymbol) poolSize += 32;
  if (poolSize === 0) poolSize = 1;

  // --- Entropy in bits: log2(poolSize ^ length) ---
  const rawEntropyBits = pw.length * Math.log2(poolSize);

  // Repeated characters reduce true randomness even though the raw pool looks large
  const uniqueRatio = new Set(pw.toLowerCase()).size / pw.length;
  const repetitionMultiplier = 0.5 + 0.5 * uniqueRatio; // 0.5x (all same char) to 1x (all unique)
  const adjustedEntropyBits = rawEntropyBits * repetitionMultiplier;

  // --- Map entropy bits to a 1-10 scale ---
  let score = Math.round((adjustedEntropyBits / 100) * 10);
  const uncappedScore = score;

  // --- Hard penalties for predictable patterns brute-force math doesn't capture ---
  const lower = pw.toLowerCase();

  let capReason = null;

  if (COMMON_PASSWORDS.has(lower)) {
    score = 1;
    capReason = "Exact match with a known common password";
    feedback.push("This is one of the most commonly used passwords");
  } else if (isCommonPasswordPattern(pw)) {
    score = Math.min(score, 2);
    capReason = "Based on a common password (with digits, symbols, or leetspeak swapped in)";
    feedback.push("This is a common password with minor changes — attackers check for this pattern");
  }

  if (/(.)\1{2,}/.test(pw)) {
    if (score > 3) capReason = "Contains repeated characters (e.g. aaa)";
    score = Math.min(score, 3);
    feedback.push("Avoid repeating the same character multiple times");
  }

  const sequences = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop"];
  for (const seq of sequences) {
    for (let i = 0; i <= seq.length - 4; i++) {
      if (lower.includes(seq.slice(i, i + 4))) {
        if (score > 3) capReason = "Contains a sequential pattern (e.g. 1234, abcd)";
        score = Math.min(score, 3);
        feedback.push("Avoid sequential patterns like 1234 or abcd");
        break;
      }
    }
  }

  score = Math.max(1, Math.min(10, score));

  if (feedback.length === 0) {
    feedback.push("Strong password! No issues found.");
  }

  const breakdown = {
    poolSize,
    rawEntropyBits,
    uniqueRatio,
    repetitionMultiplier,
    adjustedEntropyBits,
    uncappedScore: Math.max(1, Math.min(10, uncappedScore)),
    capReason,
    wasCapped: capReason !== null,
  };

  return { score, feedback, breakdown };
}

// ---- Suggestion logic ----
// Style: "password" -> "P455w0rd!42" — leetify the whole password, then
// GUARANTEE the result has an uppercase letter, lowercase letter, digit,
// symbol, and is at least 8 characters — not just probably, always.
function suggestPasswords(pw, count = 3) {
  if (!pw) return [];
  const suggestions = new Set();
  let attempts = 0;

  while (suggestions.size < count && attempts < 30) {
    attempts++;

    let base = pw.charAt(0).toUpperCase() + pw.slice(1);

    // Leetify most letters, flip case on the rest for extra variation
    let leeted = "";
    for (const ch of base) {
      const lower = ch.toLowerCase();
      if (LEET_MAP[lower] && Math.random() < 0.85) {
        leeted += LEET_MAP[lower];
      } else if (/[a-zA-Z]/.test(ch) && Math.random() < 0.5) {
        leeted += ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase();
      } else {
        leeted += ch;
      }
    }

    // Always append a symbol + 2 digits — guarantees digit & symbol requirements
    const symbol = "!@#$%&*"[Math.floor(Math.random() * 7)];
    const digits = Math.floor(10 + Math.random() * 90);
    let suggestion = `${leeted}${symbol}${digits}`;

    // --- Now GUARANTEE every requirement, rather than hoping randomness covers it ---
    // If leetifying consumed every lowercase letter (all got swapped to symbols/uppercase),
    // add one back. Same for uppercase.
    if (!/[a-z]/.test(suggestion)) {
      suggestion += String.fromCharCode(97 + Math.floor(Math.random() * 26)); // a-z
    }
    if (!/[A-Z]/.test(suggestion)) {
      suggestion += String.fromCharCode(65 + Math.floor(Math.random() * 26)); // A-Z
    }
    // Digit and symbol are already guaranteed by the suffix above, but double-check
    // in case the original password's suffix chars got altered somehow
    if (!/[0-9]/.test(suggestion)) {
      suggestion += Math.floor(Math.random() * 10);
    }
    if (!/[^a-zA-Z0-9]/.test(suggestion)) {
      suggestion += "!@#$%&*"[Math.floor(Math.random() * 7)];
    }

    // Guarantee minimum length of 8 by padding with random alphanumeric characters
    const padChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    while (suggestion.length < 8) {
      suggestion += padChars[Math.floor(Math.random() * padChars.length)];
    }

    suggestions.add(suggestion);
  }

  return Array.from(suggestions);
}

// ---- Passphrase generator (alternative to leetspeak suggestions) ----
// Uses random, unrelated words instead of transforming the original password.
// Generally more memorable AND more resistant to dictionary/pattern attacks
// than leetspeak substitution, since it doesn't start from a guessable base.
const PASSPHRASE_WORDS = [
  "River", "Comet", "Tiger", "Willow", "Ember", "Otter", "Nova", "Falcon",
  "Marble", "Cedar", "Quartz", "Storm", "Maple", "Coral", "Lantern", "Prairie",
  "Granite", "Meadow", "Thistle", "Harbor", "Frost", "Ridge", "Copper", "Violet",
];

function suggestPassphrases(count = 3) {
  const phrases = new Set();
  let attempts = 0;

  while (phrases.size < count && attempts < 20) {
    attempts++;
    const words = [];
    for (let i = 0; i < 3; i++) {
      words.push(PASSPHRASE_WORDS[Math.floor(Math.random() * PASSPHRASE_WORDS.length)]);
    }
    const symbol = "!@#$%&*"[Math.floor(Math.random() * 7)];
    const digits = Math.floor(10 + Math.random() * 90);
    const phrase = `${words.join("-")}${symbol}${digits}`;
    phrases.add(phrase);
  }

  return Array.from(phrases);
}

// ---- Personal info collision detection ----
// Checks whether the password contains any personal info the user optionally
// provides (name, birth year, pet name, etc). This catches one of the most
// common real-world weaknesses that pure entropy math can't detect on its own.
function checkPersonalInfoCollisions(pw, personalInfo) {
  if (!pw) return [];
  const lower = pw.toLowerCase();
  const matches = [];

  for (const [label, value] of Object.entries(personalInfo)) {
    const trimmed = value.trim();
    if (trimmed.length >= 2 && lower.includes(trimmed.toLowerCase())) {
      matches.push(label);
    }
  }

  return matches;
}

// ---- Number formatting for the attack simulator ----
// Turns huge combination counts into readable text (e.g. "4.2 trillion")
// instead of a raw string of digits that's impossible to read at a glance.
function formatGuessCount(n) {
  if (n < 1000) return Math.round(n).toLocaleString();

  const units = ["", "thousand", "million", "billion", "trillion", "quadrillion", "quintillion", "sextillion"];
  let unitIndex = 0;
  let val = n;
  while (val >= 1000 && unitIndex < units.length - 1) {
    val /= 1000;
    unitIndex++;
  }

  if (unitIndex >= units.length - 1 && val >= 1000) {
    return n.toExponential(2);
  }

  return `${val.toFixed(val < 10 ? 1 : 0)} ${units[unitIndex]}`.trim();
}

// ---- Crack time estimation ----
// NOTE: This is a theoretical estimate based on entropy math, not real
// breach data. It assumes a fast OFFLINE attack (~10 billion guesses/sec)
// against a weakly-hashed or unsalted password — a worst-case scenario.
// Real-world speed varies hugely depending on how the password is stored
// (bcrypt/Argon2 can slow this to thousands of guesses/sec) and whether
// the attack is online (often rate-limited to a handful of attempts).
function estimateCrackTime(pw) {
  if (!pw) return { display: "", poolSize: 0, entropyBits: 0, guessesPerSecond: 0 };

  let poolSize = 0;
  if (/[a-z]/.test(pw)) poolSize += 26;
  if (/[A-Z]/.test(pw)) poolSize += 26;
  if (/[0-9]/.test(pw)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) poolSize += 32;
  if (poolSize === 0) poolSize = 1;

  const entropyBits = pw.length * Math.log2(poolSize);
  const combinations = Math.pow(poolSize, pw.length);
  const guessesPerSecond = 10_000_000_000;
  let seconds = combinations / guessesPerSecond;

  const lower = pw.toLowerCase();
  const isDictionaryHit = isCommonPasswordPattern(pw);
  if (isDictionaryHit) {
    seconds = 0.001;
  }

  let display;
  if (seconds < 1) display = "Instantly";
  else if (seconds < 60) display = `${Math.round(seconds)} seconds`;
  else if (seconds < 3600) display = `${Math.round(seconds / 60)} minutes`;
  else if (seconds < 86400) display = `${Math.round(seconds / 3600)} hours`;
  else if (seconds < 31536000) display = `${Math.round(seconds / 86400)} days`;
  else {
    const years = seconds / 31536000;
    if (years < 1000) display = `${Math.round(years)} years`;
    else if (years < 1_000_000) display = `${Math.round(years / 1000)} thousand years`;
    else if (years < 1_000_000_000) display = `${Math.round(years / 1_000_000)} million years`;
    else display = `${Math.round(years / 1_000_000_000)} billion years`;
  }

  return { display, poolSize, entropyBits, guessesPerSecond, isDictionaryHit, combinations };
}

// ---- Strength label + color helpers ----
function getStrengthMeta(score) {
  if (score === 0) return { label: "Empty", color: "bg-slate-600", textColor: "text-slate-400", icon: ShieldX, ring: "ring-slate-500/20" };
  if (score <= 3) return { label: "Weak", color: "bg-rose-500", textColor: "text-rose-400", icon: ShieldX, ring: "ring-rose-500/30" };
  if (score <= 6) return { label: "Fair", color: "bg-amber-500", textColor: "text-amber-400", icon: ShieldAlert, ring: "ring-amber-500/30" };
  if (score <= 8) return { label: "Good", color: "bg-lime-500", textColor: "text-lime-400", icon: ShieldCheck, ring: "ring-lime-500/30" };
  return { label: "Strong", color: "bg-emerald-500", textColor: "text-emerald-400", icon: ShieldCheck, ring: "ring-emerald-500/30" };
}

function isPositive(fb) {
  return fb.startsWith("Strong password");
}

// ---- UI ----
export default function App() {
  const [password, setPassword] = useState("");
  const [suggestions, setSuggestions] = useState([]);
  const [history, setHistory] = useState([]);
  const [showPassword, setShowPassword] = useState(true);
  const [copied, setCopied] = useState(null);
  const [showInfo, setShowInfo] = useState(false);
  const [showScoreInfo, setShowScoreInfo] = useState(false);
  const [showSuggestionInfo, setShowSuggestionInfo] = useState(false);
  const [lastImprovement, setLastImprovement] = useState(null); // { from, to }
  const [suggestionMode, setSuggestionMode] = useState("leet"); // "leet" | "passphrase"
  const [showPersonalInfo, setShowPersonalInfo] = useState(false);
  const [personalInfo, setPersonalInfo] = useState({
    "Name": "",
    "Birth year": "",
    "Pet/nickname": "",
  });
  const [attackRunning, setAttackRunning] = useState(false);
  const [attackGuesses, setAttackGuesses] = useState(0);
  const [attackResult, setAttackResult] = useState(null); // "cracked" | "survived" | null

  const { score: baseScore, feedback, breakdown } = scorePassword(password);
  const personalMatches = checkPersonalInfoCollisions(password, personalInfo);
  const score = personalMatches.length > 0 ? Math.min(baseScore, 3) : baseScore;
  const meta = getStrengthMeta(score);
  const StrengthIcon = meta.icon;
  const crackInfo = personalMatches.length > 0
    ? { ...estimateCrackTime(password), display: "Instantly", isDictionaryHit: true }
    : estimateCrackTime(password);

  function regenerateSuggestions(pw) {
    setSuggestions(
      suggestionMode === "passphrase" ? suggestPassphrases(3) : suggestPasswords(pw)
    );
  }

  function handlePasswordChange(e) {
    const value = e.target.value;
    setPassword(value);
    regenerateSuggestions(value);
    setLastImprovement(null);
    stopAttackSimulation();
  }

  function applySuggestion(suggestion) {
    const beforeScore = scorePassword(password).score;
    const afterScore = scorePassword(suggestion).score;
    setHistory((prev) => [...prev, password]);
    setPassword(suggestion);
    regenerateSuggestions(suggestion);
    setLastImprovement({ from: beforeScore, to: afterScore });
    stopAttackSimulation();
  }

  function switchSuggestionMode(mode) {
    setSuggestionMode(mode);
    setSuggestions(mode === "passphrase" ? suggestPassphrases(3) : suggestPasswords(password));
  }

  function undoOneStep() {
    if (history.length === 0) return;
    const last = history[history.length - 1];
    setHistory((prev) => prev.slice(0, -1));
    setPassword(last);
    regenerateSuggestions(last);
    // If this undo lands us back on the very first password (history now empty),
    // there's no longer a "before → after" improvement to show
    if (history.length - 1 === 0) {
      setLastImprovement(null);
    }
  }

  function restoreOriginal() {
    if (history.length === 0) return;
    const original = history[0];
    setHistory([]);
    setPassword(original);
    regenerateSuggestions(original);
    setLastImprovement(null);
  }

  function copyToClipboard(text, index) {
    navigator.clipboard.writeText(text);
    setCopied(index);
    setTimeout(() => setCopied(null), 1500);
  }

  function generateReport() {
    if (!password) return;

    const timestamp = new Date().toLocaleString();
    const lines = [
      "PASSWORD GUARDIAN — SECURITY REPORT",
      `Generated: ${timestamp}`,
      "",
      "Note: The actual password is NOT included in this report for your safety.",
      "",
      `Strength score: ${score}/10 (${meta.label})`,
      `Estimated time to crack: ${crackInfo.display}`,
      `Password length: ${password.length} characters`,
      `Character types used: ${[
        /[a-z]/.test(password) && "lowercase",
        /[A-Z]/.test(password) && "uppercase",
        /[0-9]/.test(password) && "numbers",
        /[^a-zA-Z0-9]/.test(password) && "symbols",
      ].filter(Boolean).join(", ") || "none"}`,
      "",
      "Feedback:",
      ...feedback.map((f) => `  - ${f}`),
    ];

    if (personalMatches.length > 0) {
      lines.push("", `Warning: contains personal info you flagged (${personalMatches.join(", ")})`);
    }

    lines.push(
      "",
      "---",
      "This estimate is a simplified educational model, not real breach data.",
      "Generated entirely in your browser — nothing was sent to a server.",
    );

    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `password-guardian-report-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function clearPassword() {
    setPassword("");
    setSuggestions([]);
    setHistory([]);
    setLastImprovement(null);
    stopAttackSimulation();
  }

  const attackIntervalRef = useRef(null);

  function stopAttackSimulation() {
    if (attackIntervalRef.current) {
      clearInterval(attackIntervalRef.current);
      attackIntervalRef.current = null;
    }
    setAttackRunning(false);
    setAttackGuesses(0);
    setAttackResult(null);
  }

  // Runs a visual (time-compressed) simulation of a brute-force attack.
  // The counter animates rapidly regardless of actual password strength —
  // what differs is whether it lands on "cracked" or "still secure" at the
  // end, based on the real crack-time estimate. This is a demonstration,
  // not a real attack — it never tries to actually guess anything.
  function runAttackSimulation() {
    if (!password) return;
    stopAttackSimulation();

    const rawInfo = estimateCrackTime(password);
    const info = personalMatches.length > 0
      ? { ...rawInfo, display: "Instantly", isDictionaryHit: true }
      : rawInfo;
    const willCrack = info.isDictionaryHit || info.display.includes("second") ||
      info.display.includes("minute") || info.display.includes("hour") || info.display === "Instantly";

    // Target guess count: for dictionary hits, attackers find it almost
    // immediately from a wordlist (not by counting through combinations),
    // so use a small realistic number instead of the full brute-force space.
    // Otherwise, ramp toward the ACTUAL number of combinations this password
    // requires — so the animation reflects this specific password, not a
    // fixed generic number.
    const target = info.isDictionaryHit
      ? Math.floor(50 + Math.random() * 2000)
      : Math.max(info.combinations, 10);
    const logTarget = Math.log10(target);

    setAttackRunning(true);
    setAttackResult(null);
    const durationMs = 2500;
    const stepMs = 40;
    const steps = durationMs / stepMs;
    let step = 0;

    attackIntervalRef.current = setInterval(() => {
      step++;
      // Ramp exponentially in log space so it visually accelerates, but
      // lands exactly on the real target guess count at the end
      const count = Math.floor(Math.pow(10, logTarget * (step / steps)));
      setAttackGuesses(count);

      if (step >= steps) {
        clearInterval(attackIntervalRef.current);
        attackIntervalRef.current = null;
        setAttackRunning(false);
        setAttackGuesses(target);
        setAttackResult(willCrack ? "cracked" : "survived");
      }
    }, stepMs);
  }

  useEffect(() => {
    return () => stopAttackSimulation();
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex items-center justify-center p-4 sm:p-6">
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-40 left-1/2 -translate-x-1/2 w-[600px] h-[400px] bg-blue-500/10 rounded-full blur-[120px]" />
        <div className="absolute bottom-0 right-0 w-[400px] h-[300px] bg-emerald-500/5 rounded-full blur-[100px]" />
      </div>

      <div className="relative w-full max-w-lg">
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-blue-500 to-cyan-500 shadow-lg shadow-blue-500/30 mb-4">
            <Lock className="w-7 h-7 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Password Guardian</h1>
          <p className="text-sm text-slate-400 mt-1.5 flex items-center justify-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-blue-400" />
            Runs entirely in your browser — nothing is sent anywhere
          </p>
          <p className="text-xs text-slate-500 mt-2">
            78% of the world's most common passwords can be cracked in under a second — NordPass
          </p>
        </div>

        <div className="bg-slate-900/70 backdrop-blur-xl border border-slate-700/50 rounded-2xl shadow-2xl shadow-slate-950/50 p-6 sm:p-8">
          <div className="relative">
            <input
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={handlePasswordChange}
              placeholder="Type a password..."
              autoComplete="off"
              spellCheck={false}
              className="w-full px-4 py-3.5 pr-28 text-base text-white placeholder-slate-500 bg-slate-800/60 border border-slate-700/60 rounded-xl outline-none transition-all focus:border-blue-500/50 focus:ring-2 focus:ring-blue-500/20"
            />
            <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-1">
              {password && (
                <>
                  <button
                    onClick={() => copyToClipboard(password, "main")}
                    className="p-1.5 text-slate-400 hover:text-white transition-colors"
                    aria-label="Copy password"
                  >
                    {copied === "main" ? (
                      <Check className="w-5 h-5 text-emerald-400" />
                    ) : (
                      <Copy className="w-5 h-5" />
                    )}
                  </button>
                  <button
                    onClick={clearPassword}
                    className="p-1.5 text-slate-400 hover:text-white transition-colors"
                    aria-label="Clear password"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </>
              )}
              <button
                onClick={() => setShowPassword(!showPassword)}
                className="p-1.5 text-slate-400 hover:text-white transition-colors"
                aria-label="Toggle password visibility"
              >
                {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
          </div>

          {history.length > 0 && (
            <div className="flex flex-wrap gap-2 mt-3">
              <button
                onClick={undoOneStep}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-300 bg-slate-800/60 border border-slate-700/60 rounded-lg hover:bg-slate-700/60 hover:text-white transition-all"
              >
                <Undo2 className="w-3.5 h-3.5" />
                Undo last change
              </button>
              <button
                onClick={restoreOriginal}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-300 bg-slate-800/60 border border-slate-700/60 rounded-lg hover:bg-slate-700/60 hover:text-white transition-all"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                Restore original
              </button>
            </div>
          )}

          {/* Optional personal info check — never leaves the browser, not stored */}
          <button
            onClick={() => setShowPersonalInfo(!showPersonalInfo)}
            className="mt-3 inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-purple-300 bg-purple-500/10 border border-purple-500/30 rounded-lg hover:bg-purple-500/20 hover:border-purple-500/50 transition-all"
          >
            <UserCheck className="w-3.5 h-3.5" />
            {showPersonalInfo ? "Hide personal info check" : "Check against personal info"}
          </button>
          {!showPersonalInfo && (
            <p className="mt-1 text-[11px] text-slate-500">
              Optional — stays in your browser, never sent or saved
            </p>
          )}

          {showPersonalInfo && (
            <div className="mt-2 p-3 bg-slate-800/40 border border-slate-700/50 rounded-lg space-y-2">
              {Object.keys(personalInfo).map((label) => (
                <input
                  key={label}
                  type="text"
                  value={personalInfo[label]}
                  onChange={(e) =>
                    setPersonalInfo((prev) => ({ ...prev, [label]: e.target.value }))
                  }
                  placeholder={label}
                  className="w-full px-3 py-2 text-sm text-white placeholder-slate-500 bg-slate-800/60 border border-slate-700/60 rounded-lg outline-none focus:border-blue-500/50"
                />
              ))}
              <p className="text-xs text-slate-500">
                Used only to flag if your password contains this info — never sent anywhere or saved.
              </p>
            </div>
          )}

          {personalMatches.length > 0 && (
            <div className="mt-3 flex items-start gap-2 px-3 py-2 bg-rose-500/10 border border-rose-500/20 rounded-lg text-sm">
              <ShieldX className="w-4 h-4 text-rose-400 flex-shrink-0 mt-0.5" />
              <span className="text-rose-300">
                Your password contains your {personalMatches.join(" and ")} — this is one of the
                most common real-world weaknesses attackers exploit first.
              </span>
            </div>
          )}

          {password && (
            <div className="mt-6">
              <div className="flex items-center justify-between mb-2.5">
                <div className="flex items-center gap-2">
                  <div className={`flex items-center justify-center w-8 h-8 rounded-lg bg-slate-800/60 ring-1 ${meta.ring}`}>
                    <StrengthIcon className={`w-4 h-4 ${meta.textColor}`} />
                  </div>
                  <span className="text-sm font-semibold text-white">Strength</span>
                  <span className={`text-sm font-bold ${meta.textColor}`}>{meta.label}</span>
                  <button
                    onClick={() => setShowScoreInfo(!showScoreInfo)}
                    className="text-slate-500 hover:text-slate-300 transition-colors"
                    aria-label="How is the score calculated?"
                  >
                    <Info className="w-3.5 h-3.5" />
                  </button>
                </div>
                <span className="text-sm font-bold text-slate-300">
                  {score}<span className="text-slate-500 font-normal">/10</span>
                </span>
              </div>

              {showScoreInfo && breakdown && (
                <div className="mb-3 p-3 bg-slate-800/60 border border-slate-700/50 rounded-lg text-xs text-slate-400 space-y-1.5">
                  <p className="text-slate-300 font-medium">How this score is calculated</p>
                  <p>
                    Character pool: <span className="text-slate-200 font-mono">{breakdown.poolSize}</span> possible characters
                  </p>
                  <p>
                    Raw entropy: <span className="text-slate-200 font-mono">{breakdown.rawEntropyBits.toFixed(1)} bits</span> (length × log₂(pool size))
                  </p>
                  <p>
                    Uniqueness adjustment: <span className="text-slate-200 font-mono">{Math.round(breakdown.uniqueRatio * 100)}%</span> of
                    characters are unique, scaling entropy by <span className="text-slate-200 font-mono">{breakdown.repetitionMultiplier.toFixed(2)}x</span>
                  </p>
                  <p>
                    Adjusted entropy: <span className="text-slate-200 font-mono">{breakdown.adjustedEntropyBits.toFixed(1)} bits</span> → mapped to a 1-10 scale
                  </p>
                  {breakdown.wasCapped && (
                    <p className="text-amber-400/90">
                      Score capped at {score}/10 despite higher raw entropy — reason: {breakdown.capReason}.
                      Real attackers check for these patterns before brute-forcing, so they're treated as
                      an automatic weakness regardless of length.
                    </p>
                  )}
                  {personalMatches.length > 0 && (
                    <p className="text-rose-400/90">
                      Score also capped at 3/10 max — this password contains personal info you flagged
                      ({personalMatches.join(", ")}), which real attackers check for first.
                    </p>
                  )}
                  <p className="text-slate-500 italic pt-1">
                    Same underlying math as the crack-time estimate above — this is a simplified model,
                    not a guarantee of real-world resistance.
                  </p>
                </div>
              )}

              <div className="flex gap-1">
                {Array.from({ length: 10 }).map((_, i) => (
                  <div
                    key={i}
                    className={`h-2 flex-1 rounded-full transition-all duration-300 ${
                      i < score ? meta.color : "bg-slate-700/50"
                    }`}
                  />
                ))}
              </div>

              {crackInfo.display && (
                <div className="mt-3">
                  <div className="flex items-center gap-1.5">
                    <p className="text-xs text-slate-400 flex items-center gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400/70" />
                      Estimated time to crack: <span className="font-semibold text-slate-200">{crackInfo.display}</span>
                    </p>
                    <button
                      onClick={() => setShowInfo(!showInfo)}
                      className="text-slate-500 hover:text-slate-300 transition-colors"
                      aria-label="How is this calculated?"
                    >
                      <Info className="w-3.5 h-3.5" />
                    </button>
                  </div>

                  {showInfo && (
                    <div className="mt-2 p-3 bg-slate-800/60 border border-slate-700/50 rounded-lg text-xs text-slate-400 space-y-1.5">
                      <p className="text-slate-300 font-medium">How this is calculated</p>
                      <p>
                        Character pool: <span className="text-slate-200 font-mono">{crackInfo.poolSize}</span> possible characters
                        (based on which types you used — lowercase, uppercase, numbers, symbols)
                      </p>
                      <p>
                        Entropy: <span className="text-slate-200 font-mono">{crackInfo.entropyBits.toFixed(1)} bits</span> — length × log₂(pool size)
                      </p>
                      <p>
                        Assumes <span className="text-slate-200 font-mono">10 billion</span> guesses/second — a fast offline
                        attack against a weakly-hashed password
                      </p>
                      {crackInfo.isDictionaryHit && (
                        <p className="text-amber-400/90">
                          This matches a common/leetspeak password, so it's assumed to be cracked instantly
                          regardless of the math above — real attackers check dictionaries first.
                        </p>
                      )}
                      <p className="text-slate-500 italic pt-1">
                        This is a theoretical estimate, not real breach data. Actual crack time
                        depends heavily on how the password is stored (e.g. bcrypt is far slower
                        than this) and whether the attack is online (often rate-limited).
                      </p>
                    </div>
                  )}

                  {/* Attack simulator — visual demo only, no real cracking happens */}
                  <div className="mt-3">
                    {!attackRunning && attackResult === null && (
                      <button
                        onClick={runAttackSimulation}
                        className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded-lg hover:bg-amber-500/20 hover:border-amber-500/50 transition-all shadow-sm shadow-amber-500/10"
                      >
                        <Zap className="w-3.5 h-3.5" />
                        Simulate an attack
                      </button>
                    )}

                    {(attackRunning || attackResult !== null) && (
                      <div className={`p-3 rounded-lg border text-sm ${
                        attackResult === "cracked"
                          ? "bg-rose-500/10 border-rose-500/20"
                          : attackResult === "survived"
                          ? "bg-emerald-500/10 border-emerald-500/20"
                          : "bg-slate-800/60 border-slate-700/50"
                      }`}>
                        <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
                          <Zap className="w-3.5 h-3.5" />
                          {attackRunning ? "Simulating brute-force attempts..." : "Simulation complete"}
                        </div>
                        <p className="font-mono text-slate-200 text-xs">
                          {formatGuessCount(attackGuesses)} guesses attempted
                        </p>
                        {attackResult === "cracked" && (
                          <p className="mt-1.5 text-rose-300 font-medium flex items-center gap-1.5">
                            <ShieldX className="w-4 h-4" /> Cracked — this password wouldn't survive real attacks
                          </p>
                        )}
                        {attackResult === "survived" && (
                          <p className="mt-1.5 text-emerald-300 font-medium flex items-center gap-1.5">
                            <ShieldCheck className="w-4 h-4" /> Still uncracked at simulation end — estimated {crackInfo.display} at real attack speed
                          </p>
                        )}
                        {attackResult !== null && (
                          <button
                            onClick={stopAttackSimulation}
                            className="mt-2 text-xs text-slate-500 hover:text-slate-300 underline decoration-dotted"
                          >
                            Reset
                          </button>
                        )}
                        <p className="mt-1.5 text-[11px] text-slate-500 italic">
                          Animation is time-compressed for demonstration — no real cracking attempt is made.
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {password && (
            <div className="mt-5 space-y-2">
              {feedback.map((f, i) => {
                const positive = isPositive(f);
                return (
                  <div
                    key={i}
                    className={`flex items-start gap-2.5 text-sm ${
                      positive ? "text-emerald-400" : "text-slate-400"
                    }`}
                  >
                    {positive ? (
                      <CheckCircle2 className="w-4 h-4 mt-0.5 flex-shrink-0 text-emerald-400" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0 text-amber-400/80" />
                    )}
                    <span>{f}</span>
                  </div>
                );
              })}
            </div>
          )}

          {password && suggestions.length > 0 && (
            <div className="mt-6 pt-6 border-t border-slate-700/50">
              <div className="flex items-center gap-2 mb-3">
                <Sparkles className="w-4 h-4 text-blue-400" />
                <span className="text-sm font-semibold text-white">Stronger alternatives</span>
                <button
                  onClick={() => setShowSuggestionInfo(!showSuggestionInfo)}
                  className="text-slate-500 hover:text-slate-300 transition-colors"
                  aria-label="How are these generated?"
                >
                  <Info className="w-3.5 h-3.5" />
                </button>
              </div>

              {/* Mode toggle: leetspeak variant vs random passphrase */}
              <div className="flex gap-1.5 mb-3">
                <button
                  onClick={() => switchSuggestionMode("leet")}
                  className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-all ${
                    suggestionMode === "leet"
                      ? "bg-blue-500/20 border-blue-500/40 text-blue-300"
                      : "bg-slate-800/60 border-slate-700/60 text-slate-400 hover:text-slate-200"
                  }`}
                >
                  Leetspeak variant
                </button>
                <button
                  onClick={() => switchSuggestionMode("passphrase")}
                  className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-all ${
                    suggestionMode === "passphrase"
                      ? "bg-blue-500/20 border-blue-500/40 text-blue-300"
                      : "bg-slate-800/60 border-slate-700/60 text-slate-400 hover:text-slate-200"
                  }`}
                >
                  Random passphrase
                </button>
              </div>

              {/* Before → after comparison, shown right after applying a suggestion */}
              {lastImprovement && (
                <div className="mb-3 flex items-center gap-2 px-3 py-2 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-sm">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                  <span className="text-slate-300">
                    Score improved:
                  </span>
                  <span className="font-bold text-slate-400">{lastImprovement.from}/10</span>
                  <span className="text-slate-500">→</span>
                  <span className="font-bold text-emerald-400">{lastImprovement.to}/10</span>
                </div>
              )}

              {showSuggestionInfo && (
                <div className="mb-3 p-3 bg-slate-800/60 border border-slate-700/50 rounded-lg text-xs text-slate-400 space-y-1.5">
                  <p className="text-slate-300 font-medium">How these are generated</p>
                  {suggestionMode === "leet" ? (
                    <>
                      <p>
                        Each suggestion leetifies your original password (letters like a, e, i, o, s, t
                        become 4, 3, 1, 0, 5, 7), randomly flips the case of remaining letters, then
                        appends a random symbol and two digits.
                      </p>
                      <p>
                        Every suggestion is then checked and guaranteed to include: a lowercase letter,
                        an uppercase letter, a number, a symbol, and at least 8 characters.
                      </p>
                      <p className="text-slate-500 italic pt-1">
                        Keeping part of your original password makes it easier to remember, but simple
                        letter-to-number substitution is a well-known pattern — try "Random passphrase"
                        mode for something with less predictable structure.
                      </p>
                    </>
                  ) : (
                    <>
                      <p>
                        Three random, unrelated words are picked from a fixed word list and joined with
                        dashes, then a symbol and two digits are appended.
                      </p>
                      <p>
                        Unlike the leetspeak mode, this doesn't start from your original password at all —
                        so it isn't tied to any pattern an attacker could guess from it.
                      </p>
                      <p className="text-slate-500 italic pt-1">
                        Multi-word passphrases are generally both easier to remember and harder to
                        brute-force than short complex strings, per NIST guidance.
                      </p>
                    </>
                  )}
                </div>
              )}
              <div className="space-y-2">
                {suggestions.map((s, i) => (
                  <div
                    key={i}
                    className="group flex items-center gap-2 bg-slate-800/50 border border-slate-700/50 rounded-xl hover:border-blue-500/40 hover:bg-slate-800/80 transition-all"
                  >
                    <button
                      onClick={() => applySuggestion(s)}
                      className="flex-1 text-left px-4 py-3 font-mono text-sm text-slate-200 hover:text-white transition-colors"
                      title="Click to check this password"
                    >
                      {s}
                    </button>
                    <button
                      onClick={() => copyToClipboard(s, i)}
                      className="p-2.5 mr-2 text-slate-400 hover:text-white transition-colors"
                      aria-label="Copy to clipboard"
                    >
                      {copied === i ? (
                        <Check className="w-4 h-4 text-emerald-400" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                ))}
              </div>
              <button
                onClick={() => regenerateSuggestions(password)}
                className="mt-3 inline-flex items-center gap-2 px-4 py-2.5 text-sm font-medium text-slate-300 bg-slate-800/60 border border-slate-700/60 rounded-lg hover:bg-slate-700/60 hover:text-white transition-all"
              >
                <RefreshCw className="w-4 h-4" />
                Generate more
              </button>
            </div>
          )}

          {!password && (
            <div className="mt-6 flex flex-col items-center justify-center py-8 text-center">
              <div className="w-12 h-12 rounded-full bg-slate-800/60 flex items-center justify-center mb-3">
                <Lock className="w-5 h-5 text-slate-500" />
              </div>
              <p className="text-sm text-slate-500">
                Start typing above to check your password strength
              </p>
            </div>
          )}
          {password && (
            <div className="mt-6 pt-4 border-t border-slate-700/50 flex flex-col items-center gap-2">
              <button
                onClick={generateReport}
                className="inline-flex items-center gap-2 px-4 py-2.5 text-sm font-semibold text-white bg-gradient-to-r from-blue-500 to-cyan-500 rounded-lg hover:from-blue-400 hover:to-cyan-400 transition-all shadow-md shadow-blue-500/20"
              >
                <Download className="w-4 h-4" />
                Download security report
              </button>
              <p className="text-[11px] text-slate-500 text-center max-w-xs">
                The report only includes your strength score, estimated crack time, character
                types used, and feedback — never the actual password.
              </p>
            </div>
          )}
        </div>

        <p className="text-center text-xs text-slate-600 mt-4 flex items-center justify-center gap-1.5">
          <ShieldCheck className="w-3.5 h-3.5" />
          No data leaves your device
        </p>
      </div>
    </div>
  );
}