import { checkPwnedPassword } from "./pwned-passwords.js";

const PWNED_TIMEOUT_MS = 1_000;

const input = document.getElementById("password");
const resultsElement = document.getElementById("results");
const breachStatus = document.getElementById("breach-status");
const breachMessage = document.getElementById("breach-message");
const announcer = document.getElementById("status-announcer");

let activeBreachCheck;

async function loadWasm() {
  const go = new Go();
  try {
    const result = await WebAssembly.instantiateStreaming(
      fetch("main.wasm"),
      go.importObject
    );
    go.run(result.instance);
  } catch (error) {
    document.getElementById("loading").textContent =
      "Failed to load WASM: " + error.message;
    return;
  }

  document.getElementById("loading").classList.add("hidden");
  input.disabled = false;
  input.focus();
}

function updateLocalAnalysis(password) {
  if (!password) {
    resultsElement.classList.add("hidden");
    return;
  }

  const data = JSON.parse(window.analyzePassword(password));
  resultsElement.classList.remove("hidden");

  const labelClass = data.label.toLowerCase().replace(/ /g, "-");

  const bar = document.getElementById("strength-bar");
  bar.style.width = data.score + "%";
  bar.className = "strength-bar " + labelClass;

  const meter = document.getElementById("strength-meter");
  meter.setAttribute("aria-valuenow", data.score);
  meter.setAttribute(
    "aria-valuetext",
    `${data.label}, score ${data.score} out of 100`
  );

  const label = document.getElementById("strength-label");
  label.textContent = data.label;
  label.className = "strength-label " + labelClass;

  document.getElementById("entropy").textContent =
    data.entropy.toFixed(1) + " bits";
  document.getElementById("charset").textContent =
    data.charsetSize + " chars";
  document.getElementById("crack-time").textContent = data.timeEstimate;

  const patternsElement = document.getElementById("patterns");
  patternsElement.replaceChildren();
  for (const pattern of data.patterns || []) {
    const chip = document.createElement("span");
    chip.className = "pattern-chip";
    chip.textContent = "⚠ " + pattern;
    patternsElement.appendChild(chip);
  }
}

function setBreachStatus(state, message, { announce = false } = {}) {
  breachStatus.dataset.state = state;
  if (state === "checking") {
    breachStatus.setAttribute("aria-busy", "true");
  } else {
    breachStatus.removeAttribute("aria-busy");
  }
  breachMessage.textContent = message;
  if (announce) {
    announcer.textContent = message;
  }
}

function resetBreachStatus() {
  setBreachStatus("idle", "Checked after you leave the password field.");
  announcer.textContent = "";
}

function renderBreachResult(result) {
  switch (result.status) {
    case "pwned": {
      const occurrences = result.occurrences.toLocaleString();
      setBreachStatus(
        "pwned",
        `Found in known breaches ${occurrences} times. Do not use this password.`,
        { announce: true }
      );
      break;
    }
    case "not-pwned":
      setBreachStatus(
        "not-pwned",
        "Not found in the known-password corpus. This does not guarantee safety.",
        { announce: true }
      );
      break;
    case "timeout":
      setBreachStatus(
        "unavailable",
        "Breach check timed out. The local analysis is still available.",
        { announce: true }
      );
      break;
    case "unavailable":
      setBreachStatus(
        "unavailable",
        "Breach check is unavailable. The local analysis is still available.",
        { announce: true }
      );
      break;
  }
}

async function runBreachCheck(password) {
  activeBreachCheck?.abort();
  const controller = new AbortController();
  activeBreachCheck = controller;

  setBreachStatus("checking", "Checking known breaches…");

  const result = await checkPwnedPassword(password, {
    timeoutMs: PWNED_TIMEOUT_MS,
    signal: controller.signal,
  });

  if (
    activeBreachCheck !== controller ||
    input.value !== password ||
    result.status === "cancelled"
  ) {
    return;
  }

  activeBreachCheck = undefined;
  renderBreachResult(result);
}

input.addEventListener("input", (event) => {
  activeBreachCheck?.abort();
  activeBreachCheck = undefined;
  updateLocalAnalysis(event.target.value);
  resetBreachStatus();
});

input.addEventListener("blur", () => {
  if (input.value) {
    runBreachCheck(input.value);
  }
});

loadWasm();
