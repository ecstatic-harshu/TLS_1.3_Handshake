const STAGES = [
  { id: "tcp", icon: "🔌", title: "TCP Connection", desc: "The client opens a plain network connection to the secure proxy." },
  { id: "tls", icon: "🔐", title: "TLS 1.3 Handshake", desc: "A classical encrypted tunnel is set up first, the same as HTTPS in a browser." },
  { id: "pq", icon: "🛡️", title: "Post-Quantum Handshake", desc: "ML-KEM-768 exchanges a secret that even a future quantum computer can't break, and ML-DSA-65 verifies the proxy's identity." },
  { id: "hybrid", icon: "🧬", title: "Hybrid Key Derivation", desc: "The classical and post-quantum secrets are combined with HKDF-SHA256 into one master key." },
  { id: "channel", icon: "🔒", title: "Secure Channel Ready", desc: "An AES-256-GCM encrypted channel is now active between the client and the proxy." },
  { id: "send", icon: "📨", title: "Message Encrypted & Sent", desc: "Your message is sealed into unreadable ciphertext before it ever leaves the client." },
  { id: "proxy_relay", icon: "🔓", title: "Proxy Decrypts & Forwards", desc: "Only the proxy holds the key to open the envelope. It forwards the message as a normal HTTP request to your existing backend." },
  { id: "backend", icon: "🖥️", title: "Backend Handles Request", desc: "Your ordinary backend sees a normal, unmodified HTTP request — nothing about it needs to change." },
  { id: "response", icon: "🔏", title: "Response Re-Encrypted", desc: "The proxy seals the backend's reply back into an encrypted message." },
  { id: "receive", icon: "📬", title: "Client Decrypts Reply", desc: "The client unlocks the response with its secret key and shows the plaintext result." },
];

// What each node's caption should say while a given stage is on screen.
// A stage that doesn't mention a node leaves that node's caption alone.
const NODE_MESSAGES = {
  tcp: {
    client: "Opening a TCP connection to the proxy…",
    proxy: "Accepting the incoming connection…",
  },
  tls: {
    client: "Negotiating a TLS 1.3 tunnel with the proxy…",
    proxy: "Negotiating TLS 1.3 with the client…",
  },
  pq: {
    client: "Exchanging post-quantum keys (ML-KEM-768) and verifying the proxy's identity (ML-DSA-65)…",
    proxy: "Verifying the client and exchanging post-quantum keys…",
  },
  hybrid: {
    client: "Deriving the hybrid session key (HKDF-SHA256)…",
    proxy: "Deriving the matching hybrid session key…",
  },
  channel: {
    client: "Secure AES-256-GCM channel is ready.",
    proxy: "Secure AES-256-GCM channel is ready.",
  },
  send: {
    client: "Encrypting the message and sending it to the proxy 🔒",
    proxy: "Waiting for the encrypted message…",
  },
  proxy_relay: {
    proxy: "Decrypted the message — forwarding it as a plain HTTP request 🔓",
    backend: "Waiting for the request…",
  },
  backend: {
    backend: "Received a normal HTTP POST /echo — processing it, unaware any of this happened.",
    proxy: "Waiting for the backend's reply…",
  },
  response: {
    proxy: "Got the backend's reply — encrypting the response 🔏",
    backend: "Request handled, back to idle.",
  },
  receive: {
    client: "Decrypting the proxy's response 📬",
    proxy: "Encrypted response delivered to the client.",
  },
};

const IDLE_CAPTIONS = {
  client: "Idle — waiting to send a message",
  proxy: "Idle — waiting for a client",
  backend: "Idle — waiting for requests",
};

// How long autoplay holds on each pipeline step before advancing. Real
// crypto finishes in milliseconds; this paces the story so a human
// audience can actually follow it. Manual Prev/Next ignores this entirely.
const STAGE_STEP_MS = 1400;

const stageListEl = document.getElementById("stage-list");
const consoleEl = document.getElementById("console");
const toggleConsoleBtn = document.getElementById("toggle-console");
const resultEl = document.getElementById("result");
const resultSentEl = document.getElementById("result-sent");
const resultReplyEl = document.getElementById("result-reply");
const sendForm = document.getElementById("send-form");
const messageInput = document.getElementById("message-input");
const sendBtn = document.getElementById("send-btn");
const chipsEl = document.getElementById("chips");
const statusBackend = document.getElementById("status-backend");
const statusProxy = document.getElementById("status-proxy");
const nodeClient = document.getElementById("node-client");
const nodeProxy = document.getElementById("node-proxy");
const nodeBackend = document.getElementById("node-backend");
const packetLeft = document.getElementById("packet-left");
const packetRight = document.getElementById("packet-right");
const captionClient = document.getElementById("caption-client");
const captionProxy = document.getElementById("caption-proxy");
const captionBackend = document.getElementById("caption-backend");
const autoplayToggle = document.getElementById("autoplay-toggle");
const btnPrev = document.getElementById("btn-prev");
const btnPlayPause = document.getElementById("btn-playpause");
const btnNext = document.getElementById("btn-next");
const transportStatus = document.getElementById("transport-status");

function buildStageList() {
  stageListEl.innerHTML = "";
  STAGES.forEach((s) => {
    const li = document.createElement("li");
    li.className = "stage-item";
    li.id = `stage-${s.id}`;
    li.innerHTML = `
      <div class="stage-icon">${s.icon}</div>
      <div>
        <div class="stage-title">${s.title}</div>
        <div class="stage-desc">${s.desc}</div>
      </div>
    `;
    stageListEl.appendChild(li);
  });
}

function resetCaptions(text) {
  captionClient.textContent = text ? text.client : IDLE_CAPTIONS.client;
  captionProxy.textContent = text ? text.proxy : IDLE_CAPTIONS.proxy;
  captionBackend.textContent = text ? text.backend : IDLE_CAPTIONS.backend;
}

function updateCaptions(stageId) {
  const msgs = NODE_MESSAGES[stageId];
  if (!msgs) return;
  if (msgs.client) captionClient.textContent = msgs.client;
  if (msgs.proxy) captionProxy.textContent = msgs.proxy;
  if (msgs.backend) captionBackend.textContent = msgs.backend;
}

function resetStageList() {
  STAGES.forEach((s) => {
    const el = document.getElementById(`stage-${s.id}`);
    el.classList.remove("done", "active");
  });
  [nodeClient, nodeProxy, nodeBackend].forEach((n) => n.classList.remove("active"));
}

function flyPacket(el, direction, kind) {
  el.classList.remove("fly-fwd", "fly-back", "locked", "unlocked");
  void el.offsetWidth; // restart animation
  el.classList.add(kind);
  el.classList.add(direction === "fwd" ? "fly-fwd" : "fly-back");
}

function pulseNode(node) {
  node.classList.add("active");
  setTimeout(() => node.classList.remove("active"), STAGE_STEP_MS - 100);
}

function animateForStage(stageId) {
  switch (stageId) {
    case "tcp":
    case "tls":
    case "pq":
    case "hybrid":
    case "channel":
      pulseNode(nodeClient);
      pulseNode(nodeProxy);
      break;
    case "send":
      pulseNode(nodeClient);
      flyPacket(packetLeft, "fwd", "locked");
      break;
    case "proxy_relay":
      pulseNode(nodeProxy);
      flyPacket(packetRight, "fwd", "unlocked");
      break;
    case "backend":
      pulseNode(nodeBackend);
      break;
    case "response":
      pulseNode(nodeProxy);
      flyPacket(packetRight, "back", "unlocked");
      break;
    case "receive":
      pulseNode(nodeClient);
      flyPacket(packetLeft, "back", "locked");
      break;
  }
}

// =====================================
// STEPPABLE TIMELINE
// =====================================
//
// The real handshake + relay finishes in milliseconds. Stage events are
// appended to `timeline` as they arrive over SSE, and `currentIndex` is
// the step currently on screen. Play/Pause auto-advances on a timer;
// Prev/Next move by hand; both just move `currentIndex` and re-render —
// there's no separate "queue to drain," so going backward is as simple
// as going forward. The raw technical console keeps updating in true
// real time regardless of where the story pointer is.

let timeline = [];
let currentIndex = -1;
let playing = false;
let autoplayPref = false;
let runFinished = false;
let pendingResult = null;
let playTimer = null;

// True from the moment a run starts until its result is revealed —
// independent of whether the timer is actively ticking, so a paused
// mid-story view still blocks a new send.
let storyActive = false;

function renderStage(index) {
  resetStageList();

  for (let i = 0; i <= index; i++) {
    const stageId = timeline[i];
    const el = document.getElementById(`stage-${stageId}`);
    if (!el) continue;
    el.classList.add(i === index ? "active" : "done");
  }

  if (index >= 0) {
    const stageId = timeline[index];
    const el = document.getElementById(`stage-${stageId}`);
    if (el) el.scrollIntoView({ block: "nearest", behavior: "smooth" });
    animateForStage(stageId);
    updateCaptions(stageId);
  }

  updateTransportUI();
}

function updateTransportUI() {
  const total = timeline.length;
  const shown = currentIndex + 1;
  const caughtUp = currentIndex + 1 >= total;

  btnPlayPause.textContent = playing ? "⏸ Pause" : "▶ Auto Play";
  btnPlayPause.disabled = caughtUp && runFinished;
  btnPrev.disabled = currentIndex < 0;
  btnNext.disabled = caughtUp;

  transportStatus.textContent = total === 0 ? "No run yet" : `Step ${shown} / ${total}`;
}

function maybeRevealIfDone() {
  if (runFinished && currentIndex + 1 >= timeline.length && pendingResult) {
    const result = pendingResult;
    pendingResult = null;
    revealResult(result);
  }
}

function tick() {
  if (!playing) return;

  if (currentIndex + 1 < timeline.length) {
    currentIndex++;
    renderStage(currentIndex);
    playTimer = setTimeout(tick, STAGE_STEP_MS);
  } else if (runFinished) {
    pausePlaying();
    maybeRevealIfDone();
  } else {
    // Caught up but more stages may still arrive over SSE — check back shortly.
    playTimer = setTimeout(tick, 200);
  }
}

function startPlaying() {
  if (playing) return;
  playing = true;
  updateTransportUI();
  tick();
}

function pausePlaying() {
  playing = false;
  clearTimeout(playTimer);
  playTimer = null;
  updateTransportUI();
}

function stepNext() {
  pausePlaying();
  if (currentIndex + 1 < timeline.length) {
    currentIndex++;
    renderStage(currentIndex);
    maybeRevealIfDone();
  }
}

function stepPrev() {
  pausePlaying();
  if (currentIndex > 0) {
    currentIndex--;
    renderStage(currentIndex);
  } else if (currentIndex === 0) {
    currentIndex = -1;
    renderStage(currentIndex);
  }
}

function revealResult(data) {
  resultSentEl.textContent = data.message || "";
  resultReplyEl.textContent = data.success
    ? (data.reply || "(empty reply)")
    : `Error: ${data.error || "run failed"}`;
  resultEl.hidden = false;

  storyActive = false;
  sendBtn.disabled = false;

  resetCaptions({
    client: data.success ? "Done ✓ — response received and decrypted." : "Run failed — see technical log.",
    proxy: "Done ✓ — relayed one encrypted round trip.",
    backend: "Done ✓ — request handled.",
  });
}

// Groups the 10 pipeline stages into functional categories for log
// coloring: setting up the secure session, post-quantum crypto specifically,
// the encrypted client<->proxy leg, and the plain proxy<->backend leg —
// matching the same red (locked) / green (unlocked) language as the
// topology packets above.
const STAGE_LOG_CLASS = {
  tcp: "log-setup",
  tls: "log-setup",
  channel: "log-success",
  pq: "log-pq",
  hybrid: "log-pq",
  send: "log-encrypted",
  receive: "log-encrypted",
  proxy_relay: "log-plain",
  backend: "log-plain",
  response: "log-plain",
};

const ERROR_PATTERN = /error|traceback|exception|failed|failure/i;

function classifyLogClass(stage, line) {
  if (ERROR_PATTERN.test(line)) return "log-error";
  return STAGE_LOG_CLASS[stage] || "log-default";
}

function appendLog(source, line, stage) {
  const div = document.createElement("div");
  div.className = `line ${classifyLogClass(stage, line)}`;
  const tag = source.toUpperCase();
  div.textContent = `[${tag}] ${line}`;
  consoleEl.appendChild(div);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function setStatus(el, online) {
  el.classList.remove("online", "offline");
  el.classList.add(online ? "online" : "offline");
}

function refreshStatus() {
  fetch("/status")
    .then((r) => r.json())
    .then((data) => {
      setStatus(statusBackend, data.backend === "online");
      setStatus(statusProxy, data.proxy === "online");
      if (!storyActive) {
        sendBtn.disabled = !!data.busy;
      }
    })
    .catch(() => {});
}

function connectEvents() {
  const es = new EventSource("/events");

  es.onmessage = (evt) => {
    let data;
    try {
      data = JSON.parse(evt.data);
    } catch (e) {
      return;
    }

    if (data.type === "log") {
      appendLog(data.source, data.line, data.stage);
      if (data.stage && timeline[timeline.length - 1] !== data.stage) {
        timeline.push(data.stage);
        updateTransportUI();
      }
    } else if (data.type === "run_start") {
      pausePlaying();
      timeline = [];
      currentIndex = -1;
      runFinished = false;
      pendingResult = null;
      storyActive = true;

      resetStageList();
      resetCaptions({
        client: "Starting a new secure connection…",
        proxy: IDLE_CAPTIONS.proxy,
        backend: IDLE_CAPTIONS.backend,
      });
      resultEl.hidden = true;
      sendBtn.disabled = true;
      updateTransportUI();

      if (autoplayPref) startPlaying();
    } else if (data.type === "run_complete") {
      runFinished = true;
      pendingResult = data;
      updateTransportUI();
      maybeRevealIfDone();
    }
  };

  es.onerror = () => {
    // EventSource auto-reconnects; nothing to do here.
  };
}

function sendMessage(message) {
  fetch("/send", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  }).then((r) => {
    if (r.status === 409) {
      alert("A demo run is already in progress, please wait for it to finish.");
    }
  });
}

sendForm.addEventListener("submit", (e) => {
  e.preventDefault();
  const message = messageInput.value.trim();
  if (!message) return;
  sendMessage(message);
});

chipsEl.addEventListener("click", (e) => {
  const btn = e.target.closest(".chip");
  if (!btn) return;
  messageInput.value = btn.dataset.msg;
  sendMessage(btn.dataset.msg);
});

toggleConsoleBtn.addEventListener("click", () => {
  const hidden = consoleEl.hasAttribute("hidden");
  if (hidden) {
    consoleEl.removeAttribute("hidden");
    toggleConsoleBtn.textContent = "Hide";
  } else {
    consoleEl.setAttribute("hidden", "");
    toggleConsoleBtn.textContent = "Show";
  }
});

btnPlayPause.addEventListener("click", () => {
  if (playing) pausePlaying();
  else startPlaying();
});

btnNext.addEventListener("click", stepNext);
btnPrev.addEventListener("click", stepPrev);

// Autoplay starts OFF: a run only walks itself forward if the presenter
// opts in. Otherwise Play/Next stay fully manual.
autoplayToggle.checked = false;
autoplayToggle.addEventListener("change", () => {
  autoplayPref = autoplayToggle.checked;
});

buildStageList();
updateTransportUI();
refreshStatus();
setInterval(refreshStatus, 4000);
connectEvents();
