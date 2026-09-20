const STAGE_DEFS = [
  {
    id: "tcp",
    title: "TCP Connection",
    icon: "🔌",
    text: "The client opens a plain network connection to the secure proxy."
  },
  {
    id: "tls",
    title: "TLS 1.3 Handshake",
    icon: "🔐",
    text: "A classical encrypted tunnel is set up first (TLS 1.3) as the outer pipe."
  },
  {
    id: "pq",
    title: "Post-Quantum Handshake",
    icon: "🛡️",
    text: "ML-KEM-768 exchanges a secret resistant to quantum attacks, and ML-DSA-65 verifies identity over the transcript."
  },
  {
    id: "hybrid",
    title: "Hybrid Key Derivation",
    icon: "🧬",
    text: "The classical TLS contribution and post-quantum shared secret are combined with HKDF into a master key."
  },
  {
    id: "channel",
    title: "Secure Channel Ready",
    icon: "⚡",
    text: "Directional AES-256-GCM keys are ready. Application messages can now be encrypted end-to-end on this hop."
  },
  {
    id: "send",
    title: "Encrypted Message Sent",
    icon: "📤",
    text: "Your plaintext is sealed with AES-GCM and sent to the proxy as a secure message."
  },
  {
    id: "proxy_relay",
    title: "Proxy Opens PQ Server Hop",
    icon: "🔁",
    text: "The proxy starts a second post-quantum session to the PQ secure server (--backend-pq)."
  },
  {
    id: "backend",
    title: "PQ Secure Server Handles Message",
    icon: "🖥️",
    text: "The PQ server (--mode server) receives the sealed payload and prepares an ACK reply."
  },
  {
    id: "response",
    title: "Encrypted Reply Returned",
    icon: "📥",
    text: "The server reply travels back over the PQ↔PQ hop, then the client PQ channel."
  }
];

const PACE = {
  slow: { log: 900, stage: 2600 },
  normal: { log: 450, stage: 1600 },
  fast: { log: 180, stage: 700 }
};

let LOG_MS = PACE.normal.log;
let STAGE_HOLD_MS = PACE.normal.stage;
const MAX_LOG_LINES = 120;

const stageOrder = STAGE_DEFS.map((s) => s.id);
const activated = new Set();
let currentIndex = -1;
let autoplay = true;
let runActive = false;
let lastHint = "";
let logFilter = "all";
let previewRunning = false;

const eventQueue = [];
let draining = false;
let pendingComplete = null;

const stagesEl = document.getElementById("stages");
const logEl = document.getElementById("log");
const messageEl = document.getElementById("message");
const sendBtn = document.getElementById("send-btn");
const sendHint = document.getElementById("send-hint");
const replyEl = document.getElementById("reply");
const stepCount = document.getElementById("step-count");
const progressBar = document.getElementById("progress-bar");
const charCount = document.getElementById("char-count");
const statusBackend = document.getElementById("status-backend");
const statusProxy = document.getElementById("status-proxy");
const topologyEl = document.getElementById("topology");
const flowStatusEl = document.getElementById("flow-status");
const linkPq = document.getElementById("link-pq");
const linkBackend = document.getElementById("link-backend");
const captionPq = document.getElementById("caption-pq");
const captionBackend = document.getElementById("caption-backend");
const nodeClient = document.getElementById("node-client");
const nodeProxy = document.getElementById("node-proxy");
const nodeBackend = document.getElementById("node-backend");
const inspectEl = document.getElementById("inspect");
const inspectTitle = document.getElementById("inspect-title");
const inspectBody = document.getElementById("inspect-body");
const tipBanner = document.getElementById("tip-banner");
const tipTitle = document.getElementById("tip-title");
const tipBody = document.getElementById("tip-body");
const previewBtn = document.getElementById("preview-path");

const FLOW_BY_STAGE = {
  tcp: "handshake",
  tls: "handshake",
  pq: "handshake",
  hybrid: "handshake",
  channel: "handshake",
  send: "client_to_proxy",
  proxy_relay: "proxy_to_backend",
  backend: "at_backend",
  response: "return_path",
  receive: "return_path"
};

const INSPECT = {
  client: {
    title: "Client App",
    body: "Runs inside a throwaway Docker container and speaks the PQ client protocol (secure_connect → send_secure → receive_secure)."
  },
  proxy: {
    title: "Secure Proxy",
    body: "Terminates the client PQ session, then opens a second PQ session to the server with --backend-pq (PQ↔PQ relay)."
  },
  backend: {
    title: "PQ Secure Server",
    body: "A --mode server instance that speaks the same PQ stack and replies with ACK: <message>."
  },
  "link-client": {
    title: "Client ↔ Proxy channel",
    body: "TLS 1.3 outer tunnel + ML-KEM-768 / ML-DSA-65 hybrid keys + AES-256-GCM application messages."
  },
  "link-server": {
    title: "Proxy ↔ Server PQ hop",
    body: "Second post-quantum session. Same crypto family as the client hop — no plain HTTP in this demo."
  }
};

const CRYPTO_TIPS = {
  tls: {
    title: "TLS 1.3",
    body: "Classical outer encrypted pipe. Provides the TLS contribution mixed into the hybrid key."
  },
  kem: {
    title: "ML-KEM-768",
    body: "Post-quantum key encapsulation (Kyber family). Creates a shared secret resistant to quantum attacks."
  },
  dsa: {
    title: "ML-DSA-65",
    body: "Post-quantum digital signature (Dilithium family). Authenticates the peer over the handshake transcript."
  },
  hkdf: {
    title: "HKDF-SHA256",
    body: "Combines classical TLS material + PQ shared secret into directional session keys."
  },
  aes: {
    title: "AES-256-GCM",
    body: "Authenticated encryption for application payloads after the hybrid handshake completes."
  }
};

function setHint(text) {
  lastHint = text;
  sendHint.textContent = text;
}

function setFlow(mode) {
  if (!topologyEl) return;

  const nodes = [nodeClient, nodeProxy, nodeBackend];
  const links = [linkPq, linkBackend];

  nodes.forEach((n) => n && n.classList.remove("active"));
  links.forEach((l) => {
    if (!l) return;
    l.classList.remove("active", "flow-down", "flow-up", "returning");
  });
  if (captionPq) captionPq.textContent = "";
  if (captionBackend) captionBackend.textContent = "";

  topologyEl.dataset.flow = mode;

  if (mode === "idle") {
    flowStatusEl.textContent = "Idle — send a message, or click Preview path.";
    return;
  }

  if (mode === "handshake") {
    nodeClient.classList.add("active");
    nodeProxy.classList.add("active");
    linkPq.classList.add("active", "flow-down");
    captionPq.textContent = "↓ client PQ handshake";
    flowStatusEl.textContent = "Client ↔ Proxy: negotiating the post-quantum secure channel…";
    return;
  }

  if (mode === "client_to_proxy") {
    nodeClient.classList.add("active");
    nodeProxy.classList.add("active");
    linkPq.classList.add("active", "flow-down");
    captionPq.textContent = "↓ encrypted message";
    flowStatusEl.textContent = "Client → Proxy: sealed AES-GCM payload on the client PQ channel…";
    return;
  }

  if (mode === "proxy_to_backend") {
    nodeProxy.classList.add("active");
    nodeBackend.classList.add("active");
    linkBackend.classList.add("active", "flow-down");
    captionBackend.textContent = "↓ PQ↔PQ hop";
    flowStatusEl.textContent = "Proxy → PQ Server: second post-quantum session (--backend-pq)…";
    return;
  }

  if (mode === "at_backend") {
    nodeBackend.classList.add("active");
    nodeProxy.classList.add("active");
    linkBackend.classList.add("active", "flow-down");
    captionBackend.textContent = "↓ PQ server processing";
    flowStatusEl.textContent = "PQ Secure Server: handling the message over the PQ session…";
    return;
  }

  if (mode === "return_path") {
    nodeBackend.classList.add("active");
    nodeProxy.classList.add("active");
    nodeClient.classList.add("active");
    linkBackend.classList.add("active", "flow-up", "returning");
    linkPq.classList.add("active", "flow-up", "returning");
    captionBackend.textContent = "↑ PQ server reply";
    captionPq.textContent = "↑ re-encrypted to client";
    flowStatusEl.textContent = "PQ Server → Proxy → Client: reply on both PQ hops…";
  }
}

function syncFlowToCurrentStage() {
  if (currentIndex < 0) return;
  const stageId = stageOrder[currentIndex];
  const flow = FLOW_BY_STAGE[stageId];
  if (flow) setFlow(flow);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function updateCharCount() {
  const n = messageEl.value.length;
  charCount.textContent = `${n}/300`;
}

function showInspect(role) {
  const info = INSPECT[role];
  if (!info) return;

  [nodeClient, nodeProxy, nodeBackend, linkPq, linkBackend].forEach((el) => {
    if (!el) return;
    el.classList.toggle("selected", el.dataset.role === role);
    if (el.classList.contains("node")) {
      el.setAttribute("aria-pressed", el.dataset.role === role ? "true" : "false");
    }
  });

  inspectTitle.textContent = info.title;
  inspectBody.textContent = info.body;
  inspectEl.hidden = false;

  if (role === "client" || role === "link-client") setFlow("handshake");
  if (role === "proxy") setFlow("client_to_proxy");
  if (role === "link-server") setFlow("proxy_to_backend");
  if (role === "backend") setFlow("at_backend");
}

function hideInspect() {
  inspectEl.hidden = true;
  [nodeClient, nodeProxy, nodeBackend, linkPq, linkBackend].forEach((el) => {
    if (!el) return;
    el.classList.remove("selected");
    if (el.classList.contains("node")) el.setAttribute("aria-pressed", "false");
  });
  if (!runActive && !previewRunning) setFlow("idle");
}

function showTip(key) {
  const tip = CRYPTO_TIPS[key];
  if (!tip) return;
  tipTitle.textContent = tip.title;
  tipBody.textContent = tip.body;
  tipBanner.hidden = false;
  document.querySelectorAll(".badge").forEach((b) => {
    b.classList.toggle("active-tip", b.dataset.tip === key);
  });
}

function hideTip() {
  tipBanner.hidden = true;
  document.querySelectorAll(".badge").forEach((b) => b.classList.remove("active-tip"));
}

function renderStages() {
  stagesEl.innerHTML = "";
  STAGE_DEFS.forEach((stage, index) => {
    const li = document.createElement("li");
    li.className = "stage locked";
    li.dataset.stage = stage.id;
    li.tabIndex = 0;
    li.setAttribute("role", "button");
    li.innerHTML = `
      <div class="stage-top">
        <div class="stage-icon">${stage.icon}</div>
        <h3>${index + 1}. ${stage.title}</h3>
      </div>
      <p>${stage.text}</p>
    `;
    li.addEventListener("click", () => jumpToStage(stage.id));
    li.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        jumpToStage(stage.id);
      }
    });
    stagesEl.appendChild(li);
  });
  updateStageUI();
}

function jumpToStage(stageId) {
  if (!activated.has(stageId) && !previewRunning) return;
  const idx = stageOrder.indexOf(stageId);
  if (idx < 0) return;
  currentIndex = idx;
  updateStageUI();
  syncFlowToCurrentStage();
  const el = stagesEl.querySelector(`[data-stage="${stageId}"]`);
  if (el) el.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function updateStageUI() {
  const items = [...stagesEl.querySelectorAll(".stage")];
  items.forEach((el, idx) => {
    el.classList.remove("active", "done", "locked");
    const id = el.dataset.stage;
    const unlocked = activated.has(id) || previewRunning;
    if (!unlocked) el.classList.add("locked");
    if (activated.has(id) && idx < currentIndex) el.classList.add("done");
    if (idx === currentIndex) el.classList.add("active");
  });

  const shown = currentIndex >= 0 ? currentIndex + 1 : 0;
  stepCount.textContent = `Step ${shown} / ${STAGE_DEFS.length}`;
  const pct = currentIndex < 0 ? 0 : ((currentIndex + 1) / STAGE_DEFS.length) * 100;
  progressBar.style.width = `${pct}%`;
}

function activateStage(stageId) {
  if (!stageId || !stageOrder.includes(stageId)) return;

  const idx = stageOrder.indexOf(stageId);
  const isNew = !activated.has(stageId);
  if (isNew) activated.add(stageId);

  if (autoplay || currentIndex < 0) {
    if (idx >= currentIndex) {
      currentIndex = idx;
      syncFlowToCurrentStage();
    }
  }

  updateStageUI();

  if (isNew) {
    const el = stagesEl.querySelector(`[data-stage="${stageId}"]`);
    if (el) el.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}

function resetPipeline({ clearLog = true } = {}) {
  activated.clear();
  currentIndex = -1;
  eventQueue.length = 0;
  pendingComplete = null;
  setFlow("idle");
  updateStageUI();
  replyEl.hidden = true;
  replyEl.classList.remove("error");
  replyEl.textContent = "";
  if (clearLog) logEl.innerHTML = "";
}

function colorClassFor(source, stage, line) {
  if (line && (line.includes("ERROR") || line.includes("error") || line.includes("Failed"))) {
    return "error";
  }
  if (stage === "pq" || stage === "hybrid") return "pq";
  if (stage === "channel") return "ready";
  if (stage === "tls" || stage === "send" || stage === "response" || stage === "receive") {
    return "encrypted";
  }
  if (stage === "backend" || stage === "proxy_relay") return "pq";
  if (stage === "tcp") return "setup";
  if (source === "client") return "setup";
  if (source === "proxy" || source === "backend") return "pq";
  return "setup";
}

function explainLog(source, stage, line) {
  const text = line || "";
  const rules = [
    { test: /Starting secure round-trip/i, title: "Demo started", why: "The dashboard launched a one-shot secure client for your message." },
    { test: /Connecting to /i, title: "Client dialing proxy", why: "Opening a network connection to the quantum-safe proxy address." },
    { test: /TCP_CONNECT\b|TCP connection established|TCP_CONNECTED/i, title: "TCP connection", why: "A plain socket is open between client and proxy — no crypto yet." },
    { test: /TCP client connected/i, title: "Proxy accepted TCP", why: "The proxy saw a new inbound connection from a client." },
    { test: /TLS_HANDSHAKE|TLS connection established|TLS established|TLS_CONNECTED|TLS_HANDSHAKE_COMPLETE/i, title: "TLS 1.3 tunnel", why: "Classical TLS finished. Traffic is encrypted with today’s crypto as an outer pipe." },
    { test: /TLS Cipher:|TLS_METADATA/i, title: "TLS cipher suite", why: "Shows which classical TLS algorithms were negotiated for this session." },
    { test: /AUTHENTICATED_PQ_HANDSHAKE/i, title: "Post-quantum handshake", why: "Starting ML-KEM key exchange + ML-DSA identity proof on top of TLS." },
    { test: /PQ KEM:/i, title: "ML-KEM-768 key exchange", why: "Both sides agreed on a shared secret that quantum computers cannot efficiently break." },
    { test: /PQ Signature:/i, title: "ML-DSA-65 authentication", why: "The proxy’s post-quantum signature proves you are talking to the real proxy." },
    { test: /HYBRID_KEY_DERIVATION|HYBRID_KEY_DERIVED/i, title: "Hybrid key derivation", why: "TLS + PQ secrets are combined with HKDF into session keys." },
    { test: /SECURE_CHANNEL_CREATION|SECURE_CHANNEL_CREATED|Secure Channel:/i, title: "AES-GCM channel keys", why: "Directional AES-256-GCM keys are ready for application messages." },
    { test: /Secure session established|Authentication: SUCCESS/i, title: "Secure session ready", why: "Handshake succeeded. Encrypted payloads can flow." },
    { test: /Secure message sent|Sent message:/i, title: "Encrypted payload sent", why: "Your plaintext was sealed with AES-GCM and transmitted." },
    { test: /Secure message received/i, title: "Encrypted payload received", why: "A sealed message arrived and was authenticated + decrypted." },
    { test: /Received reply:/i, title: "Client got the reply", why: "The secure client decrypted the PQ server’s response." },
    { test: /PQ backend mode|PQ backend session|PQ↔PQ/i, title: "Proxy → PQ server hop", why: "Proxy opens a second post-quantum session (--backend-pq)." },
    { test: /ACK:/i, title: "PQ server ACK", why: "The PQ secure server processed the message and sent an acknowledgement." },
    { test: /Connection closed/i, title: "Client disconnected", why: "Demo client closed the socket after one full round-trip." },
    { test: /ERROR|Failed|failed/i, title: "Error", why: "Something failed — check the raw line for the exact cause." }
  ];

  for (const rule of rules) {
    if (rule.test.test(text)) return { title: rule.title, why: rule.why };
  }

  if (source === "backend") return { title: "PQ server log", why: "Output from the PQ secure server (--mode server)." };
  if (source === "proxy") return { title: "Proxy log", why: "Output from the quantum-safe proxy process." };
  if (source === "client") return { title: "Client log", why: "Output from the demo secure client container." };
  return { title: "System log", why: "Raw process output from the demo stack." };
}

function applyLogFilter() {
  [...logEl.children].forEach((el) => {
    if (logFilter === "all") {
      el.classList.remove("hidden-filter");
    } else {
      el.classList.toggle("hidden-filter", !el.classList.contains(logFilter));
    }
  });
}

function trimLog() {
  while (logEl.children.length > MAX_LOG_LINES) {
    logEl.removeChild(logEl.firstChild);
  }
}

function paintLogLine(event) {
  const div = document.createElement("div");
  const cls = colorClassFor(event.source, event.stage, event.line);
  const explain = explainLog(event.source, event.stage, event.line);
  const src = (event.source || "sys").toUpperCase();

  div.className = `log-line ${cls} log-enter`;
  if (event.stage) div.dataset.stage = event.stage;
  div.innerHTML = `
    <div class="log-meta">
      <span class="src">[${src}]</span>
      <span class="log-title">${escapeHtml(explain.title)}</span>
    </div>
    <div class="log-raw">${escapeHtml(event.line || "")}</div>
    <div class="log-why">${escapeHtml(explain.why)}</div>
  `;
  div.addEventListener("click", () => {
    div.classList.add("flash");
    setTimeout(() => div.classList.remove("flash"), 600);
    if (event.stage) jumpToStage(event.stage);
  });

  logEl.appendChild(div);
  applyLogFilter();
  trimLog();
  logEl.scrollTop = logEl.scrollHeight;

  if (runActive && event.stage) activateStage(event.stage);
}

function enqueueLog(event) {
  if (!runActive && !event.forcePace) {
    paintLogLine(event);
    return;
  }
  eventQueue.push(event);
  drainQueue();
}

async function drainQueue() {
  if (draining) return;
  draining = true;

  while (eventQueue.length) {
    const event = eventQueue.shift();
    const isNewStage =
      runActive &&
      event.stage &&
      stageOrder.includes(event.stage) &&
      !activated.has(event.stage);

    paintLogLine(event);
    await sleep(isNewStage ? STAGE_HOLD_MS : LOG_MS);
  }

  draining = false;

  if (pendingComplete) {
    const done = pendingComplete;
    pendingComplete = null;
    finishRun(done);
  }
}

function finishRun(event) {
  runActive = false;
  sendBtn.disabled = false;
  previewBtn.disabled = false;
  replyEl.hidden = false;
  if (event.success) {
    replyEl.classList.remove("error");
    replyEl.textContent = `PQ server reply: ${event.reply}`;
    setHint("Round-trip complete. Click stages, nodes, or Preview path anytime.");
    activateStage("response");
    setFlow("return_path");
    setTimeout(() => {
      if (topologyEl.dataset.flow === "return_path") {
        flowStatusEl.textContent = "Round-trip complete — click any node to inspect.";
      }
    }, 2200);
  } else {
    replyEl.classList.add("error");
    replyEl.textContent = event.error || "Demo run failed.";
    setHint("Something failed — check the live log.");
    setFlow("idle");
    flowStatusEl.textContent = "Stopped — error during the demo run.";
  }
  refreshStatus();
}

function escapeHtml(text) {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

async function refreshStatus() {
  try {
    const res = await fetch("/status");
    const data = await res.json();
    setPill(statusBackend, data.backend);
    setPill(statusProxy, data.proxy);

    const busy = !!data.busy || draining || eventQueue.length > 0 || runActive;
    sendBtn.disabled = busy;
    previewBtn.disabled = busy || previewRunning;
  } catch (_) {
    setPill(statusBackend, "offline");
    setPill(statusProxy, "offline");
  }
}

function setPill(el, status) {
  el.classList.remove("online", "offline", "starting");
  const normalized = status || "offline";
  el.classList.add(
    normalized === "online" ? "online" : normalized === "starting" ? "starting" : "offline"
  );
}

async function sendMessage() {
  const message = messageEl.value.trim();
  if (!message) return;
  if (runActive || sendBtn.disabled || previewRunning) return;

  hideInspect();
  resetPipeline({ clearLog: true });
  runActive = true;
  sendBtn.disabled = true;
  previewBtn.disabled = true;
  setHint("Starting secure client through Docker…");

  try {
    const res = await fetch("/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
  } catch (err) {
    runActive = false;
    sendBtn.disabled = false;
    previewBtn.disabled = false;
    setHint("Could not start demo run.");
    replyEl.hidden = false;
    replyEl.classList.add("error");
    replyEl.textContent = String(err.message || err);
  }
}

async function previewPath() {
  if (runActive || previewRunning || sendBtn.disabled) return;
  previewRunning = true;
  previewBtn.disabled = true;
  sendBtn.disabled = true;
  hideInspect();
  activated.clear();
  STAGE_DEFS.forEach((s) => activated.add(s.id));

  const sequence = [
    "handshake",
    "client_to_proxy",
    "proxy_to_backend",
    "at_backend",
    "return_path"
  ];
  const stageHits = ["tcp", "send", "proxy_relay", "backend", "response"];

  setHint("Preview only — no real crypto. Click Send for a live round-trip.");
  for (let i = 0; i < sequence.length; i++) {
    currentIndex = stageOrder.indexOf(stageHits[i]);
    updateStageUI();
    setFlow(sequence[i]);
    await sleep(STAGE_HOLD_MS);
    if (!previewRunning) break;
  }

  previewRunning = false;
  sendBtn.disabled = false;
  previewBtn.disabled = false;
  flowStatusEl.textContent = "Preview finished — send a real message when ready.";
  setHint("Preview finished. Send a secure message to run the live demo.");
}

function connectEvents() {
  const es = new EventSource("/events");

  es.onmessage = (msg) => {
    let event;
    try {
      event = JSON.parse(msg.data);
    } catch (_) {
      return;
    }

    if (event.type === "log") {
      if (!runActive && !event.demo) return;
      enqueueLog(event);
      return;
    }

    if (event.type === "run_start") {
      runActive = true;
      resetPipeline({ clearLog: true });
      runActive = true;
      enqueueLog({
        source: "dashboard",
        line: `Starting secure round-trip for: ${event.message}`,
        stage: "tcp",
        forcePace: true
      });
      setHint("Handshake + relay running… (paced for demo)");
      return;
    }

    if (event.type === "run_complete") {
      if (draining || eventQueue.length) {
        pendingComplete = event;
      } else {
        finishRun(event);
      }
    }
  };
}

function wireInteractions() {
  document.getElementById("chips").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-msg]");
    if (!btn) return;
    messageEl.value = btn.dataset.msg;
    updateCharCount();
    document.querySelectorAll("#chips button").forEach((b) => {
      b.classList.toggle("selected", b === btn);
    });
    messageEl.focus();
  });

  messageEl.addEventListener("input", updateCharCount);
  messageEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendMessage();
  });

  sendBtn.addEventListener("click", sendMessage);
  previewBtn.addEventListener("click", previewPath);

  document.getElementById("pace-speed").addEventListener("change", (e) => {
    const pace = PACE[e.target.value] || PACE.normal;
    LOG_MS = pace.log;
    STAGE_HOLD_MS = pace.stage;
  });

  document.getElementById("autoplay").addEventListener("change", (e) => {
    autoplay = e.target.checked;
  });

  document.getElementById("prev-stage").addEventListener("click", () => {
    if (currentIndex > 0) {
      currentIndex -= 1;
      updateStageUI();
      syncFlowToCurrentStage();
    }
  });

  document.getElementById("next-stage").addEventListener("click", () => {
    const max = Math.max(...[...activated].map((id) => stageOrder.indexOf(id)), -1);
    if (currentIndex < max) {
      currentIndex += 1;
      updateStageUI();
      syncFlowToCurrentStage();
    }
  });

  document.getElementById("clear-log").addEventListener("click", () => {
    logEl.innerHTML = "";
  });

  document.getElementById("inspect-close").addEventListener("click", hideInspect);
  document.getElementById("tip-close").addEventListener("click", hideTip);

  [nodeClient, nodeProxy, nodeBackend, linkPq, linkBackend].forEach((el) => {
    el.addEventListener("click", () => showInspect(el.dataset.role));
  });

  statusBackend.addEventListener("click", () => showInspect("backend"));
  statusProxy.addEventListener("click", () => showInspect("proxy"));

  document.getElementById("badges").addEventListener("click", (e) => {
    const btn = e.target.closest(".badge[data-tip]");
    if (!btn) return;
    showTip(btn.dataset.tip);
  });

  document.getElementById("legend").addEventListener("click", (e) => {
    const btn = e.target.closest(".legend-btn");
    if (!btn) return;
    logFilter = btn.dataset.filter;
    document.querySelectorAll(".legend-btn").forEach((b) => {
      b.setAttribute("aria-pressed", b === btn ? "true" : "false");
    });
    applyLogFilter();
  });

  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input, textarea, select")) return;
    if (e.key === "ArrowLeft") {
      document.getElementById("prev-stage").click();
    } else if (e.key === "ArrowRight") {
      document.getElementById("next-stage").click();
    } else if (e.key === "Escape") {
      hideInspect();
      hideTip();
      previewRunning = false;
    }
  });
}

renderStages();
wireInteractions();
connectEvents();
updateCharCount();
refreshStatus();
setInterval(refreshStatus, 3000);
