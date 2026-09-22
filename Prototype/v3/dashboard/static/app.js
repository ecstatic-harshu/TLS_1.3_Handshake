const MAX_LOG_LINES = 120;
const MAX_MESSAGE = 500;
const SESSION_KEY = "nqsp-sessions-v1";
const THEME_KEY = "nqsp-theme";

const STAGE_DEFS = [
  { id: "tcp", rail: "tcp" },
  { id: "tls", rail: "tls" },
  { id: "pq", rail: "pq" },
  { id: "hybrid", rail: "hybrid" },
  { id: "channel", rail: "channel" },
  { id: "send", rail: "send" },
  { id: "proxy_relay", rail: "proxy_relay" },
  { id: "backend", rail: "backend" },
  { id: "response", rail: "response" }
];

const RAIL_ORDER = ["tcp", "tls", "pq", "hybrid", "channel", "send", "proxy_relay", "backend", "response"];

const PACE = { log: 450, stage: 1600 };
const LOG_MS = PACE.log;
const STAGE_HOLD_MS = PACE.stage;
// The arrow glide has to land before the next stage's log lines start
// appearing (STAGE_HOLD_MS apart), so it's derived from that pace rather
// than a made-up number — slow and soft, but never behind the real pipeline.
const ARROW_TRAVEL_MS = Math.round(STAGE_HOLD_MS * 0.85);
// The return journey (server -> proxy, then proxy -> client) is a two-phase
// cosmetic replay — real per-hop timing on the way back isn't observed
// separately, only the full round trip. Each phase needs to stay on screen
// long enough to actually read as a continuous, flowing hop rather than a
// flash: at least one full active-line cycle (see .flow-line's 1.6s duration
// in style.css, itself matched to STAGE_HOLD_MS) plus the arrow's own glide.
const RETURN_PHASE_MS = Math.round(STAGE_HOLD_MS * 1.5);

const stageOrder = STAGE_DEFS.map((s) => s.id);
const activated = new Set();
let currentIndex = -1;
let autoplay = true;
let runActive = false;
let logFilter = "all";

const eventQueue = [];
let draining = false;
let pendingComplete = null;
let runStartedAt = 0;
let sessionTimer = null;
let lastMessage = "Hello, secure world!";
let lastStatus = { backend: "starting", proxy: "starting", busy: false };
let detailsExpanded = false;
let sessionsExpanded = false;

const $ = (id) => document.getElementById(id);

const logEl = $("log");
const messageEl = $("message");
const sendBtn = $("send-btn");
const sendHint = $("send-hint");
const replyEl = $("reply");
const charCount = $("char-count");
const topologyEl = $("topology");
const flowStatusEl = $("flow-status");
const nodeClient = $("node-client");
const nodeProxy = $("node-proxy");
const nodeBackend = $("node-backend");
const pktPlain = $("pkt-plain");

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

function setHint(text) {
  if (sendHint) sendHint.textContent = text;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function formatBytes(n) {
  if (!n && n !== 0) return "—";
  if (n < 1024) return `${n} B`;
  return `${(n / 1024).toFixed(1)} KB`;
}

function formatLatency(ms) {
  if (ms == null || Number.isNaN(ms)) return "—";
  if (ms < 1000) return `${Math.max(1, Math.round(ms))} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

function toMs(ts) {
  if (ts == null || ts === "") return Date.now();
  return ts > 1e12 ? ts : ts * 1000;
}

function clock(ts) {
  return new Date(toMs(ts)).toLocaleTimeString([], {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

function padTime(totalSec) {
  const s = Math.max(0, Math.floor(totalSec));
  const hh = String(Math.floor(s / 3600)).padStart(2, "0");
  const mm = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
  const ss = String(s % 60).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

function shortHash(input) {
  let h = 0;
  const str = String(input || "nqsp");
  for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
  return h.toString(16).toUpperCase().padStart(8, "0");
}

function updateCharCount() {
  const n = (messageEl.value || "").length;
  charCount.textContent = `${n}/${MAX_MESSAGE}`;
}

function currentPayload() {
  return (messageEl.value || "").trim();
}

// Each hop is two cubics matching the stream paths. Client curves run left→right.
// Server curves are drawn right→left, so u=0 is the server end and u=1 is the proxy end.
const FLOW_CURVES = {
  client: [
    [[2, 30], [55, 10], [105, 50], [160, 30], [160, 30], [215, 10], [215, 10], [252, 28]],
    [[2, 55], [60, 36], [115, 76], [165, 55], [165, 55], [215, 34], [220, 34], [252, 52]],
    [[2, 80], [50, 62], [110, 100], [162, 80], [162, 80], [214, 60], [212, 60], [252, 76]]
  ],
  server: [
    [[258, 30], [205, 10], [155, 50], [100, 30], [100, 30], [45, 10], [45, 10], [8, 28]],
    [[258, 55], [200, 36], [145, 76], [95, 55], [95, 55], [45, 34], [40, 34], [8, 52]],
    [[258, 80], [210, 62], [150, 100], [98, 80], [98, 80], [46, 60], [48, 60], [8, 76]]
  ]
};

const flowPaths = {};
const arrowMotions = new Map();
let arrowFrame = 0;

function cubicPoint(p0, c1, c2, p1, t) {
  const u = 1 - t;
  return {
    x: u ** 3 * p0[0] + 3 * u ** 2 * t * c1[0] + 3 * u * t ** 2 * c2[0] + t ** 3 * p1[0],
    y: u ** 3 * p0[1] + 3 * u ** 2 * t * c1[1] + 3 * u * t ** 2 * c2[1] + t ** 3 * p1[1],
    dx: 3 * u ** 2 * (c1[0] - p0[0]) + 6 * u * t * (c2[0] - c1[0]) + 3 * t ** 2 * (p1[0] - c2[0]),
    dy: 3 * u ** 2 * (c1[1] - p0[1]) + 6 * u * t * (c2[1] - c1[1]) + 3 * t ** 2 * (p1[1] - c2[1])
  };
}

function pointOnCubics(pts, t) {
  const u = Math.min(1, Math.max(0, t));
  const local = u < 0.5 ? u * 2 : (u - 0.5) * 2;
  const i = u < 0.5 ? 0 : 4;
  return cubicPoint(pts[i], pts[i + 1], pts[i + 2], pts[i + 3], u >= 1 ? 1 : local);
}

function buildFlowPath(pts) {
  const steps = 72;
  const samples = [];
  let length = 0;
  let prev = null;
  for (let i = 0; i <= steps; i++) {
    const p = pointOnCubics(pts, i / steps);
    if (prev) length += Math.hypot(p.x - prev.x, p.y - prev.y);
    samples.push({ ...p, length });
    prev = p;
  }
  return { samples, length };
}

function sampleFlowPath(path, u) {
  const target = Math.min(1, Math.max(0, u)) * path.length;
  const samples = path.samples;
  let i = 1;
  while (i < samples.length && samples[i].length < target) i += 1;
  const a = samples[i - 1];
  const b = samples[Math.min(i, samples.length - 1)];
  const span = b.length - a.length || 1;
  const f = (target - a.length) / span;
  return {
    x: a.x + (b.x - a.x) * f,
    y: a.y + (b.y - a.y) * f,
    dx: a.dx + (b.dx - a.dx) * f,
    dy: a.dy + (b.dy - a.dy) * f
  };
}

function pathForArrow(el) {
  const hop = el.dataset.hop;
  const index = Number(el.dataset.index);
  const key = `${hop}:${index}`;
  if (!flowPaths[key]) flowPaths[key] = buildFlowPath(FLOW_CURVES[hop][index]);
  return flowPaths[key];
}

function paintFlowArrow(el, u, towardIncreasing) {
  const sample = sampleFlowPath(pathForArrow(el), u);
  const sign = towardIncreasing ? 1 : -1;
  let vx = sample.dx * sign;
  let vy = sample.dy * sign;
  const mag = Math.hypot(vx, vy) || 1;
  vx /= mag;
  vy /= mag;
  const tipX = sample.x + vx * 2;
  const tipY = sample.y + vy * 2;
  const deg = Math.atan2(vy, vx) * 180 / Math.PI + 180;
  const fix = arrowAspectFix(el);
  el.setAttribute(
    "transform",
    `translate(${tipX.toFixed(2)},${tipY.toFixed(2)}) rotate(${deg.toFixed(2)}) scale(${fix.toFixed(4)},1)`
  );
}

function arrowAspectFix(el) {
  const svg = el.ownerSVGElement;
  if (!svg) return 1;
  const rect = svg.getBoundingClientRect();
  const box = svg.viewBox.baseVal;
  if (!rect.width || !rect.height || !box.width || !box.height) return 1;
  const scaleX = rect.width / box.width;
  const scaleY = rect.height / box.height;
  if (!scaleX || !scaleY) return 1;
  return scaleY / scaleX;
}

function repaintFlowArrows() {
  arrowMotions.forEach((motion, el) => {
    paintFlowArrow(el, motion.u, motion.u >= 0.5);
  });
}

function watchStreamScale() {
  if (typeof ResizeObserver === "undefined") {
    window.addEventListener("resize", repaintFlowArrows);
    return;
  }
  const observer = new ResizeObserver(() => repaintFlowArrows());
  document.querySelectorAll(".stream").forEach((svg) => observer.observe(svg));
}

function kickArrowFrame() {
  if (arrowFrame) return;
  arrowFrame = requestAnimationFrame(stepFlowArrows);
}

function stepFlowArrows(now) {
  arrowFrame = 0;
  let pending = false;
  arrowMotions.forEach((motion, el) => {
    if (!motion.dur) {
      paintFlowArrow(el, motion.u, motion.u >= 0.5);
      return;
    }
    const t = Math.min(1, (now - motion.start) / motion.dur);
    // ease-in-out-sine: no abrupt acceleration change, so the arrow's glide
    // between hops reads as a soft drift rather than a mechanical snap.
    const eased = -(Math.cos(Math.PI * t) - 1) / 2;
    motion.u = motion.from + (motion.to - motion.from) * eased;
    paintFlowArrow(el, motion.u, motion.to > motion.from);
    if (t < 1) pending = true;
    else motion.dur = 0;
  });
  if (pending) arrowFrame = requestAnimationFrame(stepFlowArrows);
}

function hopDirections(mode) {
  if (mode === "return_path" || mode === "server_to_proxy") return { server: "back" };
  if (mode === "proxy_to_client") return { client: "back" };
  if (mode === "proxy_to_backend" || mode === "at_backend") return { server: "forward" };
  if (mode === "handshake" || mode === "client_to_proxy") return { client: "forward" };
  return { client: "forward", server: "forward" };
}

function hopPresence(mode) {
  if (mode === "handshake" || mode === "client_to_proxy") return { client: "live", server: "off" };
  if (mode === "proxy_to_backend" || mode === "at_backend") return { client: "held", server: "live" };
  if (mode === "return_path" || mode === "server_to_proxy") return { client: "held", server: "live" };
  if (mode === "proxy_to_client") return { client: "live", server: "held" };
  return { client: "live", server: "live" };
}

let returnPhaseTimer = 0;

function revealHopArrows(mode) {
  const presence = hopPresence(mode);
  ["client", "server"].forEach((hop) => {
    const svg = streamSvg(hop);
    if (!svg) return;
    const state = presence[hop];
    svg.classList.toggle("is-hidden", state === "off");
    svg.classList.toggle("is-held", state === "held");
  });
}

const streamApplied = { client: null, server: null };

function streamSvg(hop) {
  return hop === "server"
    ? document.querySelector(".stream-green")
    : document.querySelector(".stream:not(.stream-green)");
}

function restartSvgAnim(anim) {
  const next = anim.cloneNode(true);
  anim.replaceWith(next);
}

function applyBinaryFlow(hop, dir) {
  if (streamApplied[hop] === dir) return;
  streamApplied[hop] = dir;
  const svg = streamSvg(hop);
  if (!svg) return;
  const along = hop === "client" ? dir === "forward" : dir === "back";
  svg.classList.toggle("flow-reverse", !along);
  svg.querySelectorAll("textPath animate").forEach((anim) => {
    anim.setAttribute("from", along ? "0" : "64");
    anim.setAttribute("to", along ? "64" : "0");
    restartSvgAnim(anim);
  });
  svg.querySelectorAll("animateMotion").forEach((anim) => {
    anim.setAttribute("keyPoints", along ? "0;1" : "1;0");
    anim.setAttribute("keyTimes", "0;1");
    anim.setAttribute("calcMode", "linear");
    restartSvgAnim(anim);
  });
}

function orientFlowArrows(mode, immediate) {
  clearTimeout(returnPhaseTimer);
  const dirs = hopDirections(mode);
  applyBinaryFlow("client", dirs.client || streamApplied.client || "forward");
  applyBinaryFlow("server", dirs.server || streamApplied.server || "forward");
  revealHopArrows(mode);
  document.querySelectorAll(".flow-arrowhead").forEach((el) => {
    const dir = dirs[el.dataset.hop];
    if (!dir) return;
    const hop = el.dataset.hop;
    const target = hop === "server"
      ? (dir === "forward" ? 0 : 1)
      : (dir === "forward" ? 1 : 0);
    const motion = arrowMotions.get(el);
    if (!motion || immediate) {
      arrowMotions.set(el, { u: target, from: target, to: target, start: 0, dur: 0 });
      paintFlowArrow(el, target, target >= 0.5);
      return;
    }
    if (Math.abs(motion.to - target) < 0.001 && Math.abs(motion.u - target) < 0.001) return;
    motion.from = motion.u;
    motion.to = target;
    motion.start = performance.now();
    motion.dur = ARROW_TRAVEL_MS;
    kickArrowFrame();
  });
  if (mode === "return_path") {
    returnPhaseTimer = setTimeout(() => {
      if (!topologyEl || topologyEl.dataset.flow !== "return_path") return;
      // Go through setFlow (not a raw orientFlowArrows call) so the phase
      // change is a real state transition: dataset.flow, the active-node
      // highlight, and the status text all switch together to "proxy -> client"
      // instead of the server -> proxy hop lingering as the reported state.
      setFlow("proxy_to_client");
    }, RETURN_PHASE_MS);
  }
}

function setFlow(mode) {
  if (!topologyEl) return;
  [nodeClient, nodeProxy, nodeBackend].forEach((n) => n && n.classList.remove("active"));
  topologyEl.dataset.flow = mode;
  orientFlowArrows(mode, false);

  if (mode === "idle") {
    flowStatusEl.textContent = "Idle — send a message to watch packets move.";
    const comms = $("comms-flow");
    if (comms) comms.textContent = "Idle — send a message from Live Demo or here.";
    return;
  }

  if (mode === "handshake") {
    nodeClient.classList.add("active");
    nodeProxy.classList.add("active");
    flowStatusEl.textContent = "Client ↔ Proxy: negotiating the post-quantum secure channel…";
  } else if (mode === "client_to_proxy") {
    nodeClient.classList.add("active");
    nodeProxy.classList.add("active");
    flowStatusEl.textContent = "Client → Proxy: sealed AES-GCM payload on the client PQ channel…";
  } else if (mode === "proxy_to_backend") {
    nodeProxy.classList.add("active");
    nodeBackend.classList.add("active");
    flowStatusEl.textContent = "Proxy → PQ Server: second post-quantum session…";
  } else if (mode === "at_backend") {
    nodeBackend.classList.add("active");
    nodeProxy.classList.add("active");
    flowStatusEl.textContent = "PQ Secure Server: handling the message over the PQ session…";
  } else if (mode === "return_path") {
    // Phase 1 of the reply: server -> proxy only. The client hop is held
    // (hidden) until phase 2 actually hands off to it, so only highlight
    // the nodes that are genuinely live right now.
    nodeBackend.classList.add("active");
    nodeProxy.classList.add("active");
    flowStatusEl.textContent = "PQ Server → Proxy: relaying the encrypted reply…";
  } else if (mode === "proxy_to_client") {
    // Phase 2: the server -> proxy hop is now held/hidden and proxy -> client
    // takes over.
    nodeProxy.classList.add("active");
    nodeClient.classList.add("active");
    flowStatusEl.textContent = "Proxy → Client: delivering the reply on your PQ channel…";
  }

  const comms = $("comms-flow");
  if (comms) comms.textContent = flowStatusEl.textContent;
}

function syncFlowToCurrentStage() {
  if (currentIndex < 0) return;
  const flow = FLOW_BY_STAGE[stageOrder[currentIndex]];
  if (flow) setFlow(flow);
}

function railForStage(stageId) {
  const def = STAGE_DEFS.find((s) => s.id === stageId);
  return def ? def.rail : null;
}

function updateStageUI() {
  const items = [...document.querySelectorAll("#step-rail .step")];
  const currentRail = currentIndex >= 0 ? railForStage(stageOrder[currentIndex]) : null;
  const currentRailIdx = RAIL_ORDER.indexOf(currentRail);

  items.forEach((el) => {
    const rail = el.dataset.rail;
    const idx = RAIL_ORDER.indexOf(rail);
    // A step's own log line can occasionally be missed or arrive out of order
    // (e.g. "send" is read from the ephemeral client process while
    // "proxy_relay"/"backend" are tailed from the proxy container's own,
    // separately-buffered stdout — they don't share a strict wire order).
    // The pipeline is strictly sequential though, so once we've reached a
    // later stage every earlier one must already have happened — treat it
    // as unlocked even if its individual marker never showed up, so a step
    // can never get stuck locked/grayed-out behind a later one that lit up.
    const seenDirectly = [...activated].some((sid) => railForStage(sid) === rail);
    const impliedByLaterStage = currentRailIdx >= 0 && idx <= currentRailIdx;
    const unlocked = seenDirectly || impliedByLaterStage;

    el.classList.remove("active", "done", "locked");
    if (!unlocked) el.classList.add("locked");
    if (unlocked && currentRailIdx >= 0 && idx < currentRailIdx) el.classList.add("done");
    if (rail === currentRail) el.classList.add("active");
  });
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
}

function jumpToStage(stageId) {
  if (!activated.has(stageId)) return;
  const idx = stageOrder.indexOf(stageId);
  if (idx < 0) return;
  currentIndex = idx;
  updateStageUI();
  syncFlowToCurrentStage();
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
  $("metric-status").textContent = "…";
  setSessionActive(true);
}

function colorClassFor(source, stage, line) {
  if (line && (line.includes("ERROR") || line.includes("error") || line.includes("Failed"))) {
    return "error";
  }
  if (stage === "pq" || stage === "hybrid") return "pq";
  if (stage === "channel") return "ready";
  if (stage === "tls" || stage === "send" || stage === "response" || stage === "receive") return "encrypted";
  if (stage === "backend" || stage === "proxy_relay") return "pq";
  if (stage === "tcp") return "setup";
  if (source === "client") return "setup";
  if (source === "proxy" || source === "backend") return "pq";
  return "setup";
}

function tagFor(source, stage, line, cls) {
  const text = line || "";
  if (cls === "error") return "ERROR";
  if (/Starting secure|dashboard launched|Starting secure proxy/i.test(text)) return "INFO";
  if (stage === "tcp" || /Connecting to|TCP_/i.test(text)) return "CONN";
  if (stage === "tls" || /TLS/i.test(text)) return "TLS";
  if (stage === "pq" || /ML-KEM|ML-DSA|PQ /i.test(text)) return "PQC";
  if (stage === "hybrid" || /HYBRID|HKDF/i.test(text)) return "ENCRYPT";
  if (stage === "channel" || /Secure Channel|Secure session/i.test(text)) return "SECURE";
  if (stage === "proxy_relay" || /backend|Forward/i.test(text)) return "FORWARD";
  if (stage === "send" || stage === "response" || /message|ACK:|bytes/i.test(text)) return "DATA";
  if (source === "backend") return "FORWARD";
  if (cls === "ready") return "SECURE";
  if (cls === "pq") return "PQC";
  if (cls === "encrypted") return "DATA";
  return "INFO";
}

function explainLog(source, stage, line) {
  const text = line || "";
  const rules = [
    { test: /Starting secure round-trip/i, msg: "Starting secure proxy…" },
    { test: /Connecting to /i, msg: `Incoming connection from client` },
    { test: /TCP_CONNECT\b|TCP connection established|TCP_CONNECTED|TCP client connected/i, msg: "TCP connection established" },
    { test: /TLS_HANDSHAKE|TLS connection established|TLS established|TLS_CONNECTED|TLS_HANDSHAKE_COMPLETE/i, msg: "TLS 1.3 handshake initiated" },
    { test: /TLS Cipher:|TLS_METADATA/i, msg: "TLS cipher suite negotiated" },
    { test: /AUTHENTICATED_PQ_HANDSHAKE/i, msg: "Post-quantum handshake in progress" },
    { test: /PQ KEM:/i, msg: "ML-KEM-768 key exchange in progress" },
    { test: /PQ Signature:/i, msg: "ML-DSA-65 signature verification" },
    { test: /HYBRID_KEY_DERIVATION|HYBRID_KEY_DERIVED/i, msg: "Hybrid key derivation completed" },
    { test: /SECURE_CHANNEL_CREATION|SECURE_CHANNEL_CREATED|Secure Channel:/i, msg: "Secure channel established" },
    { test: /Secure session established|Authentication: SUCCESS/i, msg: "Secure session ready" },
    { test: /Secure message sent|Sent message:/i, msg: `Encrypted message received (${new Blob([lastMessage]).size} bytes)` },
    { test: /Secure message received/i, msg: "Encrypted payload received" },
    { test: /Received reply:/i, msg: "Response received from PQ server" },
    { test: /PQ backend mode|PQ backend session|PQ↔PQ/i, msg: `Forwarding to PQ server (${$("kv-server-ip")?.textContent || "127.0.0.1"})` },
    { test: /ACK:/i, msg: "PQ server ACK" },
    { test: /Connection closed/i, msg: "Client disconnected" },
    { test: /ERROR|Failed|failed/i, msg: "Error during demo run" }
  ];
  for (const rule of rules) {
    if (rule.test.test(text)) return rule.msg;
  }
  return text.replace(/^\[[^\]]+\]\s*/, "") || "System log";
}

function paintLogLine(event) {
  const div = document.createElement("div");
  const cls = colorClassFor(event.source, event.stage, event.line);
  const tag = event.successTag || tagFor(event.source, event.stage, event.line, cls);
  const msg = event.display || explainLog(event.source, event.stage, event.line);
  const ts = clock(event.ts);

  div.className = `log-line ${tag} ${cls} log-enter`;
  if (event.stage) div.dataset.stage = event.stage;
  div.innerHTML = `
    <span class="log-ts">${escapeHtml(ts)}</span>
    <span class="log-tag">[${tag}]</span>
    <span class="log-msg">${escapeHtml(msg)}</span>
  `;
  div.addEventListener("click", () => {
    div.classList.add("flash");
    setTimeout(() => div.classList.remove("flash"), 600);
    if (event.stage) jumpToStage(event.stage);
  });

  logEl.appendChild(div);
  while (logEl.children.length > MAX_LOG_LINES) logEl.removeChild(logEl.firstChild);
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

function loadSessions() {
  try {
    return JSON.parse(localStorage.getItem(SESSION_KEY) || "[]");
  } catch (_) {
    return [];
  }
}

function saveSessions(list) {
  localStorage.setItem(SESSION_KEY, JSON.stringify(list.slice(0, 20)));
}

function renderSessions() {
  const all = loadSessions();
  const limit = sessionsExpanded ? all.length : 4;
  const rows = all.slice(0, Math.max(limit, 0));
  const html = rows.length
    ? rows.map((s) => `
        <tr>
          <td>${escapeHtml(s.time)}</td>
          <td><span class="msg-clip" title="${escapeHtml(s.message)}">${escapeHtml(s.message)}</span></td>
          <td class="${s.ok ? "ok" : "fail"}">${s.ok ? "● Success" : "● Failed"}</td>
          <td>${escapeHtml(s.latency)}</td>
        </tr>
      `).join("")
    : `<tr class="empty-row"><td colspan="4">No sessions yet — send a secure message.</td></tr>`;

  $("sess-body").innerHTML = html;
  const commsBody = $("comms-sess-body");
  if (commsBody) commsBody.innerHTML = html;
  renderPerf(all);
}

function renderPerf(all) {
  const ok = all.filter((s) => s.ok);
  const avg = ok.length ? ok.reduce((a, s) => a + (s.ms || 0), 0) / ok.length : null;
  const last = all[0];
  const bytes = all.reduce((a, s) => a + (s.bytes || 0), 0);
  $("perf-avg").textContent = formatLatency(avg);
  $("perf-last").textContent = last ? last.latency : "—";
  $("perf-success").textContent = all.length ? `${Math.round((ok.length / all.length) * 100)}%` : "—";
  $("perf-bytes").textContent = formatBytes(bytes);

  const maxMs = Math.max(...all.map((s) => s.ms || 1), 1);
  $("perf-bars").innerHTML = all.slice(0, 8).map((s) => `
    <div class="bar-row">
      <span>${escapeHtml(s.time)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.max(8, ((s.ms || 0) / maxMs) * 100)}%"></div></div>
      <span>${escapeHtml(s.latency)}</span>
    </div>
  `).join("") || `<p class="hint">Latency bars appear after demo runs.</p>`;
}

function recordSession({ ok, message, reply, ms }) {
  const bytes = new Blob([message || ""]).size + new Blob([reply || ""]).size;
  const entry = {
    time: clock(),
    message: message || "",
    ok,
    latency: formatLatency(ms),
    ms,
    bytes,
    ts: Date.now()
  };
  const list = [entry, ...loadSessions()].slice(0, 20);
  saveSessions(list);
  renderSessions();

  $("metric-latency").textContent = formatLatency(ms);
  $("metric-bytes").textContent = formatBytes(bytes);
  $("metric-status").textContent = ok ? "Success" : "Failed";
  $("metric-ok-ico").classList.toggle("fail", !ok);
  $("metric-ok-ico").classList.toggle("ok", ok);
}

function setSessionActive(active) {
  const chip = $("kv-status");
  chip.classList.toggle("idle", !active);
  chip.classList.toggle("active", active);
  chip.innerHTML = active ? "<i></i> Active" : "<i></i> Idle";

  if (sessionTimer) {
    clearInterval(sessionTimer);
    sessionTimer = null;
  }
  if (active) {
    const started = Date.now();
    sessionTimer = setInterval(() => {
      $("kv-session").textContent = padTime((Date.now() - started) / 1000);
    }, 250);
  }
}

function updateConnectionDetails(status) {
  const clientPort = 40000 + (Date.now() % 20000);
  const proxyPort = status.proxy_port || 5000;
  const backendPort = status.backend_port || 6000;
  if (!runActive) {
    $("kv-client-ip").textContent = `127.0.0.1:${proxyPort}`;
  }
  $("kv-server-ip").textContent = `127.0.0.1:${backendPort}`;
  $("cfg-proxy").textContent = status.proxy || "—";
  $("cfg-backend").textContent = status.backend || "—";
  $("cfg-proxy-port").textContent = String(proxyPort);
  $("cfg-backend-port").textContent = String(backendPort);
  $("cfg-gateway").textContent = status.gateway || gatewayFrom(status);

  const commsKv = $("comms-kv");
  if (commsKv) {
    commsKv.innerHTML = `
      <div><dt>Client IP</dt><dd>${escapeHtml($("kv-client-ip").textContent)}</dd></div>
      <div><dt>Server IP</dt><dd>${escapeHtml($("kv-server-ip").textContent)}</dd></div>
      <div><dt>Protocol</dt><dd>TCP (TLS 1.3)</dd></div>
      <div><dt>Status</dt><dd>${runActive ? "Active" : "Idle"}</dd></div>
      <div><dt>PQC</dt><dd>ML-KEM-768</dd></div>
      <div><dt>Signature</dt><dd>ML-DSA-65</dd></div>
    `;
  }
  return { clientPort, proxyPort, backendPort };
}

function gatewayFrom(status) {
  if (status.gateway) return status.gateway;
  if (status.proxy === "online" && status.backend === "online") return "online";
  if (status.proxy === "starting" || status.backend === "starting") return "starting";
  return "offline";
}

function setGateway(status) {
  const gw = gatewayFrom(status);
  const pill = $("gateway-pill");
  const label = $("gateway-label");
  pill.classList.remove("offline", "starting");
  if (gw === "online") {
    label.textContent = "Gateway Online";
  } else if (gw === "starting") {
    pill.classList.add("starting");
    label.textContent = "Gateway Starting";
  } else {
    pill.classList.add("offline");
    label.textContent = "Gateway Offline";
  }
}

function finishRun(event) {
  runActive = false;
  sendBtn.disabled = false;
  const commsSend = $("comms-send");
  if (commsSend) commsSend.disabled = false;

  const ms = runStartedAt ? Date.now() - runStartedAt : null;
  replyEl.hidden = false;
  if (event.success) {
    replyEl.classList.remove("error");
    replyEl.textContent = `PQ server reply: ${event.reply}`;
    setHint("Round-trip complete.");
    activateStage("response");
    setFlow("return_path");
    paintLogLine({
      source: "dashboard",
      line: "Round-trip completed",
      display: `Round-trip completed in ${formatLatency(ms)}`,
      successTag: "SUCCESS",
      stage: "response",
      ts: Date.now()
    });
    $("kv-kex").textContent = `0x${shortHash(event.reply || event.message)}…${shortHash(event.message).slice(0, 4)}`;
    setTimeout(() => {
      if (topologyEl.dataset.flow === "return_path") {
        flowStatusEl.textContent = "Round-trip complete — send another message anytime.";
      }
    }, 2200);
  } else {
    replyEl.classList.add("error");
    replyEl.textContent = event.error || "Demo run failed.";
    setHint("Something failed — check the live log.");
    setFlow("idle");
    flowStatusEl.textContent = "Stopped — error during the demo run.";
  }

  recordSession({
    ok: !!event.success,
    message: event.message || lastMessage,
    reply: event.reply || "",
    ms
  });
  setSessionActive(false);
  refreshStatus();
}

async function refreshStatus() {
  try {
    const res = await fetch("/status");
    const data = await res.json();
    lastStatus = data;
    setGateway(data);
    updateConnectionDetails(data);
    const busy = !!data.busy || draining || eventQueue.length > 0 || runActive;
    sendBtn.disabled = busy;
    const commsSend = $("comms-send");
    if (commsSend) commsSend.disabled = busy;
  } catch (_) {
    setGateway({ proxy: "offline", backend: "offline" });
  }
}

async function sendMessage(explicit) {
  const message = (explicit != null ? explicit : currentPayload()).trim().slice(0, MAX_MESSAGE);
  if (!message) return;
  if (runActive || sendBtn.disabled) return;

  lastMessage = message;
  if (messageEl.value !== message) {
    messageEl.value = message;
    updateCharCount();
  }
  if (pktPlain) {
    const label = pktPlain.querySelector("b");
    if (label) label.textContent = message.length > 22 ? `${message.slice(0, 22)}…` : message;
  }

  resetPipeline({ clearLog: true });
  runActive = true;
  runStartedAt = Date.now();
  sendBtn.disabled = true;
  const commsSend = $("comms-send");
  if (commsSend) commsSend.disabled = true;
  setHint("Starting secure client through Docker…");
  $("kv-client-ip").textContent = `127.0.0.1:${40000 + (Date.now() % 20000)}`;
  $("kv-kex").textContent = `0x${shortHash(message + Date.now())}`;

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
    if (commsSend) commsSend.disabled = false;
    setHint("Could not start demo run.");
    replyEl.hidden = false;
    replyEl.classList.add("error");
    replyEl.textContent = String(err.message || err);
    setSessionActive(false);
  }
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
      lastMessage = event.message || lastMessage;
      resetPipeline({ clearLog: true });
      runActive = true;
      runStartedAt = Date.now();
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

function showView(name) {
  document.querySelectorAll(".view").forEach((v) => {
    const on = v.dataset.view === name;
    v.classList.toggle("is-active", on);
    v.hidden = !on;
  });
  document.querySelectorAll(".nav-btn").forEach((b) => {
    b.classList.toggle("is-active", b.dataset.view === name);
  });
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem(THEME_KEY, theme);
}

function toggleTheme() {
  const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  applyTheme(next);
}

function setTab(tab) {
  document.querySelectorAll(".seg-btn").forEach((b) => {
    const on = b.dataset.tab === tab;
    b.classList.toggle("is-active", on);
    b.setAttribute("aria-selected", on ? "true" : "false");
  });
  ["text", "file", "api"].forEach((id) => {
    const pane = $(`tab-${id}`);
    if (!pane) return;
    const on = id === tab;
    pane.classList.toggle("is-active", on);
    pane.hidden = !on;
  });
}

function fillApiSnippet() {
  $("api-snippet").textContent =
    `curl -s http://127.0.0.1:8090/send \\
  -H 'Content-Type: application/json' \\
  -d '{"message":"${currentPayload() || "Hello, secure world!"}"}'`;
}

function wireInteractions() {
  sendBtn.addEventListener("click", () => sendMessage());
  messageEl.addEventListener("input", () => {
    updateCharCount();
    fillApiSnippet();
  });
  messageEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });

  document.querySelector(".seg").addEventListener("click", (e) => {
    const btn = e.target.closest(".seg-btn");
    if (btn) setTab(btn.dataset.tab);
  });

  $("file-input").addEventListener("change", async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    $("file-name").textContent = file.name;
    const text = (await file.text()).slice(0, MAX_MESSAGE);
    messageEl.value = text;
    updateCharCount();
    fillApiSnippet();
    setTab("text");
  });

  $("clear-log").addEventListener("click", () => {
    logEl.innerHTML = "";
  });

  $("qa-check").addEventListener("click", async () => {
    await refreshStatus();
    $("gateway-pill").classList.add("pulse");
    setTimeout(() => $("gateway-pill").classList.remove("pulse"), 1600);
    setHint("Connection status refreshed.");
  });

  $("qa-logs").addEventListener("click", () => {
    showView("demo");
    $("log").scrollIntoView({ behavior: "smooth", block: "center" });
  });

  $("qa-test").addEventListener("click", () => {
    messageEl.value = "Hello, secure world!";
    updateCharCount();
    sendMessage("Hello, secure world!");
  });

  $("qa-security").addEventListener("click", () => {
    showView("demo");
    $("connection-details").scrollIntoView({ behavior: "smooth", block: "center" });
  });

  $("details-all").addEventListener("click", () => {
    detailsExpanded = !detailsExpanded;
    document.querySelectorAll("#conn-kv .extra").forEach((el) => {
      el.hidden = !detailsExpanded;
    });
    $("details-all").textContent = detailsExpanded ? "View Less" : "View All";
  });

  $("sessions-all").addEventListener("click", () => {
    sessionsExpanded = !sessionsExpanded;
    $("sessions-all").textContent = sessionsExpanded ? "View Less" : "View All";
    renderSessions();
  });

  document.querySelectorAll("#step-rail .step").forEach((el) => {
    el.addEventListener("click", () => jumpToStage(el.dataset.stage));
  });

  [nodeClient, nodeProxy, nodeBackend].forEach((el) => {
    if (!el) return;
    el.addEventListener("click", () => {
      [nodeClient, nodeProxy, nodeBackend].forEach((n) => n && n.classList.remove("selected"));
      el.classList.add("selected");
      const role = el.dataset.role;
      if (role === "client") setFlow("handshake");
      if (role === "proxy") setFlow("client_to_proxy");
      if (role === "backend") setFlow("at_backend");
    });
  });

  document.querySelector(".main-nav").addEventListener("click", (e) => {
    const btn = e.target.closest(".nav-btn");
    if (btn) showView(btn.dataset.view);
  });

  $("theme-toggle").addEventListener("click", toggleTheme);
  $("cfg-theme").addEventListener("click", toggleTheme);
  $("gear-btn").addEventListener("click", () => showView("config"));

  $("comms-send").addEventListener("click", () => {
    const val = $("comms-message").value.trim();
    showView("demo");
    if (val) sendMessage(val);
    else sendMessage();
  });
  $("comms-message").addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("comms-send").click();
  });

  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input, textarea, select")) return;
    if (e.key === "Escape") {
      [nodeClient, nodeProxy, nodeBackend].forEach((n) => n && n.classList.remove("selected"));
      if (!runActive) setFlow("idle");
    }
  });
}

orientFlowArrows("idle", true);
watchStreamScale();
applyTheme(localStorage.getItem(THEME_KEY) || "dark");
fillApiSnippet();
updateCharCount();
updateStageUI();
renderSessions();
wireInteractions();
connectEvents();
refreshStatus();
setInterval(refreshStatus, 3000);
