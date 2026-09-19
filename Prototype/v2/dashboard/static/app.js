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

function resetStages() {
  STAGES.forEach((s) => {
    const el = document.getElementById(`stage-${s.id}`);
    el.classList.remove("done", "active");
  });
  [nodeClient, nodeProxy, nodeBackend].forEach((n) => n.classList.remove("active"));
}

let activeStageId = null;

function markStage(stageId) {
  if (!stageId) return;

  if (activeStageId) {
    const prev = document.getElementById(`stage-${activeStageId}`);
    if (prev) {
      prev.classList.remove("active");
      prev.classList.add("done");
    }
  }

  const el = document.getElementById(`stage-${stageId}`);
  if (el) {
    el.classList.add("active");
    el.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }
  activeStageId = stageId;

  animateForStage(stageId);
}

function flyPacket(el, direction, kind) {
  el.classList.remove("fly-fwd", "fly-back", "locked", "unlocked");
  void el.offsetWidth; // restart animation
  el.classList.add(kind);
  el.classList.add(direction === "fwd" ? "fly-fwd" : "fly-back");
}

function pulseNode(node) {
  node.classList.add("active");
  setTimeout(() => node.classList.remove("active"), 900);
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

function appendLog(source, line) {
  const div = document.createElement("div");
  div.className = `line src-${source}`;
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
      sendBtn.disabled = !!data.busy;
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
      appendLog(data.source, data.line);
      if (data.stage) {
        markStage(data.stage);
      }
    } else if (data.type === "run_start") {
      resetStages();
      resultEl.hidden = true;
      sendBtn.disabled = true;
    } else if (data.type === "run_complete") {
      sendBtn.disabled = false;
      resultSentEl.textContent = data.message || "";
      resultReplyEl.textContent = data.success
        ? (data.reply || "(empty reply)")
        : `Error: ${data.error || "run failed"}`;
      resultEl.hidden = false;
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

buildStageList();
refreshStatus();
setInterval(refreshStatus, 4000);
connectEvents();
