# Demo Guide (Investors / Non-Technical)

## One-sentence pitch

> We add a quantum-safe security gate in front of existing systems — without rewriting those systems.

## What you are showing

A live prototype where:

1. A user connects through our middleware
2. The connection is protected with quantum-resistant cryptography
3. Messages still reach a normal server / echo service
4. (Optional) Even the internal hop can be quantum-safe

You are **not** showing production software. You are showing that the idea works.

---

## Recommended live demo (Double PQ)

### Setup (before the meeting)

Open three terminals in the project folder.

**Terminal 1 — “Secure server”**
```powershell
python -m middleware.main --mode server --host 0.0.0.0 --port 6000
```

**Terminal 2 — “Our middleware / proxy”**
```powershell
python -m middleware.main --mode proxy --host 0.0.0.0 --port 5000 --backend-host 127.0.0.1 --backend-port 6000 --backend-pq --no-backend-http
```

**Terminal 3 — “User app”**
```powershell
python -m middleware.main --mode client --host 127.0.0.1 --port 5000
```

Wait until Terminal 3 shows: `Secure Session Established`.

### Demo script (about 90 seconds)

1. **Point at Terminal 3**  
   “This is the user side.”

2. **Point at Terminal 2**  
   “This is our quantum-safe middleware in the middle.”

3. **Point at Terminal 1**  
   “This is the server side — also protected in this demo.”

4. **Type in the client:** `Hi`  
   Press Enter.

5. **Show the reply:** `ACK: Hi`  
   “The message went through both secure hops and came back.”

### What to say

> “Attackers may record encrypted traffic today and try to break it later with quantum computers. We protect that front-door conversation with post-quantum cryptography. Existing systems can stay behind our gateway.”

### What not to say

- “This is production-ready”
- “Nothing can ever be hacked”
- Deep algorithm names unless asked (then: “NIST-standard post-quantum crypto”)

---

## Alternative demo: Proxy in front of a normal API

**Terminal 1**
```powershell
python backend_http_demo.py
```

**Terminal 2**
```powershell
python -m middleware.main --mode proxy --host 0.0.0.0 --port 5000 --backend-host 127.0.0.1 --backend-port 8080 --backend-http
```

**Terminal 3**
```powershell
python -m middleware.main --mode client --host 127.0.0.1 --port 5000
```

Type `Hi` → client shows `echo: Hi`.

**Talking point:**  
“The backend is a normal HTTP service. It did not need quantum crypto built in.”

---

## Simple picture (draw or slide)

```text
User  →  Our Quantum-Safe Middleware  →  Existing Server
```

---

## FAQ (plain language)

**Q: Is this a finished product?**  
A: No. It is a working prototype that proves the approach.

**Q: Do we replace the customer’s servers?**  
A: No. We sit in front of them.

**Q: What is “quantum-safe” here?**  
A: We use modern NIST post-quantum algorithms so recorded traffic is much harder to decrypt later with quantum computers.

**Q: Can the link behind the proxy also be protected?**  
A: Yes — this demo can protect both hops.

---

## Success checklist

- [ ] Client shows `Authenticated : True`
- [ ] Message send shows `Secure message sent`
- [ ] Reply appears (`ACK: …` or `echo: …`)
- [ ] You stated it is a prototype
- [ ] You stated next step is pilot hardening

## Closing line

> “The prototype works end-to-end. Next we harden identity, testing, and operations for a customer pilot.”
