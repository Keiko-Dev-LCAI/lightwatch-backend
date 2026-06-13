"""
LightWatch Backend — Railway Flask App
Provides:
  POST /api/analyze        — AIVM anomaly analysis on monitor data
  POST /api/report         — AIVM-generated report narrative
  GET  /api/qb/auth        — Start QuickBooks OAuth flow
  GET  /api/qb/callback    — QuickBooks OAuth callback (store tokens)
  GET  /api/qb/data        — Pull live QB data for connected company
  GET  /api/qb/status      — Check if QuickBooks is connected
  GET  /health             — Health check

Env vars required (set in Railway):
  LIGHTCHAIN_PRIVATE_KEY   — dApp wallet private key (for AIVM)
  QUICKBOOKS_CLIENT_ID     — from developer.intuit.com
  QUICKBOOKS_CLIENT_SECRET — from developer.intuit.com
  QUICKBOOKS_REDIRECT_URI  — https://<your-railway-url>/api/qb/callback
  SESSION_SECRET           — any random string (for Flask session)
"""

import os, json, time, threading, secrets as _secrets_mod
import base64 as _b64_mod
from flask import Flask, request, jsonify, session, redirect
from flask_cors import CORS
import requests as req

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", _secrets_mod.token_hex(32))
CORS(app)

# ── AIVM CONFIG ──────────────────────────────────────────────────────────────
AIVM_PRIVATE_KEY = os.environ.get("LIGHTCHAIN_PRIVATE_KEY", "").strip()
AIVM_GATEWAY     = "https://chat-api.mainnet.lightchain.ai"
AIVM_RELAY       = "wss://relay.mainnet.lightchain.ai/ws"
AIVM_JOB_REG     = "0xfB15F90298e4CcD7106E76fFB5e520315cC42B0b"
AIVM_JOB_FEE     = 20_000_000_000_000_000   # 0.02 LCAI in wei
AIVM_CHAIN_ID    = 9200

AIVM_ABI = [
    {"name":"createSession","type":"function","stateMutability":"payable",
     "inputs":[{"name":"paramsHash","type":"bytes32"},{"name":"worker","type":"address"},
               {"name":"encWorkerKey","type":"bytes"},{"name":"encDisputerKey","type":"bytes"},
               {"name":"workerSig","type":"bytes"},{"name":"expiry","type":"uint256"}],
     "outputs":[{"name":"sessionId","type":"uint256"}]},
    {"name":"submitJob","type":"function","stateMutability":"payable",
     "inputs":[{"name":"sessionId","type":"uint256"},{"name":"promptHash","type":"bytes32"}],
     "outputs":[]},
    {"name":"SessionCreated","type":"event",
     "inputs":[{"name":"sessionId","type":"uint256","indexed":True},
               {"name":"modelId","type":"bytes32","indexed":False},
               {"name":"worker","type":"address","indexed":True}]},
]

# ── QUICKBOOKS CONFIG ────────────────────────────────────────────────────────
QB_CLIENT_ID     = os.environ.get("QUICKBOOKS_CLIENT_ID", "")
QB_CLIENT_SECRET = os.environ.get("QUICKBOOKS_CLIENT_SECRET", "")
QB_REDIRECT_URI  = os.environ.get("QUICKBOOKS_REDIRECT_URI", "")
QB_SCOPE         = "com.intuit.quickbooks.accounting"
QB_AUTH_URL      = "https://appcenter.intuit.com/connect/oauth2"
QB_TOKEN_URL     = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
QB_API_BASE      = "https://quickbooks.api.intuit.com/v3/company"

# In-memory token store (Railway volume would persist across restarts)
_QB_TOKENS = {}   # { realm_id: {access_token, refresh_token, expires_at} }
_QB_LOCK   = threading.Lock()

# ── AIVM HELPERS ─────────────────────────────────────────────────────────────

def _aivm_decode_pubkey(s):
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    import base64 as b64
    raw = b64.b64decode(s) if not s.startswith("0x") else bytes.fromhex(s[2:])
    if len(raw) == 65 and raw[0] == 0x04:
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePublicNumbers, SECP256R1)
        from cryptography.hazmat.backends import default_backend
        x = int.from_bytes(raw[1:33], "big")
        y = int.from_bytes(raw[33:65], "big")
        return EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key(default_backend())
    return load_der_public_key(raw)

def _aivm_ecdh_wrap(session_key: bytes, peer_pub) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        generate_private_key, ECDH, SECP256R1)
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    ephem_priv = generate_private_key(SECP256R1(), default_backend())
    shared = ephem_priv.exchange(ECDH(), peer_pub)
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.hashes import SHA256
    wrap_key = HKDF(SHA256(), 32, None, b"AIVM-wrap", default_backend()).derive(shared)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    iv = _secrets_mod.token_bytes(12)
    ct = AESGCM(wrap_key).encrypt(iv, session_key, None)
    ephem_pub = ephem_priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return ephem_pub + iv + ct

def _aivm_aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    iv = _secrets_mod.token_bytes(12)
    return iv + AESGCM(key).encrypt(iv, plaintext, None)

def _aivm_aes_decrypt(key: bytes, blob: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)

class AIVMClient:
    """Server-side Lightchain AIVM inference. No user wallet required."""

    def __init__(self, private_key: str):
        from web3 import Web3
        from eth_account import Account
        self._w3       = Web3(Web3.HTTPProvider("https://rpc.mainnet.lightchain.ai"))
        self._account  = Account.from_key(private_key)
        self._registry = self._w3.eth.contract(
            address=Web3.to_checksum_address(AIVM_JOB_REG), abi=AIVM_ABI)
        self._jwt      = None
        self._jwt_exp  = 0
        self._sess_req = req.Session()

    def _auth_headers(self):
        if not self._jwt or time.time() > self._jwt_exp - 60:
            self._refresh_jwt()
        return {"Authorization": f"Bearer {self._jwt}", "Content-Type": "application/json"}

    def _refresh_jwt(self):
        from eth_account.messages import encode_defunct
        r1 = self._sess_req.get(f"{AIVM_GATEWAY}/api/auth/challenge",
                                params={"address": self._account.address}, timeout=15)
        r1.raise_for_status()
        message = r1.json()["message"]
        sig = self._account.sign_message(encode_defunct(text=message))
        r2 = self._sess_req.post(f"{AIVM_GATEWAY}/api/auth/verify",
                                 json={"message": message, "signature": "0x" + sig.signature.hex()},
                                 timeout=15)
        r2.raise_for_status()
        data = r2.json()
        self._jwt = data["token"]
        # expiresAt may be an ISO string, Unix seconds, or Unix ms — handle all
        exp_raw = data.get("expiresAt", 0)
        if isinstance(exp_raw, str):
            try:
                from datetime import datetime
                self._jwt_exp = datetime.fromisoformat(exp_raw.replace("Z", "+00:00")).timestamp()
            except Exception:
                self._jwt_exp = time.time() + 3600
        elif isinstance(exp_raw, (int, float)) and exp_raw > 1e12:
            self._jwt_exp = float(exp_raw) / 1000   # milliseconds → seconds
        elif isinstance(exp_raw, (int, float)) and exp_raw > 1e9:
            self._jwt_exp = float(exp_raw)           # already Unix seconds
        else:
            self._jwt_exp = time.time() + 3600
        print(f"  [AIVM] JWT refreshed")

    def run_inference(self, prompt: str, timeout_secs: int = 300) -> str:
        import websocket as _ws
        from web3 import Web3
        from urllib.parse import quote as _url_quote

        print(f"  [AIVM] inference ({len(prompt)} chars)")
        r = self._sess_req.get(f"{AIVM_GATEWAY}/api/models", timeout=15)
        r.raise_for_status()
        models   = r.json().get("models", [])
        model    = next((m for m in models if m["name"] == "llama3-8b"), models[0] if models else None)
        if not model:
            raise RuntimeError("No AIVM models available")
        model_id = model["id"]

        r = self._sess_req.post(f"{AIVM_GATEWAY}/api/sessions/select",
                                json={"modelId": model_id},
                                headers=self._auth_headers(), timeout=15)
        r.raise_for_status()
        sel = r.json()

        session_key  = _secrets_mod.token_bytes(32)
        enc_worker   = _aivm_ecdh_wrap(session_key, _aivm_decode_pubkey(sel["workerEncryptionKey"]))
        enc_disputer = _aivm_ecdh_wrap(session_key, _aivm_decode_pubkey(sel["disputerEncryptionKey"]))

        r = self._sess_req.post(f"{AIVM_GATEWAY}/api/sessions/prepare",
                                json={"modelId": model_id,
                                      "encWorkerKey":   _b64_mod.b64encode(enc_worker).decode(),
                                      "encDisputerKey": _b64_mod.b64encode(enc_disputer).decode()},
                                headers=self._auth_headers(), timeout=15)
        r.raise_for_status()
        prep = r.json()

        params_hash = bytes.fromhex(model_id[2:].zfill(64) if model_id[:2].lower() == "0x" else model_id.zfill(64))
        sig_bytes   = bytes.fromhex(prep["signature"][2:] if prep["signature"][:2].lower() == "0x" else prep["signature"])
        gas_price   = self._w3.eth.gas_price
        nonce_val   = self._w3.eth.get_transaction_count(self._account.address)

        tx = self._registry.functions.createSession(
            params_hash, Web3.to_checksum_address(prep["worker"]),
            enc_worker, enc_disputer, sig_bytes, prep["expiry"],
        ).build_transaction({"from": self._account.address, "nonce": nonce_val,
                              "gas": 1_000_000, "gasPrice": gas_price,
                              "value": 0, "chainId": AIVM_CHAIN_ID})
        signed  = self._account.sign_transaction(tx)
        tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt1 = self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=90)
        if receipt1.status != 1:
            raise RuntimeError("createSession reverted")

        session_id = None
        for log in receipt1.logs:
            try:
                evt = self._registry.events.SessionCreated().process_log(log)
                session_id = evt["args"]["sessionId"]
                break
            except Exception:
                pass
        if session_id is None:
            raise RuntimeError("SessionCreated event not found")

        relay_token = None
        deadline = time.time() + 60
        while time.time() < deadline:
            r = self._sess_req.get(f"{AIVM_GATEWAY}/api/sessions/{session_id}/token",
                                   headers=self._auth_headers(), timeout=10)
            if r.status_code == 200 and r.json().get("token"):
                relay_token = r.json()["token"]
                break
            time.sleep(1)
        if not relay_token:
            raise RuntimeError("Relay token not ready")

        chunks   = []
        ws_ready = threading.Event()
        ws_err   = [None]

        def _on_message(ws_obj, msg):
            try:
                frame   = json.loads(msg)
                payload = frame.get("payload")
                if payload:
                    blob = _b64_mod.b64decode(payload)
                    pt   = _aivm_aes_decrypt(session_key, blob)
                    chunks.append(pt.decode("utf-8", errors="replace"))
            except Exception:
                pass

        def _on_open(ws_obj): ws_ready.set()
        def _on_error(ws_obj, err): ws_err[0] = err; ws_ready.set()

        import websocket as _ws_mod
        ws = _ws_mod.WebSocketApp(f"{AIVM_RELAY}?token={_url_quote(relay_token)}",
                                   on_message=_on_message, on_open=_on_open, on_error=_on_error)
        ws_thread = threading.Thread(target=ws.run_forever, daemon=True)
        ws_thread.start()
        ws_ready.wait(timeout=15)
        if ws_err[0]:
            raise RuntimeError(f"WebSocket failed: {ws_err[0]}")

        cipher = _aivm_aes_encrypt(session_key, prompt.encode("utf-8"))
        r = self._sess_req.post(f"{AIVM_GATEWAY}/api/blobs",
                                json={"data": _b64_mod.b64encode(cipher).decode()},
                                headers=self._auth_headers(), timeout=15)
        r.raise_for_status()
        blob_hashes = r.json().get("blobHashes", [])
        if not blob_hashes:
            raise RuntimeError("No blob hash")
        _bh         = blob_hashes[0]
        prompt_hash = bytes.fromhex(_bh[2:].zfill(64) if _bh[:2].lower() == "0x" else _bh.zfill(64))

        nonce_val2 = self._w3.eth.get_transaction_count(self._account.address)
        tx2 = self._registry.functions.submitJob(session_id, prompt_hash).build_transaction(
            {"from": self._account.address, "nonce": nonce_val2, "gas": 500_000,
             "gasPrice": gas_price, "value": AIVM_JOB_FEE, "chainId": AIVM_CHAIN_ID})
        signed2  = self._account.sign_transaction(tx2)
        tx_hash2 = self._w3.eth.send_raw_transaction(signed2.raw_transaction)
        receipt2 = self._w3.eth.wait_for_transaction_receipt(tx_hash2, timeout=90)
        if receipt2.status != 1:
            raise RuntimeError("submitJob reverted — check LCAI balance")

        job_completed_topic = "0x" + self._w3.keccak(
            text="JobCompleted(uint256,address,bytes32,bytes32)").hex()
        done     = False
        deadline = time.time() + timeout_secs
        while time.time() < deadline and not done:
            time.sleep(5)
            if chunks:
                done = True
                break
            try:
                logs = self._w3.eth.get_logs(
                    {"address": Web3.to_checksum_address(AIVM_JOB_REG),
                     "fromBlock": receipt2.blockNumber,
                     "toBlock": self._w3.eth.block_number,
                     "topics": [job_completed_topic]})
                if logs:
                    done = True
            except Exception as e:
                print(f"  [AIVM] log poll: {e}")

        time.sleep(3)
        ws.close()
        result = "".join(chunks).strip()
        if not result and not done:
            raise RuntimeError(f"Timeout after {timeout_secs}s")
        return result or "No response from AIVM worker"

# Singleton AIVM client (lazy init)
_aivm_client = None
_aivm_lock   = threading.Lock()

def get_aivm():
    global _aivm_client
    if _aivm_client is None:
        with _aivm_lock:
            if _aivm_client is None:
                if not AIVM_PRIVATE_KEY:
                    raise RuntimeError("LIGHTCHAIN_PRIVATE_KEY env var not set")
                _aivm_client = AIVMClient(AIVM_PRIVATE_KEY)
    return _aivm_client

# ── QB HELPERS ───────────────────────────────────────────────────────────────

def _qb_get_token(realm_id: str) -> dict | None:
    with _QB_LOCK:
        tok = _QB_TOKENS.get(realm_id)
    if not tok:
        return None
    # Refresh if expiring soon
    if time.time() > tok["expires_at"] - 120:
        tok = _qb_refresh_token(realm_id, tok["refresh_token"])
    return tok

def _qb_refresh_token(realm_id: str, refresh_token: str) -> dict:
    import base64 as b64
    creds = b64.b64encode(f"{QB_CLIENT_ID}:{QB_CLIENT_SECRET}".encode()).decode()
    r = req.post(QB_TOKEN_URL,
                 headers={"Authorization": f"Basic {creds}",
                          "Content-Type": "application/x-www-form-urlencoded",
                          "Accept": "application/json"},
                 data={"grant_type": "refresh_token", "refresh_token": refresh_token},
                 timeout=15)
    r.raise_for_status()
    data = r.json()
    tok  = {"access_token":  data["access_token"],
            "refresh_token": data.get("refresh_token", refresh_token),
            "expires_at":    time.time() + data.get("expires_in", 3600)}
    with _QB_LOCK:
        _QB_TOKENS[realm_id] = tok
    return tok

def _qb_api(realm_id: str, endpoint: str, params: dict = None) -> dict:
    tok = _qb_get_token(realm_id)
    if not tok:
        raise RuntimeError("QuickBooks not connected")
    url = f"{QB_API_BASE}/{realm_id}/{endpoint}"
    r   = req.get(url, headers={"Authorization": f"Bearer {tok['access_token']}",
                                 "Accept": "application/json"},
                  params=params or {}, timeout=15)
    r.raise_for_status()
    return r.json()

def _qb_report(realm_id: str, report_name: str, params: dict = None) -> dict:
    return _qb_api(realm_id, f"reports/{report_name}", params)

# ── API ROUTES ───────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "aivm_key": bool(AIVM_PRIVATE_KEY),
                    "qb_configured": bool(QB_CLIENT_ID and QB_CLIENT_SECRET)})

# ── AIVM: Analyze monitor data ───────────────────────────────────────────────
@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Body: {
      company: str,
      industry: str,
      monitors: [{name, value, unit, status, threshold}],
      alerts: [{title, severity, triggered_value, threshold}],
      rules: [str]
    }
    Returns: { analysis: str }
    """
    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "No data"}), 400

    company  = data.get("company", "Unknown Company")
    industry = data.get("industry", "General")
    monitors = data.get("monitors", [])
    alerts   = data.get("alerts", [])
    rules    = data.get("rules", [])

    monitor_lines = "\n".join(
        f"  - {m['name']}: {m['value']} {m.get('unit','')} | Status: {m['status']} | Threshold: {m.get('threshold','N/A')}"
        for m in monitors)
    alert_lines = "\n".join(
        f"  - [{a['severity'].upper()}] {a['title']}: triggered at {a.get('triggered_value','?')} (limit: {a.get('threshold','?')})"
        for a in alerts) or "  None"
    rule_lines = "\n".join(f"  - {r}" for r in rules) or "  None defined"

    prompt = f"""You are LightWatch AI, an enterprise compliance and operations monitor for {company} ({industry}).

Current live monitor readings:
{monitor_lines}

Active alerts:
{alert_lines}

Owner-defined rules:
{rule_lines}

Provide a concise AI analysis (3-4 paragraphs) covering:
1. What the data pattern means for operations right now
2. Which alerts need immediate attention and why
3. Whether any rule violations are present
4. One specific recommended action the operator should take in the next hour

Write in plain English suitable for a business owner, not a technician. Be specific about the numbers."""

    try:
        aivm   = get_aivm()
        result = aivm.run_inference(prompt, timeout_secs=240)
        return jsonify({"analysis": result, "source": "AIVM"})
    except Exception as e:
        print(f"[analyze] AIVM error: {e}")
        # Fallback: rule-based summary
        critical = [a for a in alerts if a.get("severity") == "critical"]
        warnings = [a for a in alerts if a.get("severity") == "warning"]
        summary  = f"AI analysis for {company}: "
        if critical:
            summary += f"{len(critical)} critical alert(s) require immediate attention: {', '.join(a['title'] for a in critical[:2])}. "
        if warnings:
            summary += f"{len(warnings)} warning(s) are active. "
        if not alerts:
            summary += "All monitors within normal parameters. "
        summary += "Recommend reviewing threshold settings and acknowledging active alerts."
        return jsonify({"analysis": summary, "source": "fallback", "error": str(e)})


# ── AIVM: Generate report narrative ─────────────────────────────────────────
@app.route("/api/report", methods=["POST"])
def generate_report():
    """
    Body: {
      company: str,
      industry: str,
      report_type: 'bank'|'regulator'|'auditor'|'exec'|'govt'|'investor',
      data: { monitors, alerts, rules, stats }
    }
    Returns: { report: str }
    """
    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "No data"}), 400

    # Accept either {company, industry, data:{...}} or {entity:{name, industry, ...}, report_type}
    entity      = data.get("entity", {})
    company     = data.get("company", entity.get("name", "Unknown"))
    industry    = data.get("industry", entity.get("industry", "General"))
    report_type = data.get("report_type", "exec")
    company_data = data.get("data", entity)   # fall back to entity block

    audience_map = {
        "bank":      "a bank loan officer reviewing creditworthiness and operational stability",
        "regulator": "a government regulator verifying compliance with industry standards",
        "auditor":   "an external auditor conducting an operational audit",
        "exec":      "a C-suite executive who needs a high-level operational summary",
        "govt":      "a government contracting officer evaluating suitability for a contract",
        "investor":  "a potential investor evaluating the business for funding",
    }
    audience = audience_map.get(report_type, audience_map["exec"])

    monitors = company_data.get("monitors", [])
    alerts   = company_data.get("alerts", [])
    stats    = company_data.get("stats", {})

    data_summary = f"""Company: {company} | Industry: {industry}
Overall status: {stats.get('overall', 'Unknown')}
Active monitors: {len(monitors)}
Active alerts: {len(alerts)}
Uptime: {stats.get('uptime', 'N/A')}
Compliance score: {stats.get('compliance', 'N/A')}

Alert summary: {', '.join(f"{a.get('severity','?').upper()}: {a['title']}" for a in alerts) or 'No active alerts'}"""

    prompt = f"""You are LightWatch AI generating a formal business report for {company}.

Report audience: {audience}

Operational data:
{data_summary}

Write a professional {report_type} report (3-4 paragraphs) appropriate for {audience}.
- Use formal language appropriate to the audience
- Include specific data points
- Note the blockchain-verified audit trail where relevant
- For regulators/auditors: emphasize compliance and immutable record-keeping
- For banks/investors: emphasize operational stability and risk management
- For executives: focus on business impact and action items
- For government contracts: emphasize reliability, compliance standards met, and audit trail
Keep it concise and factual. Today's date: {time.strftime('%B %d, %Y')}."""

    try:
        aivm   = get_aivm()
        result = aivm.run_inference(prompt, timeout_secs=240)
        return jsonify({"report": result, "source": "AIVM"})
    except Exception as e:
        print(f"[report] AIVM error: {e}")
        return jsonify({"report": f"Report generation unavailable. Please review the dashboard data directly. Error: {str(e)}",
                        "source": "error", "fallback": True})


# ── QUICKBOOKS OAuth ─────────────────────────────────────────────────────────
@app.route("/api/qb/auth")
def qb_auth():
    if not QB_CLIENT_ID:
        return jsonify({"error": "QuickBooks not configured — set QUICKBOOKS_CLIENT_ID and QUICKBOOKS_CLIENT_SECRET"}), 503

    state    = _secrets_mod.token_urlsafe(16)
    session["qb_state"] = state
    auth_url = (f"{QB_AUTH_URL}?client_id={QB_CLIENT_ID}"
                f"&response_type=code&scope={QB_SCOPE}"
                f"&redirect_uri={QB_REDIRECT_URI}&state={state}")
    return redirect(auth_url)


@app.route("/api/qb/callback")
def qb_callback():
    import base64 as b64
    error = request.args.get("error")
    if error:
        return jsonify({"error": f"QB OAuth error: {error}"}), 400

    state = request.args.get("state")
    if state != session.get("qb_state"):
        return jsonify({"error": "State mismatch — possible CSRF"}), 400

    code     = request.args.get("code")
    realm_id = request.args.get("realmId")

    creds = b64.b64encode(f"{QB_CLIENT_ID}:{QB_CLIENT_SECRET}".encode()).decode()
    r = req.post(QB_TOKEN_URL,
                 headers={"Authorization": f"Basic {creds}",
                          "Content-Type": "application/x-www-form-urlencoded",
                          "Accept": "application/json"},
                 data={"grant_type": "authorization_code", "code": code,
                       "redirect_uri": QB_REDIRECT_URI},
                 timeout=15)
    r.raise_for_status()
    tok_data = r.json()

    with _QB_LOCK:
        _QB_TOKENS[realm_id] = {
            "access_token":  tok_data["access_token"],
            "refresh_token": tok_data["refresh_token"],
            "expires_at":    time.time() + tok_data.get("expires_in", 3600),
        }

    session["qb_realm_id"] = realm_id
    print(f"[QB] Connected: realm_id={realm_id}")
    # Redirect back to the frontend with success
    frontend_url = os.environ.get("FRONTEND_URL", "https://keiko-dev-lcai.github.io/lightwatch/")
    return redirect(f"{frontend_url}?qb_connected=1&realm={realm_id}")


@app.route("/api/qb/status")
def qb_status():
    realm_id = request.args.get("realm") or session.get("qb_realm_id")
    if not realm_id or realm_id not in _QB_TOKENS:
        return jsonify({"connected": False})
    return jsonify({"connected": True, "realm_id": realm_id})


@app.route("/api/qb/data")
def qb_data():
    """
    Pull live QuickBooks data and return it in LightWatch monitor format.
    Query param: realm=<realmId>
    Returns: { company_name, monitors, stats, raw }
    """
    realm_id = request.args.get("realm") or session.get("qb_realm_id")
    if not realm_id:
        return jsonify({"error": "Not connected to QuickBooks"}), 401

    try:
        # Company info
        company_info = _qb_api(realm_id, "companyinfo/" + realm_id)
        co = company_info.get("CompanyInfo", {})
        company_name = co.get("CompanyName", "Your Company")

        # P&L for current month
        now   = time.strftime("%Y-%m-%d")
        start = time.strftime("%Y-%m-01")
        pnl   = _qb_report(realm_id, "ProfitAndLoss", {"start_date": start, "end_date": now})

        # Balance Sheet
        bs = _qb_report(realm_id, "BalanceSheet", {"start_date": start, "end_date": now})

        # Cash Flow
        cf = _qb_report(realm_id, "CashFlow", {"start_date": start, "end_date": now})

        # Parse P&L into monitor-friendly values
        def _find_row(report, label_contains):
            for row in report.get("Rows", {}).get("Row", []):
                if isinstance(row, dict):
                    header = row.get("Header", {})
                    col_data = header.get("ColData", [])
                    for cd in col_data:
                        if label_contains.lower() in str(cd.get("value", "")).lower():
                            # Find the value column
                            summary = row.get("Summary", {}).get("ColData", [])
                            for i, s in enumerate(summary):
                                if i > 0 and s.get("value"):
                                    try:
                                        return float(str(s["value"]).replace(",", ""))
                                    except:
                                        pass
            return None

        revenue  = _find_row(pnl, "Total Income")  or _find_row(pnl, "Total Revenue") or 0
        expenses = _find_row(pnl, "Total Expense") or _find_row(pnl, "Total Cost")    or 0
        net_income = revenue - expenses if (revenue and expenses) else (_find_row(pnl, "Net Income") or 0)

        total_assets   = _find_row(bs,  "Total Assets")      or 0
        total_liab     = _find_row(bs,  "Total Liabilities") or 0
        cash_from_ops  = _find_row(cf,  "Net Cash")          or 0

        # Build LightWatch monitor format
        monitors = [
            {"name": "Monthly Revenue",      "value": f"${revenue:,.0f}",    "unit": "USD", "status": "green" if revenue > 0 else "yellow", "threshold": "Positive"},
            {"name": "Monthly Expenses",     "value": f"${expenses:,.0f}",   "unit": "USD", "status": "yellow" if expenses > revenue * 0.9 else "green", "threshold": f"< ${revenue:,.0f} revenue"},
            {"name": "Net Income",           "value": f"${net_income:,.0f}", "unit": "USD", "status": "green" if net_income > 0 else "red",  "threshold": "Positive"},
            {"name": "Total Assets",         "value": f"${total_assets:,.0f}","unit": "USD","status": "green", "threshold": "N/A"},
            {"name": "Total Liabilities",    "value": f"${total_liab:,.0f}", "unit": "USD", "status": "green" if total_liab < total_assets * 0.6 else "yellow", "threshold": "< 60% of assets"},
            {"name": "Cash from Operations", "value": f"${cash_from_ops:,.0f}", "unit": "USD", "status": "green" if cash_from_ops > 0 else "red", "threshold": "Positive"},
        ]

        alerts = []
        if net_income < 0:
            alerts.append({"title": "Net Loss This Month", "severity": "critical",
                           "triggered_value": f"${net_income:,.0f}", "threshold": "$0"})
        if total_liab > total_assets * 0.6:
            ratio = total_liab / total_assets if total_assets else 0
            alerts.append({"title": "High Debt-to-Asset Ratio", "severity": "warning",
                           "triggered_value": f"{ratio:.0%}", "threshold": "60%"})
        if expenses > revenue * 0.95 and revenue > 0:
            alerts.append({"title": "Expense Ratio Near Revenue", "severity": "warning",
                           "triggered_value": f"{expenses/revenue:.0%} of revenue", "threshold": "95%"})

        # Stats summary
        profit_margin = (net_income / revenue * 100) if revenue > 0 else 0
        stats = {
            "overall":    "red" if any(a["severity"] == "critical" for a in alerts) else ("yellow" if alerts else "green"),
            "uptime":     "N/A",
            "compliance": f"{max(0, min(100, 95 - len(alerts)*10))}%",
            "active_monitors": len(monitors),
            "active_alerts":   len(alerts),
            "profit_margin":   f"{profit_margin:.1f}%",
        }

        return jsonify({
            "company_name": company_name,
            "monitors":     monitors,
            "alerts":       alerts,
            "stats":        stats,
            "source":       "QuickBooks",
            "as_of":        now,
        })

    except Exception as e:
        print(f"[qb/data] error: {e}")
        return jsonify({"error": str(e)}), 500


# ── MAIN ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
