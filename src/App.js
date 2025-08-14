import React, { useState, useEffect } from "react";
import "./App.css";

const OCRA_SUITE_RESPONSE = "OCRA-1:HOTP-SHA512-10:QN10-T3M";
const OCRA_TIME_STEP_SECONDS = 180; // T3M

const App = () => {
  // ----- STATES: key request (E2EE) -----
  const [corpId, setCorpId] = useState("");
  const [userId, setUserId] = useState("");
  const [responseData, setResponseData] = useState(null);
  const [decryptedHmacKey, setDecryptedHmacKey] = useState(""); // base64 string
  const [loading, setLoading] = useState(false);

  // ----- STATES: transaksi & OCRA -----
  const [refNum, setRefNum] = useState("");
  const [trxDate, setTrxDate] = useState(""); // yyyy-MM-dd
  const [amount, setAmount] = useState("");
  const [fromAccount, setFromAccount] = useState("");
  const [toAccount, setToAccount] = useState("");

  const [challenge, setChallenge] = useState("");         // Manual input challenge
  const [responseCode, setResponseCode] = useState("");    // Manual input responseCode
  const [validateResult, setValidateResult] = useState(null);

  const [working, setWorking] = useState(false);

  // NEW: one-time-use flags
  const [consumed, setConsumed] = useState(false);        // true setelah valid:OK atau reason:ALREADY_USED
  const [lastReason, setLastReason] = useState("");       // simpan OK / NOT_MATCH_OR_EXPIRED / ALREADY_USED

  // load e2ee.js
  useEffect(() => {
    const script = document.createElement("script");
    script.src = "/e2ee.js";
    script.async = true;
    script.onload = () => console.log("e2ee.js loaded successfully!");
    script.onerror = () => console.error("Failed to load e2ee.js");
    document.body.appendChild(script);
    return () => document.body.removeChild(script);
  }, []);

  /* ------------------ UTIL: converters ------------------ */
  function toUint8Array(v) {
    if (v instanceof Uint8Array) return v;
    if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
    if (v instanceof ArrayBuffer) return new Uint8Array(v);
    if (Array.isArray(v)) return Uint8Array.from(v);
    return null;
  }
  function bytesToBase64(u8) {
    let s = "";
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return btoa(s);
  }
  function normalizeB64(s) {
    return s.replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
  }
  function b64ToBytes(s) {
    if (typeof s !== "string") return null;
    try {
      const n = normalizeB64(s);
      const pad = n.length % 4 === 0 ? "" : "=".repeat(4 - (n.length % 4));
      const bin = atob(n + pad);
      const arr = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
      return arr;
    } catch {
      return null;
    }
  }
  function hexToBytes(s) {
    if (typeof s !== "string") return null;
    const clean = s.trim().replace(/^0x/, "");
    if (!/^[0-9a-fA-F]+$/.test(clean) || clean.length % 2 !== 0) return null;
    const len = clean.length / 2;
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
  }
  function utf8ToBytes(s) {
    return new TextEncoder().encode(String(s));
  }
  function parseKeyToBytes(val) {
    if (val == null) return null;
    const ta = toUint8Array(val);
    if (ta) return ta;

    if (typeof val === "object") {
      if (typeof val.base64 === "string") {
        const b = b64ToBytes(val.base64);
        if (b) return b;
      }
      if (typeof val.hex === "string") {
        const h = hexToBytes(val.hex);
        if (h) return h;
      }
      if (Array.isArray(val.data)) {
        return Uint8Array.from(val.data);
      }
      try {
        const s = JSON.stringify(val);
        const tryHex = hexToBytes(s);
        if (tryHex) return tryHex;
        const tryB64 = b64ToBytes(s);
        if (tryB64) return tryB64;
        return utf8ToBytes(s);
      } catch {}
    }
    const s = String(val);
    let out = hexToBytes(s);
    if (out) return out;
    out = b64ToBytes(s);
    if (out) return out;
    return utf8ToBytes(s);
  }

  // NORMALISASI hasil decrypt jadi STRING base64
  async function normalizeDecryptedKey(val) {
    if (val && typeof val.then === "function") {
      try { val = await val; } catch (e) { throw new Error("decryptData gagal: " + (e?.message || e)); }
    }
    const ta = toUint8Array(val);
    if (ta) return bytesToBase64(ta);

    if (typeof CryptoKey !== "undefined" && val instanceof CryptoKey) {
      try {
        const raw = await crypto.subtle.exportKey("raw", val);
        return bytesToBase64(new Uint8Array(raw));
      } catch {
        throw new Error("Tidak bisa export CryptoKey (non-extractable). Pastikan decryptData return raw key/string.");
      }
    }
    if (typeof val === "object" && val !== null) {
      if (typeof val.base64 === "string") return val.base64.trim();
      if (typeof val.hex === "string") {
        const b = hexToBytes(val.hex);
        if (b) return bytesToBase64(b);
      }
      if (Array.isArray(val.data)) return bytesToBase64(Uint8Array.from(val.data));
    }
    const s = String(val).trim();
    const hb = hexToBytes(s); if (hb) return bytesToBase64(hb);
    const bb = b64ToBytes(s); if (bb) return bytesToBase64(bb);
    return bytesToBase64(utf8ToBytes(s));
  }

  /* ------------------ UTIL: bytes ops ------------------ */
  function concatBytes(...chunks) {
    const total = chunks.reduce((a, b) => a + (b?.length || 0), 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) { if (!c) continue; out.set(c, offset); offset += c.length; }
    return out;
  }
  function to8ByteBEFromNumber(n) {
    const hi = Math.floor(n / 2 ** 32);
    const lo = n >>> 0;
    return new Uint8Array([
      (hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>>  8) & 0xff, (hi       ) & 0xff,
      (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>>  8) & 0xff, (lo       ) & 0xff,
    ]);
  }

  /* ------------------ OCRA helpers ------------------ */
  function hotpTruncate(hmac) {
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binCode =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);
    return binCode >>> 0;
  }
  function padLeft(num, digits) { const s = String(num); return s.length >= digits ? s : "0".repeat(digits - s.length) + s; }
  function padRightTo128Bytes(qBytes) { const out = new Uint8Array(128); out.set(qBytes.slice(0,128)); return out; }
  function currentTimeStep() { const secs = Math.floor(Date.now()/1000); return Math.floor(secs / OCRA_TIME_STEP_SECONDS); }

  // FE OCRA: QN10-T3M
  async function ocraQn10T3M(challengeDigits, keyRawBytes) {
    const challengeStr = String(challengeDigits).trim();
    if (!/^\d{10}$/.test(challengeStr)) throw new Error("Challenge harus 10 digit angka");
    if (!window.crypto?.subtle) throw new Error("WebCrypto tidak tersedia di browser ini");

    const suiteBytes = utf8ToBytes(OCRA_SUITE_RESPONSE);
    const nullSep = new Uint8Array([0x00]);
    const qBytes = padRightTo128Bytes(utf8ToBytes(challengeStr));
    const tCount = currentTimeStep();
    const tBytes = to8ByteBEFromNumber(tCount);
    const data = concatBytes(suiteBytes, nullSep, qBytes, tBytes);

    const cryptoKey = await crypto.subtle.importKey("raw", keyRawBytes, { name: "HMAC", hash: "SHA-512" }, false, ["sign"]);
    const sig = await crypto.subtle.sign("HMAC", cryptoKey, data);
    const sigBytes = new Uint8Array(sig);

    const bin = hotpTruncate(sigBytes);
    const otp10 = bin % (10 ** 10);
    return padLeft(otp10, 10);
  }

  /* ------------------ API: Ambil HMAC key (E2EE) ------------------ */
  const handleGetKey = async () => {
    if (!corpId || !userId) { alert("Please fill in both CorpId and UserId."); return; }
    setLoading(true);
    try {
      const sessionKey = await window.createKey();
      const publicKey =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxRjSBw0jCl+3Cxnr+TgWel/HldUaDQqjl8Ogukho3KF6E/3IQrIy5FhEECuNiUMECFVKuGQHRuS5UnL4nwYsMh3tmvBWajG22lrCwRlSjxITR7/pQIxpVhC/hukIBtKN6qZxjAbW6VWAioxpWQFplWmc8uUVrOrO5LggfqSE9XIqMi3NwzyHvfaGF6CFsMNsbhwT4ipbbVwP8C2H3vVvlLHbNhA+iZ1lufC0YTpB9OQHrkYAEb/aKUmvhNIqFfZUuckHV1T+XCuPddU9XyjyD3EbwcrsWIDlpgcI6Z8QvFX8Yx9vtGhwPQbsx23l91wFm/HcIkkQyfQiZfa86+ZqowIDAQAB";
      const encSessionKey = await window.encryptKey(publicKey, sessionKey);
      // const keyName = corpId + userId;
      // const encKeyName = await window.encryptData(sessionKey, keyName);
      const body = JSON.stringify({ corpId, userId });

      const response = await fetch("http://localhost:8080/api/v1/token/key", {
        method: "POST",
        headers: { "Content-Type": "application/json", "encSessionKey": encSessionKey },
        body,
      });
      if (!response.ok) throw new Error("Network response was not ok");
      const data = await response.json();
      setResponseData(data);

      if (data && data.encHmacKey) {
        const rawMaybe = window.decryptData(sessionKey, data.encHmacKey);
        const normalized = await normalizeDecryptedKey(rawMaybe); // base64 string
        setDecryptedHmacKey(normalized);
      } else {
        setDecryptedHmacKey("");
      }
    } catch (error) {
      console.error("Error:", error);
      setResponseData({ error: error.message });
      setDecryptedHmacKey("");
    } finally {
      setLoading(false);
    }
  };

  /* ------------------ API: /ocra/v1/challenge ------------------ */
  const handleCreateChallenge = async () => {
    if (!refNum || !trxDate || !amount || !fromAccount || !toAccount || !corpId || !userId) {
      alert("Lengkapi semua field transaksi & identitas (corpId, userId).");
      return;
    }
    setWorking(true);
    setValidateResult(null);
    setLastReason("");
    setConsumed(false);        // reset one-time flag tiap buat challenge baru
    setResponseCode("");       // reset response FE lama
    try {
      const res = await fetch("http://localhost:8080/ocra/v1/challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refNum, trxDate, amount, fromAccount, toAccount, corpId, userId }),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json?.message || "Gagal create challenge");
      setChallenge(json.challenge || "");
    } catch (e) {
      console.error(e);
      alert(e.message || "Error create challenge");
    } finally {
      setWorking(false);
    }
  };

  /* ------------------ FE: generate responseCode ------------------ */
  const handleGenerateResponseFE = async () => {
    if (consumed) { alert("Kode sudah digunakan. Buat challenge baru."); return; }
    if (!challenge) { alert("Challenge belum ada. Buat challenge dulu."); return; }
    if (!decryptedHmacKey) { alert("HMAC key belum ada. Ambil key dulu di atas."); return; }

    try {
      setWorking(true);
      const keyBytes = parseKeyToBytes(decryptedHmacKey); // base64 -> bytes
      if (!keyBytes) throw new Error("Format key tidak valid (tidak bisa diparse)");
      const rc = await ocraQn10T3M(challenge, keyBytes);
      setResponseCode(rc);
    } catch (e) {
      console.error(e);
      alert(e.message || "Gagal generate responseCode");
    } finally {
      setWorking(false);
    }
  };

  /* ------------------ API: /ocra/v1/validate (one-time use) ------------------ */
  const handleValidate = async () => {
    if (consumed) { alert("Kode sudah digunakan. Buat challenge baru."); return; }
    if (!responseCode) { alert("ResponseCode belum ada. Generate dulu di FE."); return; }

    setWorking(true);
    try {
      const res = await fetch("http://localhost:8080/ocra/v1/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refNum, trxDate, amount, fromAccount, toAccount, corpId, userId, responseCode }),
      });
      const json = await res.json();
      setValidateResult(json);
      setLastReason(json?.reason || "");

      // Apapun hasilnya, kalau OK atau ALREADY_USED -> anggap "consumed"
      if (json?.valid === true || json?.reason === "ALREADY_USED") {
        setConsumed(true);
      }

      if (!res.ok) throw new Error(json?.reason || "Gagal validasi");

      // UX: kalau sukses, bersihkan responseCode dari UI supaya tidak dicoba-ulang
      if (json?.valid) {
        setResponseCode("");
      }

      // Info UX kalau replay
      if (!json?.valid && json?.reason === "ALREADY_USED") {
        alert("Kode sudah digunakan. Silakan minta challenge baru.");
      }
    } catch (e) {
      console.error(e);
      alert(e.message || "Error validate");
    } finally {
      setWorking(false);
    }
  };

  /* ------------------ Helper: reset flow OCRA ------------------ */
  const resetOcraFlow = () => {
    setChallenge("");
    setResponseCode("");
    setValidateResult(null);
    setConsumed(false);
    setLastReason("");
  };

  const validateDisabled = working || !responseCode || consumed;
  const generateDisabled = working || !decryptedHmacKey || !challenge || consumed;

  return (
    <div className="container">
      <h1>React App — OCRA Demo (HMAC dari CipherTrust)</h1>

      {/* ---------- 1) Ambil HMAC key (E2EE) ---------- */}
      <div className="card">
        <h2>1) Ambil HMAC Key (E2EE)</h2>
        <div className="form-grid">
          <label htmlFor="corpId">Corp ID</label>
          <input id="corpId" value={corpId} onChange={(e) => setCorpId(e.target.value)} placeholder="Corp ID" />
          <label htmlFor="userId">User ID</label>
          <input id="userId" value={userId} onChange={(e) => setUserId(e.target.value)} placeholder="User ID" />
        </div>
        <button onClick={handleGetKey} disabled={loading}>
          {loading ? "Loading..." : "Get HMAC Key"}
        </button>
        {responseData && (
          <div className="response-container">
            <h3>Response Token/Key API</h3>
            <pre>{JSON.stringify(responseData, null, 2)}</pre>
          </div>
        )}
        {decryptedHmacKey && (
          <div className="response-container">
            <h3>Decrypted HMAC Key (base64)</h3>
            <pre>{decryptedHmacKey}</pre>
          </div>
        )}
      </div>

      {/* ---------- 2) Transaksi & OCRA ---------- */}
      <div className="card">
        <h2>2) Transaksi & OCRA</h2>
        <div className="form-grid">
          <label>Ref Num</label>
          <input value={refNum} onChange={(e) => setRefNum(e.target.value)} placeholder="REF-123" />
          <label>Trx Date</label>
          <input type="date" value={trxDate} onChange={(e) => setTrxDate(e.target.value)} />
          <label>Amount</label>
          <input value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="1500000" />
          <label>From Account</label>
          <input value={fromAccount} onChange={(e) => setFromAccount(e.target.value)} placeholder="1234567890" />
          <label>To Account</label>
          <input value={toAccount} onChange={(e) => setToAccount(e.target.value)} placeholder="9876543210" />
        </div>

        <div className="btn-row">
          <button onClick={handleCreateChallenge} disabled={working}>
            {working ? "Processing..." : "Create Challenge (to BE)"}
          </button>
          <button onClick={handleGenerateResponseFE} disabled={generateDisabled}>
            {working ? "Processing..." : "Generate Response (on FE)"}
          </button>
          <button onClick={handleValidate} disabled={validateDisabled}>
            {working ? "Processing..." : "Validate (to BE)"}
          </button>
          <button onClick={resetOcraFlow} disabled={working}>
            Reset Flow
          </button>
        </div>

        {/* status one-time-use */}
        {consumed && (
          <div className="response-container">
            <h3>Status</h3>
            <pre>Kode sudah dikonsumsi ({lastReason || "OK"}). Buat challenge baru untuk transaksi berikutnya.</pre>
          </div>
        )}

        <div className="response-container">
          <h3>Challenge (Manual Input)</h3>
          <pre>{challenge || "Challenge code will appear here"}</pre>
          <input
            value={challenge}
            onChange={(e) => setChallenge(e.target.value)}
            placeholder="Enter Challenge"
          />
        </div>
        <div className="response-container">
          <h3>ResponseCode (Manual Input)</h3>
          <pre>{responseCode || "Response code will appear here"}</pre>
          <input
            value={responseCode}
            onChange={(e) => setResponseCode(e.target.value)}
            placeholder="Enter Response Code"
          />
        </div>
        {validateResult && (
          <div className="response-container">
            <h3>Validate Result</h3>
            <pre>{JSON.stringify(validateResult, null, 2)}</pre>
          </div>
        )}
      </div>
    </div>
  );
};

export default App;
