(function () {
  // NOTE: no comments or statements may come before this function (the loader does `return <this file>`).
  const { React, ReactNative: RN } = vendetta.metro.common;
  const { storage } = vendetta.plugin;

  // ---------- hex helpers (no BigInt: 64-bit IDs exceed Number precision) ----------
  const cleanHex = (v) => {
    v = (v || "").trim();
    if (/^0x/i.test(v)) v = v.slice(2);
    return v.replace(/[\s:,\-]/g, "");
  };
  const validateHex = (v) => {
    if (!v) throw new Error("Please enter a hex value.");
    if (!/^[0-9a-fA-F]+$/.test(v)) throw new Error(`'${v}' is not a valid hex string.`);
    return v;
  };
  const padBytes = (v, n) => {
    if (!n || n <= 0) return v;
    if (v.length % 2) v = "0" + v;
    if (v.length / 2 > n) throw new Error(`Value has ${v.length / 2} bytes, larger than requested ${n} bytes.`);
    return v.padStart(n * 2, "0");
  };
  const swapEndian = (h) => (h.match(/../g) || []).reverse().join("");
  const hexToDec = (hex) => {
    let d = [0];
    for (const ch of hex) {
      let carry = parseInt(ch, 16);
      for (let i = 0; i < d.length; i++) {
        const x = d[i] * 16 + carry;
        d[i] = x % 10;
        carry = Math.floor(x / 10);
      }
      while (carry) { d.push(carry % 10); carry = Math.floor(carry / 10); }
    }
    return d.reverse().join("");
  };
  const decToHex = (dec) => {
    let digits = dec.split("").map(Number);
    let out = "";
    while (digits.length && !(digits.length === 1 && digits[0] === 0)) {
      let rem = 0;
      const next = [];
      for (const dg of digits) {
        const cur = rem * 10 + dg;
        const q = Math.floor(cur / 16);
        rem = cur % 16;
        if (next.length || q) next.push(q);
      }
      out = rem.toString(16) + out;
      digits = next;
    }
    return out || "0";
  };

  // ---------- PSN API (same flow psnawp uses) ----------
  const CLIENT_AUTH = "Basic MDk1MTUxNTktNzIzNy00MzcwLTliNDAtMzgwNmU2N2MwODkxOnVjUGprYTV0bnRCMktxc1A=";
  const REDIRECT = "com.scee.psxandroid.scecompcall://redirect";
  const SCOPE = "psn:mobile.v2.core psn:clientapp";
  const uuid = () => "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === "x" ? r : (r & 3) | 8).toString(16);
  });
  const qs = (o) => Object.keys(o).map((k) => encodeURIComponent(k) + "=" + encodeURIComponent(o[k])).join("&");
  let session = null; // { access, exp }

  async function accessToken() {
    if (session && session.exp > Date.now() + 60000) return session.access;
    const npsso = (storage.npsso || "").trim();
    if (!npsso) throw new Error("Enter your NPSSO token first.");
    const cid = uuid();
    const authUrl = "https://ca.account.sony.com/api/authz/v3/oauth/authorize?" + qs({
      access_type: "offline", cid, client_id: "09515159-7237-4370-9b40-3806e67c0891",
      device_base_font_size: "10", device_profile: "mobile", elements_visibility: "no_aclink",
      enable_scheme_error_code: "true", no_captcha: "true", PlatformPrivacyWs1: "minimal",
      redirect_uri: REDIRECT, response_type: "code", scope: SCOPE,
      service_entity: "urn:service-entity:psn", service_logo: "ps", smcid: "psapp:signin",
      support_scheme: "sneiprls", turnOnTrustedBrowser: "true", ui: "pr",
    });
    const r1 = await fetch(authUrl, {
      method: "GET",
      redirect: "manual",
      headers: { Cookie: "npsso=" + npsso, "X-Requested-With": "com.scee.psxandroid" },
    });
    const loc = r1.headers && r1.headers.get && r1.headers.get("location");
    if (!loc) {
      throw new Error("PSN did not return a redirect (HTTP " + r1.status + "). This platform may hide or follow the redirect, so the login step can't read the auth code.");
    }
    if (/[?&]error=/.test(loc)) {
      throw new Error(/error_code=4165/.test(loc) ? "NPSSO token is expired or incorrect." : "PSN authentication failed.");
    }
    const m = /[?&]code=([^&]+)/.exec(loc);
    if (!m) throw new Error("No auth code in PSN redirect.");
    const r2 = await fetch("https://ca.account.sony.com/api/authz/v3/oauth/token", {
      method: "POST",
      headers: {
        Authorization: CLIENT_AUTH,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "com.sony.snei.np.android.sso.share.oauth.versa.USER_AGENT",
        "X-Psn-Correlation-Id": cid,
      },
      body: qs({ cid, code: decodeURIComponent(m[1]), grant_type: "authorization_code", redirect_uri: REDIRECT, scope: SCOPE, token_format: "jwt" }),
    });
    const j = await r2.json();
    if (!j.access_token) throw new Error("Token request failed: " + JSON.stringify(j).slice(0, 200));
    session = { access: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
    return session.access;
  }

  async function psnGet(url) {
    const token = await accessToken();
    const r = await fetch(url, { headers: { Authorization: "Bearer " + token } });
    const j = await r.json();
    if (!r.ok) throw new Error((j && j.error && j.error.message) || "PSN lookup failed (HTTP " + r.status + ").");
    return j;
  }

  async function hexToName(accountIdDec) {
    const j = await psnGet(`https://m.np.playstation.com/api/userProfile/v1/internal/users/${accountIdDec}/profiles`);
    if (!j.onlineId) throw new Error("No online ID in response.");
    return { onlineId: j.onlineId, accountId: accountIdDec };
  }
  async function nameToHex(name) {
    const j = await psnGet(`https://us-prof.np.community.playstation.net/userProfile/v1/users/${encodeURIComponent(name)}/profile2?fields=accountId,onlineId,currentOnlineId`);
    const p = j.profile || j;
    if (!p.accountId) throw new Error("User not found.");
    return { onlineId: p.onlineId || name, accountId: String(p.accountId) };
  }

  // ---------- clipboard / toast (best effort across Kettu/Bunny builds) ----------
  const copy = (text) => {
    try {
      const c = vendetta.metro.common.clipboard || vendetta.metro.findByProps("setString", "getString");
      c.setString(text);
      return true;
    } catch (e) { return false; }
  };
  const toast = (msg) => { try { vendetta.ui.toasts.showToast(msg); } catch (e) {} };

  // ---------- UI: same layout as the desktop tool ----------
  const h = React.createElement;
  const C = { bg: "#1e1f22", box: "#2b2d31", text: "#f2f3f5", dim: "#b5bac1", accent: "#5865f2", border: "#4e5058" };
  const st = {
    page: { padding: 16 },
    label: { color: C.text, marginTop: 12, marginBottom: 4, fontSize: 14 },
    input: { color: C.text, backgroundColor: C.box, borderWidth: 1, borderColor: C.border, borderRadius: 6, paddingHorizontal: 10, paddingVertical: 8 },
    btn: { backgroundColor: C.accent, borderRadius: 6, paddingVertical: 12, alignItems: "center", marginTop: 14 },
    btnText: { color: "#fff", fontWeight: "600" },
    out: { backgroundColor: C.box, borderWidth: 1, borderColor: C.border, borderRadius: 6, padding: 10, minHeight: 130 },
    outText: { color: C.text, fontFamily: RN.Platform.OS === "ios" ? "Menlo" : "monospace", fontSize: 12 },
  };
  const Btn = (label, onPress, extra, disabled) =>
    h(RN.TouchableOpacity, { onPress, disabled, style: [st.btn, extra, disabled && { opacity: 0.5 }] }, h(RN.Text, { style: st.btnText }, label));

  function Settings() {
    const [mode, setMode] = React.useState("hex2name");
    const [input, setInput] = React.useState("");
    const [width, setWidth] = React.useState("");
    const [npsso, setNpsso] = React.useState(storage.npsso || "");
    const [out, setOut] = React.useState("");
    const [last, setLast] = React.useState("");
    const [busy, setBusy] = React.useState(false);

    const switchMode = (m) => { setMode(m); setInput(""); setOut(""); setLast(""); };

    const convert = async () => {
      if (busy) return;
      try {
        const w = parseInt((width || "").trim(), 10) || 0;
        let res;
        if (mode === "hex2name") {
          const hx = padBytes(validateHex(cleanHex(input)), w);
          setBusy(true); setOut("Looking up...");
          res = await hexToName(hexToDec(hx));
        } else {
          const name = (input || "").trim();
          if (!name) throw new Error("Please enter a PSN name.");
          setBusy(true); setOut("Looking up...");
          res = await nameToHex(name);
        }
        const hexId = decToHex(res.accountId).padStart((w || 8) * 2, "0");
        const result = mode === "hex2name" ? res.onlineId : hexId;
        setLast(result);
        copy(result);
        setOut(
          `Online ID:        ${res.onlineId}\n` +
          `Account ID:       ${res.accountId}\n` +
          `${"-".repeat(35)}\n` +
          `Hex ID:           ${hexId}\n` +
          `Byte count:       ${hexId.length / 2}\n\n` +
          `(Swapped endian hex: ${swapEndian(hexId)})`
        );
      } catch (e) {
        setOut("");
        if (/expired|incorrect/i.test(String(e && e.message))) session = null;
        toast(String((e && e.message) || e));
        setOut("Error: " + String((e && e.message) || e));
      } finally {
        setBusy(false);
      }
    };

    const radio = (label, value) =>
      h(RN.TouchableOpacity, { onPress: () => switchMode(value), style: { flexDirection: "row", alignItems: "center", marginRight: 18 } },
        h(RN.Text, { style: { color: C.accent, fontSize: 18, marginRight: 6 } }, mode === value ? "◉" : "○"),
        h(RN.Text, { style: { color: C.text } }, label));

    return h(RN.ScrollView, { style: { flex: 1, backgroundColor: C.bg }, contentContainerStyle: st.page, keyboardShouldPersistTaps: "handled" },
      h(RN.Text, { style: st.label }, "NPSSO token (stored only on this device):"),
      h(RN.TextInput, { style: st.input, value: npsso, secureTextEntry: true, autoCapitalize: "none", autoCorrect: false,
        onChangeText: (t) => { setNpsso(t); storage.npsso = t; session = null; } }),
      h(RN.View, { style: { flexDirection: "row", marginTop: 16 } },
        radio("Hex ID → PSN name", "hex2name"), radio("PSN name → Hex ID", "name2hex")),
      h(RN.Text, { style: st.label }, mode === "hex2name" ? "Hex value:" : "PSN name:"),
      h(RN.TextInput, { style: st.input, value: input, onChangeText: setInput, autoCapitalize: "none", autoCorrect: false, onSubmitEditing: convert }),
      h(RN.Text, { style: st.label }, "Force byte width (optional):"),
      h(RN.TextInput, { style: [st.input, { width: 90 }], value: width, onChangeText: setWidth, keyboardType: "number-pad" }),
      Btn(busy ? "Looking up..." : "Convert", convert, null, busy),
      h(RN.Text, { style: st.label }, "Result:"),
      h(RN.View, { style: st.out }, h(RN.Text, { style: st.outText, selectable: true }, out)),
      Btn("Copy Result", () => {
        if (!last) return toast("Nothing to copy. Run a conversion first.");
        toast(copy(last) ? "Copied" : "Couldn't access clipboard");
      })
    );
  }

  return { default: { onLoad() {}, onUnload() {}, settings: Settings } };
})()
