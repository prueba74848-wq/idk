(function () {
  const V = (typeof vendetta !== "undefined" && vendetta) || {};
  const safe = (f) => { try { return f(); } catch (e) { return undefined; } };
  const getReact = () => safe(() => V.metro.common.React) || safe(() => V.metro.findByProps("createElement", "useState"));
  const getRN = () => safe(() => V.metro.common.ReactNative) || safe(() => V.metro.findByProps("View", "Text", "TextInput", "ScrollView"));
  const localStore = {};
  const store = () => safe(() => V.plugin.storage) || localStore;
  let memToken = "";
  // Accepts a bare token, a quoted one, or the whole {"npsso":"..."} JSON that Sony's page shows.
  const normToken = (raw) => {
    const t = String(raw || "");
    const m = t.match(/[A-Za-z0-9]{64}/);
    return m ? m[0] : t.replace(/["'\s{}]/g, "").replace(/^npsso:?/i, "");
  };
  const getToken = () => normToken(safe(() => store().npsso) || memToken);
  const setToken = (t) => { memToken = t; try { store().npsso = t; } catch (e) {} };

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

  function accessToken() {
    if (session && session.exp > Date.now() + 60000) return Promise.resolve(session.access);
    const npsso = getToken();
    if (!npsso) return Promise.reject(new Error("Enter your NPSSO token first."));
    if (npsso.length < 32) return Promise.reject(new Error("The NPSSO token looks wrong (" + npsso.length + " characters, expected 64)."));
    const cid = uuid();
    const authUrl = "https://ca.account.sony.com/api/authz/v3/oauth/authorize" + "?" + qs({
      access_type: "offline", cid: cid, client_id: "09515159-7237-4370-9b40-3806e67c0891",
      device_base_font_size: "10", device_profile: "mobile", elements_visibility: "no_aclink",
      enable_scheme_error_code: "true", no_captcha: "true", PlatformPrivacyWs1: "minimal",
      redirect_uri: REDIRECT, response_type: "code", scope: SCOPE,
      service_entity: "urn:service-entity:psn", service_logo: "ps", smcid: "psapp:signin",
      support_scheme: "sneiprls", turnOnTrustedBrowser: "true", ui: "pr",
    });
    return fetch(authUrl, {
      method: "GET",
      redirect: "manual",
      headers: { Cookie: "npsso=" + npsso, "X-Requested-With": "com.scee.psxandroid" },
    }).then(function (r1) {
      const loc = r1.headers && r1.headers.get && r1.headers.get("location");
      if (!loc) {
        throw new Error("PSN did not accept the NPSSO token (HTTP " + r1.status + ", no redirect). It is most likely expired or invalid: sign in at playstation.com, open ca.account.sony.com/api/v1/ssocookie, and paste the fresh 64-character token in settings.");
      }
      if (/[?&]error=/.test(loc)) {
        throw new Error(/error_code=4165/.test(loc) ? "NPSSO token is expired or incorrect." : "PSN authentication failed.");
      }
      const m = /[?&]code=([^&]+)/.exec(loc);
      if (!m) throw new Error("No auth code in PSN redirect.");
      return fetch("https://ca.account.sony.com/api/authz/v3/oauth/token", {
        method: "POST",
        headers: {
          Authorization: CLIENT_AUTH,
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "com.sony.snei.np.android.sso.share.oauth.versa.USER_AGENT",
          "X-Psn-Correlation-Id": cid,
        },
        body: qs({ cid: cid, code: decodeURIComponent(m[1]), grant_type: "authorization_code", redirect_uri: REDIRECT, scope: SCOPE, token_format: "jwt" }),
      });
    }).then(function (r2) {
      return r2.json();
    }).then(function (j) {
      if (!j.access_token) throw new Error("Token request failed: " + JSON.stringify(j).slice(0, 200));
      session = { access: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
      return session.access;
    });
  }

  function psnGet(url) {
    return accessToken().then(function (token) {
      return fetch(url, { headers: { Authorization: "Bearer " + token } });
    }).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok) throw new Error((j && j.error && j.error.message) || "PSN lookup failed (HTTP " + r.status + ").");
        return j;
      });
    });
  }

  function hexToName(accountIdDec) {
    return psnGet("https://m.np.playstation.com/api/userProfile/v1/internal/users/" + accountIdDec + "/profiles").then(function (j) {
      if (!j.onlineId) throw new Error("No online ID in response.");
      return { onlineId: j.onlineId, accountId: accountIdDec };
    });
  }
  function nameToHex(name) {
    return psnGet("https://us-prof.np.community.playstation.net/userProfile/v1/users/" + encodeURIComponent(name) + "/profile2?fields=accountId,onlineId,currentOnlineId").then(function (j) {
      const p = j.profile || j;
      if (!p.accountId) throw new Error("User not found.");
      return { onlineId: p.onlineId || name, accountId: String(p.accountId) };
    });
  }

  // Shared by the settings panel and the slash command.
  function lookup(mode, input, w) {
    let task;
    try {
      if (mode === "hex2name") {
        const hx = padBytes(validateHex(cleanHex(input)), w);
        task = hexToName(hexToDec(hx));
      } else {
        const name = (input || "").trim();
        if (!name) throw new Error("Please enter a PSN name.");
        task = nameToHex(name);
      }
    } catch (e) {
      return Promise.reject(e);
    }
    return task.then(function (res) {
      const hexId = decToHex(res.accountId).padStart((w || 8) * 2, "0");
      const result = mode === "hex2name" ? res.onlineId : hexId;
      const text =
        "Online ID:        " + res.onlineId + "\n" +
        "Account ID:       " + res.accountId + "\n" +
        "-----------------------------------\n" +
        "Hex ID:           " + hexId + "\n" +
        "Byte count:       " + (hexId.length / 2) + "\n\n" +
        "(Swapped endian hex: " + swapEndian(hexId) + ")";
      return { result: result, text: text };
    });
  }

  // ---------- clipboard / toast (best effort across Kettu/Bunny builds) ----------
  const copy = (text) => {
    try {
      const c = safe(() => V.metro.common.clipboard) || V.metro.findByProps("setString", "getString");
      c.setString(text);
      return true;
    } catch (e) { return false; }
  };
  const toast = (msg) => { try { V.ui.toasts.showToast(msg); } catch (e) {} };

  function buildPanel() {
    const React = getReact();
    const RN = getRN();
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

  function Panel() {
    const [mode, setMode] = React.useState("hex2name");
    const [input, setInput] = React.useState("");
    const [width, setWidth] = React.useState("");
    const [npsso, setNpsso] = React.useState(safe(() => store().npsso) || memToken || "");
    const [out, setOut] = React.useState("");
    const [last, setLast] = React.useState("");
    const [busy, setBusy] = React.useState(false);

    const switchMode = (m) => { setMode(m); setInput(""); setOut(""); setLast(""); };

    const fail = function (e) {
      const msg = String((e && e.message) || e);
      if (/expired|incorrect/i.test(msg)) session = null;
      toast(msg);
      setOut("Error: " + msg);
    };

    const convert = function () {
      if (busy) return;
      const w = parseInt((width || "").trim(), 10) || 0;
      setBusy(true);
      setOut("Looking up...");
      lookup(mode, input, w).then(function (r) {
        setLast(r.result);
        copy(r.result);
        setOut(r.text);
      }).catch(fail).then(function () { setBusy(false); });
    };

    const radio = (label, value) =>
      h(RN.TouchableOpacity, { onPress: () => switchMode(value), style: { flexDirection: "row", alignItems: "center", marginRight: 18 } },
        h(RN.Text, { style: { color: C.accent, fontSize: 18, marginRight: 6 } }, mode === value ? "◉" : "○"),
        h(RN.Text, { style: { color: C.text } }, label));

    return h(RN.ScrollView, { style: { flex: 1, backgroundColor: C.bg }, contentContainerStyle: st.page, keyboardShouldPersistTaps: "handled" },
      h(RN.Text, { style: st.label }, "NPSSO token (stored only on this device):"),
      h(RN.TextInput, { style: st.input, value: npsso, secureTextEntry: true, autoCapitalize: "none", autoCorrect: false,
        onChangeText: (t) => { setNpsso(t); setToken(t); session = null; } }),
      h(RN.Text, { style: { color: C.dim, fontSize: 12, marginTop: 4 } },
        (function () {
          const n = normToken(npsso).length;
          return n === 0 ? "Token: not set" : n === 64 ? "Token: saved (64 characters)" : "Token: " + n + " characters (expected 64)";
        })()),
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

    return Panel;
  }

  let PanelComp = null;
  function Settings() {
    const React = getReact();
    const RN = getRN();
    try {
      if (!PanelComp) PanelComp = buildPanel();
      return React.createElement(PanelComp);
    } catch (e) {
      const msg = "PSN ID Lookup failed to render: " + String((e && e.message) || e);
      try {
        return React.createElement(RN.View, { style: { padding: 16 } },
          React.createElement(RN.Text, { style: { color: "#f2f3f5" }, selectable: true }, msg));
      } catch (e2) { return null; }
    }
  }

  // ---------- /psn slash command ----------
  let unregister = null;

  const argOf = (args, name) => {
    for (let i = 0; i < (args || []).length; i++) if (args[i] && args[i].name === name) return args[i].value;
    return undefined;
  };
  const reply = (ctx, text) => {
    try {
      const m = V.metro.findByProps("sendBotMessage");
      m.sendBotMessage(ctx.channel.id, "```\n" + text + "\n```");
    } catch (e) {
      toast(text.split("\n")[0]);
    }
  };

  const command = {
    name: "psn",
    displayName: "psn",
    description: "Convert a PSN hex Account ID to a name, or a name to a hex ID",
    displayDescription: "Convert a PSN hex Account ID to a name, or a name to a hex ID",
    applicationId: "-1",
    type: 1,
    inputType: 0,
    options: [
      {
        name: "mode", displayName: "mode", type: 3, required: true,
        description: "Direction of the conversion", displayDescription: "Direction of the conversion",
        choices: [
          { name: "Hex ID to PSN name", displayName: "Hex ID \u2192 PSN name", value: "hex2name" },
          { name: "PSN name to Hex ID", displayName: "PSN name \u2192 Hex ID", value: "name2hex" },
        ],
      },
      {
        name: "value", displayName: "value", type: 3, required: true,
        description: "The hex ID or the PSN name", displayDescription: "The hex ID or the PSN name",
      },
      {
        name: "width", displayName: "width", type: 4, required: false,
        description: "Force byte width (optional)", displayDescription: "Force byte width (optional)",
      },
    ],
    execute: function (args, ctx) {
      const mode = argOf(args, "mode") || "hex2name";
      const w = parseInt(argOf(args, "width"), 10) || 0;
      return lookup(mode, String(argOf(args, "value") || ""), w).then(function (r) {
        copy(r.result);
        reply(ctx, r.text);
      }).catch(function (e) {
        const msg = String((e && e.message) || e);
        if (/expired|incorrect/i.test(msg)) session = null;
        reply(ctx, "Error: " + msg + (/NPSSO/i.test(msg) ? "\n(Set it in the plugin's settings page.)" : ""));
      });
    },
  };

  return {
    default: {
      onLoad() {
        try { unregister = V.commands.registerCommand(command); } catch (e) { toast("PSN: couldn't register /psn"); }
      },
      onUnload() {
        try { if (unregister) unregister(); } catch (e) {}
        unregister = null;
      },
      settings: Settings,
    },
  };
})()
