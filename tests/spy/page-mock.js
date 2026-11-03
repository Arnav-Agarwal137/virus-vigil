// Fake phone for the spy-app row test. window.__extraApps lets the test add an app between scans.
window.__extraApps = [];
const base = (pkg, label, certs) => ({ pkg, label, installer: "com.android.vending", granted: [], offers: [], certs });
window.__TAURI__ = { core: { invoke: async (cmd, a) => {
  if (cmd === "platform") return "android";
  if (cmd === "ask_local_ai") return { ok: false, error: "no-ollama" };
  if (cmd === "phish_lookup") return { found: [], count: 500000, ageHours: 3 };
  if (cmd === "update_phish_list") return {};
  if (cmd === "phone" && a.cmd === "scan") return {
    android: { sdk: 31, release: "12", patch: "2023-04-01", maker: "vivo", model: "V2111" },
    lock: true, encryption: 5, accessibility: [], admins: [],
    sms: { pkg: "com.google.android.apps.messaging", label: "Messages", system: true },
    wifi: { connected: true, security: 2 },
    apps: [
      base("com.mspy.lite", "System Service", ["0000000000000000000000000000000000000000"]),
      base("com.innocent.name", "Calculator Plus", ["31a6ececd97cf39bc4126b8745cd94a7c30bf81c"]),
      base("com.whatsapp", "WhatsApp", []),
      base("com.example.nocert", "Notes", null),
      ...window.__extraApps,
    ],
  };
  if (cmd === "phone") return {};
  throw new Error("mock: " + cmd);
} }, dialog: { open: async () => null }, opener: { openUrl: async () => {} }, event: { listen: async () => () => {} } };
