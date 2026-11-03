window.__TAURI__ = { core: { invoke: async (cmd, a) => {
  if (cmd === "platform") return "windows";
  if (cmd === "ask_local_ai") return { ok: false, error: "no-ollama" };
  if (cmd === "phish_lookup") return { found: [], count: 500000, ageHours: 3 };
  throw new Error("mock: " + cmd);
} }, dialog: { open: async () => null }, opener: { openUrl: async () => {} }, event: { listen: async () => () => {} } };
