// Scan-flow + call-button test. window.__mode picks the Defender outcome.
window.__mode = "clean";
window.__opened = [];
window.__TAURI__ = { core: { invoke: async (cmd, a) => {
  if (cmd === "platform") return /Android/.test(navigator.userAgent) ? "android" : "windows";
  if (cmd === "ask_local_ai") return { ok: false, error: "no-ollama" };
  if (cmd === "update_phish_list") return {};
  if (cmd === "update_hash_list") return {};
  // Phone known-malware test (known.mjs): only answered when the test sets them; otherwise the
  // same "mock:" failure as before, so no other suite changes.
  if (cmd === "phone" && a.cmd === "scan" && window.__phoneScan) return JSON.parse(JSON.stringify(window.__phoneScan));
  // Settings pages / the uninstall box (phoneall.mjs): recorded, never opened.
  if (cmd === "phone" && a.cmd === "openSettings" && window.__phoneScan) { (window.__settings ||= []).push(a.args); return { opened: a.args.page }; }
  // A run left going by an earlier page (29 Sep busy guard): __busyLeft calls answer busy, and
  // sweep_progress says "running" for __runningPolls polls.
  if (cmd === "sweep_progress") { const r = (window.__runningPolls || 0) > 0; if (r) window.__runningPolls--; return { files: { running: r }, apps: { running: r } }; }
  if (cmd === "forget_fingerprints") { window.__forgot = (window.__forgot || 0) + 1; return { removed: ["storage-fingerprints.tsv"] }; }
  if (cmd === "check_installed" && window.__known) { (window.__knownArgs ||= []).push(a); if ((window.__busyLeft || 0) > 0) { window.__busyLeft--; return { checked: false, busy: true, found: [] }; } return window.__known; }
  // Laptop folder sweep (folders.mjs): answered only when the test sets window.__folders.
  if (cmd === "check_folders" && window.__folders) { await new Promise((r) => setTimeout(r, 1200)); /* a real sweep ends after the checkup summary */ window.__foldersCalls = (window.__foldersCalls || 0) + 1; return JSON.parse(JSON.stringify(window.__folders)); }
  if (cmd === "phish_lookup") {
    const found = (window.__phish || []).filter((n) => a.names.includes(n));
    // 2 Nov 2026 two-list answer (fileinside.mjs): only when the test sets __phishLists.
    if (window.__phishLists) return { found, count: 518000, ageHours: 3, sourceDays: 0, lists: window.__phishLists, foundBy: window.__phishBy || {} };
    return { found, count: 500000, ageHours: 3, sourceDays: window.__phishDays === undefined ? 0 : window.__phishDays };
  }
  if (cmd === "undo_available") return { available: false };
  // "Do it all for me" (allfix.mjs): records each call; window.__allNo = the person pressed No.
  if (cmd === "apply_all") { (window.__allArgs ||= []).push(a); if (window.__allNo) return { cancelled: true };
    return { ok: true, cancelled: false, errors: [], undoSaved: true, changes: [...a.system.map((f) => ({ where: "System", name: f + "|x", wanted: 1, readBack: 1, ok: true })),
      ...a.browsers.map((b) => ({ where: "HKLM\\" + b, name: "DownloadRestrictions", wanted: 1, readBack: 1, ok: true }))] }; }
  // window.__av: "defender" (his laptop: Defender on, McAfee installed but off), "mcafee" (McAfee on,
  // Defender switched off by Windows), "stale" (McAfee on but its list is old). Shapes from scan.ps1 / extra.ps1.
  if (cmd === "scan_system") {
    const m = window.__av || "defender";
    const defOn = m === "defender" || m === "red";
    // "red": Defender's shield off on its own laptop, a firewall profile off, UAC off, SMB1/RDP/Guest on - all fixable.
    if (m === "red") return { defender: { available: true, realTime: false, tamper: true, mode: "Normal", signatureAgeDays: 0 },
      firewall: [{ name: "Domain", enabled: true }, { name: "Private", enabled: true }, { name: "Public", enabled: false }],
      smartscreen: { policy: 1 }, uac: { enabled: 0, adminPrompt: 5 }, lastUpdate: new Date().toISOString(), browsers: [],
      extra: { otherAv: [], guestEnabled: true, smb1: true, rdpDeny: 0, accountsRead: true, noPasswordAccounts: ["Kid"] },
      threatCount: window.__thCount === undefined ? 1 : window.__thCount, };
    return { defender: { available: true, realTime: defOn, tamper: defOn, mode: defOn ? "Normal" : "Not running", signatureAgeDays: defOn ? 0 : 40 },
      firewall: [{ name: "Domain", enabled: true }, { name: "Private", enabled: true }, { name: "Public", enabled: true }],
      smartscreen: { policy: 1 }, uac: { enabled: 1, adminPrompt: 5 }, lastUpdate: new Date().toISOString(), browsers: [],
      extra: { otherAv: [{ name: "McAfee", state: defOn ? "0x042000" : m === "stale" ? "0x041010" : "0x041000", on: !defOn, outOfDate: m === "stale" }] },
      threatCount: window.__thCount === undefined ? 1 : window.__thCount, };
  }
  if (cmd === "check_file") return window.__file ? { sha256: "00", apk: null, qr: null, stillThere: true, defender: { ran: true, exitCode: 0, found: false, output: "" }, ...window.__file } : { sha256: "00", apk: null, qr: null, stillThere: true, defender: { ran: true, exitCode: 0, found: false, output: "" } };
  if (cmd === "defender_quick_scan") {
    await new Promise((r) => setTimeout(r, 2500));
    if (window.__mode === "fail") return { ran: false, exitCode: 2, found: false, reason: "its scan failed, error 0x80508023", output: "x" };
    return { ran: true, exitCode: window.__mode === "caught" ? 2 : 0, found: window.__mode === "caught", output: "Scan finished." };
  }
  // Defender's own record (scan_record) and Vigil's startup read, for the quick scan's "What I checked".
  // window.__noRecord = the record can't be read; window.__trick = one startup item uses a malware trick.
  if (cmd === "scan_record") {
    if (window.__noRecord) throw new Error("no record");
    const end = new Date(), start = new Date(end.getTime() - 61000);
    // Full scan times (the sweep): window.__fullRec = "ours" (started after Vigil's start, finished now),
    // "old" (a full scan from 3 days ago - NOT ours), anything else = Defender records no full scan.
    const sw = JSON.parse(localStorage.getItem("vv.sweep") || "null");
    const full = window.__fullRec === "ours" && sw?.started ? { fullStart: sw.started, fullEnd: new Date(Math.max(end.getTime(), new Date(sw.started).getTime() + 1000)).toISOString(), fullSigs: "1.459.388.0" }
      : window.__fullRec === "old" ? { fullStart: new Date(end.getTime() - 3 * 864e5).toISOString(), fullEnd: new Date(end.getTime() - 3 * 864e5 + 3600e3).toISOString(), fullSigs: "1.459.100.0" } : {};
    return { read: true, quickStart: start.toISOString(), quickEnd: end.toISOString(), quickSigs: "1.459.388.0", sigs: "1.459.388.0", sigsUpdated: new Date(end.getTime() - 5 * 3600000).toISOString(), engine: "1.1.26080.3", ...full };
  }
  // The sweep's full scan: started (pid 4242) unless window.__fullFail; scan_alive answers window.__alive.
  if (cmd === "defender_full_scan") return window.__fullFail ? { started: false, error: "MpCmdRun refused" } : { started: true, pid: 4242 };
  if (cmd === "scan_alive") { (window.__alivePids ||= []).push(a.pid); return { alive: !!window.__alive }; }
  if (cmd === "startup_items") return { items: [
    { name: "OneDrive", path: "C:/Users/x/OneDrive.exe", exists: true, enabled: true, signature: "Valid", publisher: "Microsoft" },
    { name: "Helper", path: "C:/Program Files/h.exe", exists: true, enabled: true, signature: "NotSigned" },
    ...(window.__trick ? [{ name: "Updater", path: "C:/Users/x/AppData/Local/Temp/u.exe", exists: true, enabled: true, signature: "NotSigned", tempPlace: true }] : []),
  ] };
  if (cmd === "threat_history" && window.__thFail) return { ok: false, error: "test: could not read", items: [] };
  if (cmd === "threat_history") return { ok: true, items: [
    { name: "EICAR_Test_File", severity: 5, found: "2026-09-16T10:00:00+05:30", active: false, action: "Quarantined", resources: ["file:_C:\\old.txt"] },
    ...(window.__mode === "caught" ? [{ name: "Trojan:Win32/Wacatac.B!ml", severity: 5, found: new Date().toISOString(), active: true, action: null, resources: ["file:_C:\\Users\\x\\Downloads\\crack.exe"] }] : []),
  ] };
  throw new Error("mock: " + cmd);
} }, dialog: { open: async () => null }, opener: { openUrl: async (u) => { window.__opened.push(u); } }, event: { listen: async () => () => {} } };
