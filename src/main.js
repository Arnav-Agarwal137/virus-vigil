// Virus Vigil - the page. Vigil talks on the left; the Protection Card on the right
// is stamped as each protection ("dose") is confirmed. Everything is checked on this
// computer. Nothing about the person or the PC is ever sent. Outgoing traffic is only: web
// pages the person chooses to open, and downloads of public lists (the known-bad add-on list,
// extensions.ps1) that are matched here.

import {
  THREAT_TYPES, PLATFORMS, SUFFIXES, FAMILIES, SEVERITY, parseThreatName,
  PERMISSIONS, DANGER_COMBOS, SCAMS, SHORTENERS, RISKY_TLDS, BRANDS, GLOSSARY,
  EXT_POWERS, ALL_SITES, SHARED_HOSTS, PLATFORM_BASES, LOOK,
} from "./knowledge.js";
import { ANSWERS, MORE_GLOSSARY, forPlatform } from "./answers.js";
import { spyOf, SPY_LIST } from "./spy.js";
import { detectProblem, closestFamilies, doubtFamilies, CLOSEST_LABELS, isDistress, HOW_TO, FAMILIES as PROBLEMS, NODES, optionsFor, autoPick, nextOf, familyOf, leafFor } from "./triage.js";
Object.assign(GLOSSARY, MORE_GLOSSARY);

const T = window.__TAURI__;
const invoke = (cmd, args) => T.core.invoke(cmd, args);

// ---------- small helpers ----------
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const DAY = 864e5;
const ageDays = (iso) => (iso ? (Date.now() - new Date(iso).getTime()) / DAY : Infinity);
const fmtDate = (iso) => (iso ? new Date(iso).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" }) : "never");
const stampDate = (iso) => { const d = new Date(iso); return `${d.getDate()} ${"JAN FEB MAR APR MAY JUN JUL AUG SEP OCT NOV DEC".split(" ")[d.getMonth()]}`; };
const plural = (n, one, many) => `${typeof n === "number" ? n.toLocaleString("en-IN") : n} ${n === 1 ? one : many}`;

const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private window: ticks just won't persist */ } },
};

const AVATAR = `<svg viewBox="0 0 48 48" aria-hidden="true"><path class="shield" d="M24 3 41 9.5V22c0 10.6-7.1 19.3-17 23-9.9-3.7-17-12.4-17-23V9.5Z"/><polyline class="beat" points="9,25 17,25 20,18 24,32 28,14 31,25 39,25"/></svg>`;
document.querySelectorAll("[data-avatar]").forEach((el) => (el.innerHTML = AVATAR));

async function openUrl(url) {
  try {
    if (T.opener?.openUrl) await T.opener.openUrl(url);
    else await invoke("plugin:opener|open_url", { url });
  } catch (e) {
    if (/^tel:/.test(url)) { say(`<p>I couldn't open the dialer (${esc(e)}). Dial <b>${esc(url.slice(4))}</b> yourself.</p>`); return; }
    say(`<p>I couldn't open that page myself (${esc(e)}). You can type this address into your browser:</p><p><b>${esc(url)}</b></p>`);
  }
}
async function pickFile() {
  const options = { multiple: false, directory: false, title: "Choose a file for Vigil to check" };
  return T.dialog?.open ? T.dialog.open(options) : invoke("plugin:dialog|open", { options });
}

// ---------- state ----------
const state = { scan: null, threats: null, busy: false };
// The same page runs on Windows and on Android (Tauri's Android WebView names itself in the user
// agent). The phone has its own checks, card groups and flows - the "phone mode" section below.
const PHONE = /Android/i.test(navigator.userAgent);
const DEVICE = PHONE ? "phone" : "laptop";
let ticks = store.get("vv.ticks", {}); // manual doses: id -> ISO date stamped

// ---------- the conversation ----------
const feed = $("#feed");
function scrollDown() { feed.scrollTop = feed.scrollHeight; requestAnimationFrame(() => (feed.scrollTop = feed.scrollHeight)); }
function clearChoices() { feed.querySelectorAll(".choices").forEach((r) => r.remove()); }

function say(html, opts = {}) {
  clearChoices();
  const m = document.createElement("div");
  m.className = "msg vigil";
  m.innerHTML = `<span class="avatar">${AVATAR}</span><div class="bubble">${html}</div>`;
  feed.append(m);
  if (opts.choices) choices(opts.choices);
  scrollDown();
  return m;
}
function you(text) {
  clearChoices();
  const m = document.createElement("div");
  m.className = "msg you";
  m.innerHTML = `<div class="bubble">${esc(text)}</div>`;
  feed.append(m);
  scrollDown();
}
// A choice: {label, run, kind?: "main"|"quiet", keep?: true (does not end the question, e.g. "Open the page")}
function choices(list) {
  const row = document.createElement("div");
  row.className = "choices";
  for (const c of list) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "choice" + (c.kind ? " " + c.kind : "");
    b.textContent = c.label;
    b.addEventListener("click", () => {
      if (!c.keep) you(c.label);
      c.run();
    });
    row.append(b);
  }
  feed.append(row);
  scrollDown();
}
function thinking(text) {
  const m = say(`<span class="pulse" aria-hidden="true"></span>${esc(text)}`);
  m.classList.add("thinking");
  return () => m.remove();
}
// A "thinking" bubble whose words can change while the work runs.
function thinkingLive(text) {
  const m = say(`<span class="pulse" aria-hidden="true"></span><span class="live">${esc(text)}</span>`);
  m.classList.add("thinking");
  const live = m.querySelector(".live");
  return { set: (w) => { if (live) live.textContent = w; }, done: () => m.remove() };
}
// Live counts from Rust while a sweep or app check runs (29 Sep 2026, his report: "two seconds
// to scan my entire phone ... not actually scanning anything"). Counted by the code doing the
// work (folderscan::Progress), never estimated. Written into the bubble and the card row only.
function progressWords(p, what) {
  if (!p?.running) return null;
  const n = (x) => Number(x || 0).toLocaleString("en-IN");
  const gb = `${(Number(p.bytes || 0) / 1e9).toFixed(2)} GB`;
  const secs = `${Math.round((p.ms || 0) / 1000)} s`;
  const cur = String(p.current || "").split(/[\\/]/).pop();
  if (p.phase === 1) return `Listing ${what}: ${n(p.listed)} files found so far (${secs})...`;
  if (p.phase === 3) return `Fingerprinting app ${n(p.done)} of ${n(p.total)} - ${n(p.fresh)} read fresh, ${gb} (${secs})${cur ? ` - ${cur}` : ""}`;
  return `Reading file ${n(p.done)} of ${n(p.total)} - ${n(p.fresh)} read fresh, ${gb} (${secs})${cur ? ` - ${cur}` : ""}`;
}
function watchProgress(key, what, set, rowId) {
  const t = setInterval(async () => {
    let p;
    try { p = (await invoke("sweep_progress"))[key]; } catch { return; }
    const w = progressWords(p, what);
    if (!w) return;
    if (set) set(w);
    const note = document.querySelector(`#card-body [data-id="${rowId}"] .dose-note`);
    if (note) note.textContent = w;
  }, 700);
  return () => clearInterval(t);
}
// 29 Sep: after a page reload the last check can still be running in Rust, and a second call
// answers {busy: true}. Wait until the running one ends (its live counts say so), then ask again -
// its remembered fingerprints make the second call quick. Gives up only after an hour.
async function invokeOnce(cmd, args, key) {
  const t0 = Date.now();
  for (;;) {
    const r = await invoke(cmd, args);
    if (!r?.busy || Date.now() - t0 > 3600000) return r;
    for (let i = 0; i < 3600; i++) {
      await new Promise((ok) => setTimeout(ok, 1000));
      let p;
      try { p = (await invoke("sweep_progress"))[key]; } catch { break; }
      if (!p?.running) break;
    }
  }
}
const secsWords = (ms) => ms >= 60000 ? `${Math.floor(ms / 60000)} min ${Math.round((ms % 60000) / 1000)} s` : `${(ms / 1000).toFixed(1)} s`;
const deep = (html) => `<div class="deep deep-box">${html}</div>`;

async function guarded(fn) {
  if (state.busy) { say(`<p>One moment - I'm still finishing the last check. Ask again when it's done.</p>`); return; }
  state.busy = true;
  try { await fn(); }
  catch (e) { say(`<p>Something went wrong on my side: ${esc(e)}</p><p>Nothing was changed. You can try again.</p>`); }
  finally { state.busy = false; }
}

// ---------- doses (what the card shows) ----------
const HOWTO = {
  defender: {
    url: "windowsdefender://threatsettings",
    open: "Open Windows Security",
    steps: ["Windows Security", "Virus & threat protection", "Manage settings", "Turn on Real-time protection and Tamper Protection"],
  },
  otherav: { url: "windowsdefender://threat", open: "Open Windows Security", steps: ["Windows Security", "Virus & threat protection", "Under your antivirus's name, press “Open app”", "In it, press Update (or “Check for updates”)", "Come back and press “Check again”"] },
  firewall: { url: "windowsdefender://network", open: "Open firewall settings", steps: ["Windows Security", "Firewall & network protection", "Turn on each network that says Off"] },
  smartscreen: { url: "windowsdefender://appbrowser", open: "Open the filter settings", steps: ["Windows Security", "App & browser control", "Reputation-based protection settings", "Turn the checks on"] },
  update: { url: "ms-settings:windowsupdate", open: "Open Windows Update", steps: ["Settings", "Windows Update", "Check for updates", "Restart when it asks"] },
  uac: { steps: ["Start menu", "type UAC", "Change User Account Control settings", "Move the slider to the 2nd notch from the top", "OK"] },
  opera: { steps: ["Opera menu", "Settings", "Privacy & security", "Turn on Fraud and malware protection"] },
  accounts: { url: "ms-settings:otherusers", open: "Open account settings", steps: ["Settings", "Accounts", "Other users", "Give each account a password, or remove it"] },
  guest: { steps: ["Start menu", "type Computer Management", "Local Users and Groups → Users", "Double-click Guest", "Tick “Account is disabled”"] },
  folders: { steps: ["Don't open the file. If it is an installer (Setup.exe and the like), don't run it - that is how the 12 Sep fake game got in", "Open File Explorer, go to the folder in the note (the full path is under Details), select the file", "Press Shift+Delete, then Yes (it skips the Recycle Bin)", "If you ever opened or ran it: press “Scan everything”, and change your email and bank passwords from another device", "Come back and press “Check again”"] },
  smb1: { steps: ["Start menu", "type Windows Features", "Turn Windows features on or off", "Untick “SMB 1.0/CIFS File Sharing Support”", "OK, then restart"] },
  rdp: { url: "ms-settings:remotedesktop", open: "Open Remote Desktop settings", steps: ["Settings", "System", "Remote Desktop", "Switch it Off (unless you use it yourself)"] },
  assist: { steps: ["Start menu", "type Allow Remote Assistance", "Open “Allow Remote Assistance invitations…”", "Untick “Allow Remote Assistance connections to this computer”", "OK"] },
  // No ms-settings link: the switch moved from "For developers" to "Advanced" in 25H2; Explorer's menu is on every version.
  ext: { steps: ["File Explorer", "View", "Show", "Tick “File name extensions”"] },
  hosts: { steps: ["Start menu", "type Notepad, right-click it, Run as administrator", "File → Open: C:\\Windows\\System32\\drivers\\etc\\hosts", "Delete lines you don't recognise", "Save"] },
  proxy: { url: "ms-settings:network-proxy", open: "Open proxy settings", steps: ["Settings", "Network & internet", "Proxy", "Switch off any proxy you didn't set up"] },
  cloud: { url: "windowsdefender://threatsettings", open: "Open Windows Security", steps: ["Windows Security", "Virus & threat protection", "Manage settings", "Turn on Cloud-delivered protection"] },
  device: { url: "windowsdefender://devicesecurity", open: "Open Device security", steps: ["Windows Security", "Device security", "Core isolation details", "Turn on Memory integrity (and Local Security Authority protection)", "Restart"] },
  cards: { steps: ["Open the browser that keeps a card", "Menu (⋮ or …) → Settings", "Type “payment” in the Settings search box", "Remove every saved card (⋮ or × beside it)", "Switch off “Save and fill payment methods”", "Repeat in each profile of that browser"] },
  software: { steps: ["Tap the button below - it opens the maker's own download page", "Download the newest version (64-bit for most laptops)", "Run it - it installs over the old one and keeps your settings", "If there are two old programs, do the same for the second", "Come back and press “Check again”"] },
  // ms-settings:sync is the Windows Backup page (Microsoft's own support article links it).
  backup: { url: "ms-settings:sync", open: "Open Windows Backup", steps: ["Settings", "Accounts", "Windows backup", "Under OneDrive folder syncing, press Manage sync settings", "Switch on Desktop, Documents and Pictures", "No OneDrive space? Plug in a USB drive instead: Control Panel → System and Security → File History → Turn on"] },
  backupStranded: { steps: ["Start menu", "Type OneDrive and open it", "Sign in with your Microsoft account", "Wait for the cloud icon near the clock to show no warning", "The free plan holds 5 GB - if your files are bigger, use File History with a USB drive instead (Control Panel → System and Security → File History)"] },
  ransomware: { url: "windowsdefender://ransomwareprotection", open: "Open Ransomware protection", steps: ["Windows Security", "Virus & threat protection", "Ransomware protection → Manage ransomware protection", "Switch Controlled folder access On", "Press Yes on Windows' box"] },
  // Windows Home has no switch for these rules; Microsoft's documented local way is PowerShell.
  asrRare: { steps: ["Start menu", "type PowerShell, right-click it, Run as administrator", "Paste: Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled", "Press Enter, close the window", "If it ever blocks a program you trust, Windows Security → Protection history shows it"] },
  asrStd: { steps: ["Start menu", "type PowerShell, right-click it, Run as administrator", "Paste: Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5,9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2,e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled,Enabled,Enabled", "Press Enter, close the window"] },
  wmi: { steps: ["Don't delete it yet - a few are left by real programs (laptop-maker tools)", "Search the hook's name (shown above) online with the word “WMI”", "Run a full scan: More checks → Scan with Windows Defender", "Still unknown? Get a second opinion with ESET Online Scanner or Malwarebytes Free (one-time scan)", "Then press “Check again”"] },
  services: { steps: ["Start menu", "type Services, open it", "Find the name shown above, double-click it", "Read “Path to executable” - do you know that program?", "If not: press Stop, set Startup type to Disabled, OK", "Then check that file with Vigil (Check a file) and run a Defender scan"] },
  secureboot: { steps: ["This is switched on in the laptop's start-up menu (BIOS/UEFI), not in Windows", "Search your laptop model + “enable Secure Boot”", "Ask someone who has done it before if unsure"] },
};

// Hosts-file lines from tools people install on purpose (Docker Desktop, Tailscale).
const HOSTS_KNOWN = [/\.docker\.internal$/i, /\.ts\.net\.?$/i];
// Sites malware redirects so you get a fake page or your antivirus can't update.
const HOSTS_GUARDED = [...Object.values(BRANDS).flat(), "windowsupdate.com", "virustotal.com", "mcafee.com",
  "norton.com", "avast.com", "kaspersky.com", "bitdefender.com", "malwarebytes.com", "eset.com"];
const isBlockIp = (ip) => /^(0\.0\.0\.0|127\.|::1?$)/.test(ip);

function hostsVerdict(entries) {
  const hijack = [], unknown = [];
  for (const e of entries || []) {
    const names = e.names || [];
    if (names.some((n) => HOSTS_GUARDED.some((g) => n.toLowerCase() === g || n.toLowerCase().endsWith("." + g)))) hijack.push(e);
    else if (!isBlockIp(e.ip) && !names.some((n) => HOSTS_KNOWN.some((r) => r.test(n)))) unknown.push(e);
  }
  return { hijack, unknown };
}

// Defender attack-blocking (ASR) rules. GUIDs and names from Microsoft's ASR rules reference
// (learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference, read 24 Sep 2026).
const ASR_RARE = "01443614-cd74-433a-b99e-2ecdc07bfc25";
const ASR_LSASS = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2";
const ASR_STANDARD = ["56a863a9-875e-4185-98a7-b882c64b5ce5", ASR_LSASS, "e6db77e5-3df2-4cf1-b95a-636979351e5b"];
const ASR_ACTIONS = { 0: "off", 1: "block", 2: "watch only", 6: "warn" };
const ASR_NAMES = {
  [ASR_RARE]: "rare/new programs", "56a863a9-875e-4185-98a7-b882c64b5ce5": "abused signed drivers",
  [ASR_LSASS]: "password theft from memory (LSASS)", "e6db77e5-3df2-4cf1-b95a-636979351e5b": "hidden WMI restart hooks",
  "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": "Adobe Reader starting programs", "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Office starting programs",
  "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "programs from email", "5beb7efe-fd9a-4556-801d-275e5ffc04cc": "disguised scripts",
  "d3e037e1-3eb8-44c8-a917-57927947596d": "scripts launching downloads", "3b576869-a4ec-4529-8536-b80a7769e899": "Office writing programs",
  "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "Office injecting code", "26190899-1602-49e8-8b27-eb1d0a1ce869": "Outlook starting programs",
  "d1e49aac-8f56-4280-b9ba-993a6d77406c": "PsExec/WMI starting programs", "33ddedf1-c6e0-47cb-833e-de6133960387": "restart into Safe Mode",
  "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "unsigned programs from USB", "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb": "copied system tools",
  "a8f5898e-1dc8-49a9-9878-85004b8a61e6": "web shells (servers)", "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "Office macros calling Windows",
  "c1db55ab-c21a-4637-bb3f-a12568109d35": "advanced ransomware protection",
};

// "Deeper checks" (extra.ps1). A value of null means Windows would not tell us: no row,
// never "needs care" - an unreadable setting is not a problem we found.
function deeperDoses(s) {
  const x = s.extra;
  if (!x) return [];
  const out = [];
  const row = (cond, d) => { if (cond) out.push(d); };

  const av = x.otherAv || [];
  const staleOn = av.filter((a) => a.on && a.outOfDate);
  const pic = avPicture(s);
  const onNames = av.filter((a) => a.on).map((a) => a.name).join(", ");
  const offNames = av.filter((a) => !a.on).map((a) => a.name).join(", ");
  row(av.length, { id: "deep-otherav", care: "A second antivirus is out of date", name: "Second antivirus not in the way", ok: !staleOn.length, how: staleOn.length ? "otherav" : "defender",
    note: staleOn.length ? `${staleOn.map((a) => a.name).join(", ")} is on but its virus list is old.`
      : pic.otherPrimary ? `${onNames} is your antivirus now and up to date. Windows switched Defender off by itself - that is normal.`
      : onNames ? `${onNames} is on and up to date, alongside Defender.`
      : `${offNames} is installed but switched off - ${pic.defOn ? "Defender does the job" : "and Defender is off too"}.`,
    deep: av.map((a) => `${a.name} productState=${a.state} on=${a.on} outOfDate=${a.outOfDate}`).join("; ") });
  row(x.guestEnabled != null, { id: "deep-guest", care: "Guest account is on", name: "Guest account off", ok: !x.guestEnabled, how: "guest",
    note: x.guestEnabled ? "Anyone could use the laptop without an account." : "Stops anyone using the laptop without an account.", deep: `Guest enabled=${x.guestEnabled}` });
  const np = x.noPasswordAccounts || [];
  row(x.accountsRead, { id: "deep-nopass", care: "An account has no password", name: "Every account has a password", ok: !np.length, how: "accounts",
    note: np.length ? `No password needed for: ${np.join(", ")}.` : "No account opens without one.", deep: `PasswordRequired=False on: ${np.join(", ") || "none"}` });
  row(x.smb1 != null, { id: "deep-smb1", care: "Old file-sharing (SMB1) is on", name: "Old file-sharing switched off", ok: !x.smb1, how: "smb1",
    note: "SMB1 is how the WannaCry worm spread in 2017.", deep: `EnableSMB1Protocol=${x.smb1}` });
  row(x.rdpDeny != null, { id: "deep-rdp", care: "Remote Desktop is on", name: "Remote control from outside off", ok: x.rdpDeny === 1, how: "rdp",
    note: x.rdpDeny === 1 ? "Nobody can log in to this laptop over the network." : "Fine only if you use Remote Desktop yourself.", deep: `fDenyTSConnections=${x.rdpDeny}` });
  row(x.remoteAssist != null, { id: "deep-assist", care: "Remote help invitations are allowed", name: "Remote help invitations off", ok: x.remoteAssist !== 1, how: "assist",
    note: x.remoteAssist === 1 ? "“Tech support” scammers ask you to invite them in this way." : "Nobody can be invited in to take over the screen.", deep: `fAllowToGetHelp=${x.remoteAssist}` });
  row(x.hideExt != null, { id: "deep-ext", care: "File endings are hidden", name: "File endings visible", ok: x.hideExt === 0, how: "ext",
    note: x.hideExt === 0 ? "You see “bill.pdf.exe”, not a harmless-looking “bill.pdf”." : "So “bill.pdf.exe” shows as a harmless-looking “bill.pdf”. Windows hides them by default.", deep: `HideFileExt=${x.hideExt}` });
  if (x.hostsRead) {
    const hv = hostsVerdict(x.hostsEntries);
    const all = (x.hostsEntries || []).map((e) => `${e.ip} ${e.names.join(" ")}`).join("; ") || "none";
    if (hv.hijack.length) out.push({ id: "deep-hosts", care: "Website address book was changed", name: "Website address book untouched", ok: false, how: "hosts",
      note: `It sends ${hv.hijack.flatMap((e) => e.names).join(", ")} somewhere else - a known malware trick.`, deep: all });
    else if (hv.unknown.length) out.push({ id: "deep-hosts", name: "Website address book looked at", manual: true, how: "hosts",
      note: `${plural(hv.unknown.length, "line", "lines")} I don't recognise: ${hv.unknown.flatMap((e) => e.names).join(", ")}. Tap once you've checked.`, deep: all });
    else out.push({ id: "deep-hosts", name: "Website address book untouched", ok: true, how: "hosts",
      note: (x.hostsEntries || []).length ? "Only lines from tools you installed (like Docker or Tailscale)." : "Nothing added to it.", deep: all });
  }
  const p = x.proxy || {};
  const proxyOn = p.enabled === 1 || !!p.pac;
  out.push({ id: "deep-proxy", care: "Internet goes through a proxy", name: "Internet not rerouted", ok: !proxyOn, how: "proxy",
    note: proxyOn ? `Your traffic goes through ${p.server || p.pac} - fine only if you set that up.` : "No proxy is sitting in the middle.", deep: `ProxyEnable=${p.enabled} ProxyServer=${p.server} AutoConfigURL=${p.pac}` });
  out.push({ id: "deep-pause", care: "Updates are paused", name: "Updates not paused", ok: !x.updatesPausedUntil, how: "update",
    note: x.updatesPausedUntil ? `Paused until ${fmtDate(x.updatesPausedUntil)}.` : "Windows is allowed to fetch fixes.", deep: `pausedUntil=${x.updatesPausedUntil}` });
  out.push({ id: "deep-reboot", care: "A restart is waiting", name: "Updates finished installing", ok: !x.rebootPending, how: "update",
    note: x.rebootPending ? "Fixes are downloaded but only work after a restart." : "Nothing is waiting for a restart.", deep: `rebootPending=${x.rebootPending}` });
  row(x.cloud, { id: "deep-cloud", care: "Cloud look-ups are off", name: "Cloud look-ups on", ok: (x.cloud?.maps ?? 0) >= 1, how: "cloud",
    note: (x.cloud?.maps ?? 0) >= 1 ? "Lets brand-new viruses be recognised in seconds, not days." : "Brand-new viruses take days to be recognised instead of seconds.", deep: `MAPSReporting=${x.cloud?.maps} SubmitSamplesConsent=${x.cloud?.samples}` });
  row(x.memoryIntegrity != null, { id: "deep-hvci", care: "Memory integrity is off", name: "Memory integrity on", ok: !!x.memoryIntegrity, how: "device",
    note: x.memoryIntegrity ? "Stops bad drivers from getting into the heart of Windows." : "Bad drivers could get into the heart of Windows.", deep: `DeviceGuard running has 2 (HVCI)=${x.memoryIntegrity}` });
  row(x.lsaPpl != null, { id: "deep-lsa", care: "Windows' sign-in store is unguarded", name: "Password vault guarded", ok: x.lsaPpl >= 1, how: "device",
    note: x.lsaPpl >= 1 ? "Shields Windows' store of sign-ins from password-stealing tools." : "Password-stealing tools could read Windows' sign-ins.", deep: `RunAsPPL=${x.lsaPpl}` });
  row(x.driverBlocklist != null, { id: "deep-drivers", care: "Known-bad drivers are allowed", name: "Known-bad drivers blocked", ok: x.driverBlocklist !== 0, how: "device",
    note: x.driverBlocklist !== 0 ? "Refuses old drivers that attackers abuse." : "Old drivers that attackers abuse can still load.", deep: `VulnerableDriverBlocklistEnable=${x.driverBlocklist}` });
  if (x.asr) {
    const act = (id) => x.asr[id] ?? 0;
    const deepAsr = `ASR ${Object.entries(x.asr).map(([id, a]) => `${ASR_NAMES[id] || id}=${ASR_ACTIONS[a] ?? a}`).join("; ") || "none set"}. SmartAppControl=${x.sac} AicEnabled=${x.appSource}`;
    // Block (1) only: "warn" lets one click through, and one click is how the 12 Sep installer got in.
    const rare = act(ASR_RARE), rareOk = rare === 1 || x.sac === 1;
    out.push({ id: "deep-asr-rare", care: "Brand-new unknown programs can run", name: "Rare new programs blocked", ok: rareOk, how: "asrRare", asrFix: rareOk ? null : [ASR_RARE],
      note: rareOk ? "Windows refuses programs that are brand new and almost nobody has - the kind a fake game installer is."
        : rare === 2 ? "The rule is only watching, not blocking. A fake game installer like the 12 Sep one would still run."
        : rare === 6 ? "The rule only warns - one click lets a fake installer through." : "A fake game or “crack” installer nobody else has would run without a question.",
      deep: deepAsr });
    // Microsoft's "standard protection" three. Its docs: with LSA protection on, the LSASS rule adds nothing.
    const missing = ASR_STANDARD.filter((id) => act(id) !== 1 && !(id === ASR_LSASS && x.lsaPpl >= 1));
    out.push({ id: "deep-asr-std", care: "Attack-blocking rules are off", name: "Attack-blocking rules on", ok: !missing.length, how: "asrStd", asrFix: missing.length ? missing : null,
      note: missing.length ? `Not blocking yet: ${missing.map((id) => ASR_NAMES[id]).join(", ")}.`
        : "Blocks password theft from memory, bad drivers, and hidden restart hooks - Microsoft's three standard rules.",
      deep: deepAsr });
  }
  row(Array.isArray(x.wmiHooks), { id: "deep-wmi", care: "A hidden script hook is set", name: "No hidden script hooks", ok: !x.wmiHooks?.length, how: "wmi",
    note: x.wmiHooks?.length ? `${plural(x.wmiHooks.length, "hook runs", "hooks run")} something by itself when Windows events happen: ${x.wmiHooks.map((h) => h.name).join(", ")}. Malware uses this to come back after every restart without a file in any start-up list.`
      : "Nothing is set to run secretly when Windows events happen.",
    deep: (x.wmiHooks || []).map((h) => `${h.kind} ${h.name}: ${h.runs}`).join("; ") || "no CommandLine/ActiveScript event consumers" });
  row(Array.isArray(x.oddServices), { id: "deep-services", care: "An unsigned background service", name: "Background services all signed", ok: !x.oddServices?.length, how: "services",
    note: x.oddServices?.length ? `${x.oddServices.map((v) => `“${v.display || v.name}”`).join(", ")} ${x.oddServices.length === 1 ? "runs" : "run"} from a user folder with no maker's signature - a common hiding place for malware that starts with Windows.`
      : "No background service runs unsigned from a folder ordinary programs can write to.",
    deep: (x.oddServices || []).map((v) => `${v.name} (${v.state}) ${v.path} signature=${v.signature}`).join("; ") || "none" });
  row(x.secureBoot != null, { id: "deep-secureboot", care: "Secure Boot is off", name: "Safe start-up (Secure Boot)", ok: x.secureBoot === 1, how: "secureboot",
    note: x.secureBoot === 1 ? "Stops anything sneaking in before Windows starts." : "Something could sneak in before Windows starts.", deep: `UEFISecureBootEnabled=${x.secureBoot}` });
  const bk = backupDose(x.backup);
  if (bk) out.push(bk);
  return out.concat(softwareDose(s));
}

// Backups (extra.ps1 "backup"; report only). A folder counts as copied only when it sits inside a
// SIGNED-IN OneDrive account's folder, or File History is on. Inside a OneDrive folder with nobody
// signed in = "stranded": it looks backed up and is copied nowhere (the owner's laptop, 24 Sep).
const FOLDER_NAMES = { Desktop: "Desktop", Personal: "Documents", "My Pictures": "Pictures" };
function backupDose(b) {
  if (!b) return null;
  const norm = (p) => String(p || "").toLowerCase().replace(/[\\/]+$/, "");
  const inside = (p, root) => { const r = norm(root); return !!r && (norm(p) === r || norm(p).startsWith(r + "\\")); };
  const order = Object.keys(FOLDER_NAMES);
  const entries = Object.entries(b.folders || {}).sort(([a], [c]) => order.indexOf(a) - order.indexOf(c));
  const accts = b.oneDriveAccounts || [];
  const synced = entries.filter(([, p]) => accts.some((a) => inside(p, a.folder)));
  const looksOneDrive = (p) => (b.oneDriveRoots || []).some((r) => inside(p, r)) || /\\onedrive( - [^\\]+)?\\/i.test(norm(p) + "\\");
  const stranded = entries.filter(([n, p]) => !synced.some(([m]) => m === n) && looksOneDrive(p));
  const fh = b.fileHistory === true;
  const names = (l) => l.map(([n]) => FOLDER_NAMES[n] || n).join(", ");
  const deepText = `folders: ${entries.map(([n, p]) => `${n}=${p}`).join("; ") || "unread"}. OneDrive accounts: ${accts.map((a) => `${a.name}=${a.folder}`).join("; ") || "none signed in"}. OneDrive running=${b.oneDriveRunning}. File History=${b.fileHistory}. `
    + "OneDrive syncing is a copy, not a vault: ransomware-scrambled files sync too, but OneDrive keeps earlier versions to restore from. Free OneDrive holds 5 GB.";
  const base = { id: "deep-backup", name: "Your files have a copy elsewhere", deep: deepText };
  if (stranded.length && !b.oneDriveRunning) return { ...base, ok: false, how: "backupStranded", care: "Your files look backed up but aren't",
    note: `Your ${names(stranded)} sit in a OneDrive folder, but OneDrive is signed out - so nothing is being copied. If the laptop broke or ransomware struck, they'd be gone.` };
  if (synced.length || fh) {
    const parts = [];
    if (synced.length) parts.push(`OneDrive keeps a copy of your ${names(synced)}${b.oneDriveRunning ? "" : " (open OneDrive now and then so the copy stays fresh - it isn't running right now)"}`);
    if (fh) parts.push("File History is set up to copy your files to another drive");
    return { ...base, ok: true, how: "backup", note: parts.join(". ") + "." };
  }
  // Not seen is not "none": another backup app or an external disk is invisible from here.
  if (stranded.length) return { ...base, manual: true, how: "backupStranded",
    note: `Your ${names(stranded)} sit in OneDrive and OneDrive is running, but I couldn't see it signed in. Check its cloud icon near the clock shows no warning, then tap to stamp.` };
  return { ...base, manual: true, how: "backup",
    note: "I found no OneDrive or File History copy of your photos and documents. If the laptop broke or ransomware struck, a copy elsewhere is the one cure. Already use another backup (Google Drive, an external disk)? Tap to stamp it." };
}

// Installed programs whose old versions were used in real attacks (software.ps1; cut-offs and
// their sources are in that file). Unreadable list = no row; an unreadable VERSION is said, not graded.
const SW_NAMES = { winrar: "WinRAR", "7zip": "7-Zip", java: "Java" };
function softwareDose(s) {
  const sw = s.software;
  if (!sw || !sw.ok) return [];
  const items = sw.items || [];
  const old = items.filter((i) => i.old === true);
  const unsure = items.filter((i) => i.old == null && i.minSafe);
  const java = items.filter((i) => i.id === "java");
  // "7.12.0" -> "7.12", "24.08" stays "24.08" (the text as people see it, not the parsed number)
  const shown = (i) => (/\d+\.\d+/.exec(i.version) || /\d+\.\d+/.exec(i.name.slice(SW_NAMES[i.id].length)) || [i.parsed])[0];
  const oldIds = [...new Set(old.map((i) => i.id))];
  let note;
  if (old.length) note = `Old ${oldIds.map((id) => `${SW_NAMES[id]} (${old.filter((i) => i.id === id).map(shown).join(", ")})`).join(" and ")} - criminals have broken into computers through these versions. Update to ${oldIds.map((id) => `${SW_NAMES[id]} ${old.find((i) => i.id === id).minSafe}`).join(" and ")} or newer.`;
  else if (items.some((i) => i.minSafe)) note = `${[...new Set(items.filter((i) => i.old === false).map((i) => SW_NAMES[i.id]))].join(" and ") || "They"} ${items.filter((i) => i.old === false).length === 1 ? "is" : "are"} new enough to be safe from the known attacks.`;
  else note = "No WinRAR or 7-Zip installed - two programs attackers broke in through.";
  if (unsure.length) note += ` I couldn't read the version of ${unsure.map((i) => i.name).join(", ")} - update ${unsure.length === 1 ? "it" : "them"} to be sure.`;
  if (java.length) note += ` ${java.map((i) => i.name).join(", ")} is installed - most people no longer need Java at all; remove it if nothing you use asks for it.`;
  return [{
    id: "deep-software", care: "An old program has known break-in holes", name: "No old programs attackers use", ok: !old.length, how: "software",
    links: oldIds.map((id) => ({ url: old.find((i) => i.id === id).url, open: `Open the ${SW_NAMES[id]} download page` })),
    note,
    deep: `${sw.read} programs read. ${items.map((i) => `${i.name} v${i.version} parsed=${i.parsed} min=${i.minSafe} old=${i.old} ${i.cve || ""} (${i.scope})`).join("; ") || "none of WinRAR / 7-Zip / Java JRE"}`,
  }];
}

// Which antivirus is actually guarding the laptop. On a home PC with McAfee/ESET/Norton etc.,
// Windows switches Defender off by itself ("Disabled mode", learn.microsoft.com, read 25 Sep
// 2026): normal, not a hole. Then Defender's own rows (tamper lock, virus-list age) and
// Defender's scans say nothing about the laptop's real protection.
function avPicture(s) {
  const d = s?.defender || {};
  const defOn = !!(d.available && d.realTime && !/passive|not running|sxs/i.test(d.mode || ""));
  const other = (s?.extra?.otherAv || []).find((a) => a.on) || null;
  return { known: !!s, defOn, other, otherPrimary: !defOn && !!other };
}

function laptopDoses(s) {
  const d = s.defender || {};
  const av = avPicture(s);
  const fw = s.firewall || [];
  const ss = s.smartscreen || {};
  const uac = s.uac || {};
  const ssOn = ss.policy === 1 || (ss.policy == null && ss.setting !== "Off");
  const updAge = ageDays(s.lastUpdate);
  const shield = av.otherPrimary
    ? { id: "shield", care: `Virus shield (${av.other.name}) is out of date`, name: `Virus shield switched on (${av.other.name})`, ok: !av.other.outOfDate, how: "otherav",
      note: av.other.outOfDate ? `${av.other.name} is on but its virus list is old - open ${av.other.name} and update it.`
        : `${av.other.name} checks every file as it arrives. Windows switched Defender off by itself because ${av.other.name} is on - that is normal.`,
      deep: `Primary antivirus ${av.other.name} productState=${av.other.state} outOfDate=${av.other.outOfDate}; Defender available=${d.available} realTime=${d.realTime} mode=${d.mode}` }
    : { id: "shield", care: "Virus shield is off", name: "Virus shield switched on", ok: av.defOn, how: "defender",
      note: "Windows Defender checks every file as it arrives.", deep: `Defender available=${d.available} realTime=${d.realTime} mode=${d.mode}` };
  return [
    shield,
    // Defender's own lock and list: meaningless (and would go stale red) while another antivirus is the one on duty.
    ...(av.otherPrimary ? [] : [{ id: "tamper", care: "Programs could switch the shield off", name: "Shield locked against switch-off", ok: !!d.tamper, how: "defender",
      note: "A bad program can't quietly turn the shield off.", deep: `IsTamperProtected=${d.tamper}` },
    { id: "sigs", care: "Virus list is out of date", name: "Virus list fresh", ok: d.signatureAgeDays != null && d.signatureAgeDays <= 3, how: "update",
      note: d.signatureAgeDays == null ? "Couldn't read its age." : d.signatureAgeDays === 0 ? "Updated today." : `Updated ${plural(d.signatureAgeDays, "day", "days")} ago.`,
      deep: `AntivirusSignatureAge=${d.signatureAgeDays} (given if <= 3)` }]),
    { id: "fw", care: "Firewall is off on a network", name: "Firewall on for every network", ok: fw.length > 0 && fw.every((f) => f.enabled), how: "firewall",
      note: "The gatekeeper for your internet connection.", deep: fw.map((f) => `${f.name}=${f.enabled ? "on" : "OFF"}`).join(" ") || "no firewall profiles read" },
    { id: "smartscreen", care: "Unknown-program filter is off", name: "Unknown-program filter on", ok: ssOn, how: "smartscreen",
      note: "Warns before you run a program nobody has vouched for.", deep: `policy EnableSmartScreen=${ss.policy} level=${ss.level} setting=${ss.setting}` },
    { id: "uac", care: "Windows doesn't ask before big changes", name: "Asks before big changes", ok: uac.enabled === 1 && uac.adminPrompt !== 0, how: "uac",
      note: "Windows asks you “Do you want to allow this?” before anything changes the system.", deep: `EnableLUA=${uac.enabled} ConsentPromptBehaviorAdmin=${uac.adminPrompt}` },
    { id: "updates", care: "Windows hasn't updated recently", name: "Windows updated recently", ok: updAge <= 35, how: "update",
      note: s.lastUpdate ? `Last update installed ${fmtDate(s.lastUpdate)}.` : "Couldn't find an installed update.", deep: `newest hotfix ${s.lastUpdate} (given if <= 35 days)` },
  ];
}

const FIXABLE = ["chrome", "edge", "brave", "firefox"];
function browserDoses(s) {
  return (s.browsers || []).filter((b) => b.installed).map((b) => {
    const v = (x) => (x && typeof x === "object" ? x.value : x);
    let ok, note, deepText;
    if (b.kind === "chromium") {
      ok = v(b.safeBrowsing) === 2 && v(b.downloads) >= 1;
      note = ok ? "Enhanced safe browsing and download blocking are on." : "Safe browsing isn't set to its strongest level yet.";
      deepText = `SafeBrowsingProtectionLevel=${v(b.safeBrowsing)} (${b.safeBrowsing?.scope ?? "-"}) DownloadRestrictions=${v(b.downloads)} DnsOverHttpsMode=${v(b.doh)} PasswordManagerEnabled=${v(b.passwords)}`;
    } else if (b.kind === "edge") {
      ok = v(b.safeBrowsing) === 1 && v(b.downloads) >= 1;
      note = ok ? "SmartScreen and download blocking are on." : "Edge's SmartScreen filter isn't locked on yet.";
      deepText = `SmartScreenEnabled=${v(b.safeBrowsing)} SmartScreenPuaEnabled=${v(b.safeBrowsingPua)} DownloadRestrictions=${v(b.downloads)} DnsOverHttpsMode=${v(b.doh)}`;
    } else if (b.kind === "firefox") {
      ok = b.doh === true;
      note = ok ? "Safe lookups (secure DNS) are on." : "Secure DNS isn't switched on yet.";
      deepText = `policies.json present=${b.hasPolicyFile} DNSOverHTTPS=${b.doh} PasswordManagerEnabled=${b.passwords}`;
    } else {
      return { id: "br-" + b.id, name: b.name, manual: true, how: "opera", note: "I can't change this browser myself - I'll show you where the switch is.", deep: "no policy support" };
    }
    return { id: "br-" + b.id, name: b.name, ok, fixable: FIXABLE.includes(b.id), browser: b.id, note, deep: deepText };
  }).concat(cardDose(s));
}

// Bank cards kept inside browsers (a count from lib.rs cards.rs - never the cards themselves).
// Password stealers copy these; a browser setting stops NEW ones, but saved ones must be removed by hand.
function cardDose(s) {
  const list = (s.cards?.browsers || []).filter((b) => b.cards != null);
  if (!list.length) return []; // nothing readable: no row, never a false "all clear"
  const holding = list.filter((b) => b.cards > 0);
  const total = holding.reduce((n, b) => n + b.cards, 0);
  return [{
    id: "br-cards", care: "Bank cards are saved in your browser", name: "No bank cards kept in browsers", ok: !total, how: "cards", holding,
    note: total
      ? `${holding.map((b) => `${b.name} keeps ${plural(b.cards, "card", "cards")}`).join(", ")}. Password-stealing programs copy saved cards - remove them.`
      : "No browser on this laptop keeps a bank card.",
    deep: list.map((b) => `${b.id}: ${b.cards} in ${b.read}/${b.profiles} profiles${b.errors?.length ? ` (unreadable: ${b.errors.length})` : ""}`).join("; "),
  }];
}

const ACCOUNTS = [
  { id: "acc-google-devices", name: "Google: devices signed in", url: "https://myaccount.google.com/device-activity",
    steps: ["Open the page", "Look at every device", "Tap one you don't know", "Sign out"], look: "a phone, computer or city that isn't yours" },
  { id: "acc-google-apps", name: "Google: apps with access", url: "https://myaccount.google.com/connections",
    steps: ["Open the page", "Look at each app", "Tap one you never connected", "Delete all connections"], look: "an app or website you don't remember connecting" },
  { id: "acc-gmail-fwd", name: "Gmail: forwarding and filters", url: "https://mail.google.com/mail/u/0/#settings/fwdandpop",
    steps: ["Open the page", "Forwarding should be disabled", "Open the Filters tab", "Delete filters you didn't make"], look: "your mail being forwarded, or filters that hide bank or security emails" },
  { id: "acc-gmail-delegates", name: "Gmail: who else can read it", url: "https://mail.google.com/mail/u/0/#settings/accounts",
    steps: ["Open the page", "Find “Grant access to your account”", "It should list nobody", "Remove anyone you don't know"], look: "any name listed there that you didn't add" },
  { id: "acc-whatsapp", name: "WhatsApp: linked devices", phone: true,
    steps: ["Open WhatsApp on your phone", "Tap ⋮ (top right) - on an iPhone, tap Settings instead", "Linked devices", "Tap any you don't know → Log out"], look: "a computer or browser you don't use" },
  { id: "acc-telegram", name: "Telegram: active sessions", phone: true,
    steps: ["Open Telegram", "Settings", "Devices", "Terminate all other sessions"], look: "a device or place you don't recognise" },
  { id: "acc-instagram", name: "Instagram: where you're logged in", url: "https://accountscenter.instagram.com/password_and_security/",
    steps: ["Open the page", "Where you're logged in", "Look at each one", "Log out of strangers"], look: "a phone or city that isn't yours" },
  { id: "acc-facebook", name: "Facebook: where you're logged in", url: "https://accountscenter.facebook.com/password_and_security/",
    steps: ["Open the page", "Where you're logged in", "Look at each one", "Log out of strangers"], look: "a phone or city that isn't yours" },
  { id: "acc-microsoft", name: "Microsoft: recent sign-ins", url: "https://account.live.com/Activity",
    steps: ["Open the page", "Read the recent sign-ins", "Any strange place?", "“Secure your account”"], look: "a sign-in from a country or device that isn't you" },
  { id: "acc-leaks", name: "Leaked passwords check", url: "https://passwords.google.com/checkup",
    steps: ["Open the page", "Check passwords", "Change each one marked leaked", "Email and bank first"], look: "passwords marked “compromised”" },
];

function pastDoses(s) {
  // A count Defender did not give is "not read", never 0 (31 Oct 2026: `?? 0` turned a failed read green).
  const unread = !!s && typeof s.threatCount !== "number";
  const n = s && !unread ? s.threatCount : null;
  return [
    { id: "past-reviewed", name: "Old infections reviewed", manual: n !== 0, ok: n === 0 ? true : undefined,
      note: n === 0 ? "Defender has caught nothing on this laptop." : unread ? "I couldn't read Defender's record - tap “Was I hacked before?”" : n == null ? "Tap “Was I hacked before?”" : `Defender has ${plural(n, "old record", "old records")} - look at them once.` ,
      deep: `Get-MpThreatDetection count=${n}` },
    ...(s ? sweepDoses(s) : []),
    ...(s && !PHONE ? [folderRow()] : []),
    ...ACCOUNTS.map((a) => ({ id: a.id, name: a.name, manual: true, note: a.phone ? "On your phone" : "One web page", acc: a })),
  ];
}

// "Every file scanned" is given only by Defender's own record of a full scan that finished after
// Vigil started it and caught nothing (sweepClean). Running, stopped or never = due; caught = open.
// With another antivirus on duty Defender can't scan, so the row becomes a tick after its own scan.
function sweepDoses(s) {
  const av = avPicture(s);
  const second = { id: "sweep-second", name: "Second scanner checked too", manual: true, flow: () => GO.second().run(),
    note: "A free scanner from a different company, once", deep: "manual tick; guide = answers.js second-opinion" };
  if (av.otherPrimary) return [{ id: "sweep-full", name: `Every file scanned (by ${av.other.name})`, manual: true, flow: sweepIntro,
    note: `Run a full scan inside ${av.other.name}, then tap the circle.`, deep: "Defender is off (another antivirus is primary): its full scan can't run" }, second];
  const w = sweepGet();
  const caught = !!(w?.fullEnd && w.found > 0);
  const note = sweepRunning(w) ? `Defender is opening every file now (started ${hm(w.started)}).`
    : caught ? `Defender's full scan on ${fmtDate(w.fullEnd)} caught ${plural(w.found, "thing", "things")}. Open Windows Security → Protection history.`
    : sweepClean(w) ? `Defender opened every file on ${fmtDate(w.fullEnd)} and found nothing.`
    : w?.unread ? "The last full scan finished, but its result couldn't be read - see Windows Security."
    : w?.stopped ? "The last full scan stopped before it finished - start it again."
    : w?.fullEnd ? `The last full scan was over ${SWEEP_DAYS} days ago - scan again.`
    : "Not done yet - Defender opens every file once (1 to 2 hours).";
  return [{ id: "sweep-full", name: "Every file scanned", care: "The full scan caught something", ok: sweepClean(w) ? true : caught ? false : undefined,
    when: w?.fullEnd, note, flow: sweepIntro, deep: `vv.sweep ${JSON.stringify(w || {})}` }, second];
}

// Each dose resolves to given / due / open.
// Laptop: every file in Downloads, Desktop and Temp against the known-malware list and the YARA
// rules (25 Sep, his tap "Laptop folder sweep"; check_folders). Run after each checkup, not
// awaited: the first run reads every file there, later runs only new or changed ones.
async function refreshFolders(set) {
  if (state.foldersRunning) return null;
  state.foldersRunning = true;
  renderCard();
  const stop = watchProgress("files", PHONE ? "phone storage" : "your folders", set, "d-folders");
  let f;
  try { f = await invokeOnce("check_folders", undefined, "files"); } catch (e) { f = { checked: false, error: String(e) }; }
  finally { state.foldersRunning = false; stop(); }
  if (f.busy) return null;
  const before = state.folders;
  state.folders = { ...f, time: new Date().toISOString() };
  renderCard();
  // A new catch is said at once, whatever the person is doing (the card alone could be missed).
  const had = new Set(folderBad(before).map((x) => x.path));
  const fresh = folderBad(f).filter((x) => !had.has(x.path));
  f.said = fresh.length > 0;
  if (fresh.length) {
    say(`<p><b>Stop - I found ${fresh.length === 1 ? "a harmful file" : `${fresh.length} harmful files`} on this ${DEVICE}.</b> Don't open ${fresh.length === 1 ? "it" : "them"}.</p>`
      + fresh.slice(0, 6).map(folderSlip).join(""),
      { choices: [{ label: "Show me how", kind: "main", run: () => showHow([folderRow()], 0) }, { label: "Not now", kind: "quiet", run: bye }] });
  }
  return f;
}
// A catch is "harmful" only on strong evidence. `weak` (from Rust) = only a loose pattern, or a
// list hit on short plain text - 26 Sep 2026 his own shortcuts and a stock Vite template were
// called harmful. Those are "worth a look": listed on the row, never shouted, never "delete".
const folderBad = (f) => [...(f?.found || []).filter((x) => !x.weak), ...(f?.blocked || []).map((b) => ({ ...b, blocked: true }))];
const folderLook = (f) => (f?.found || []).filter((x) => x.weak);
// A fingerprint hit can also be one of the Echap stalkerware samples the app ships (29 Sep); the
// look-up then names the app (`stalkerware`). Never credit MalwareBazaar's list with that find.
const spyFile = (name) => `Its exact file is ${name}, a known spy app (stalkerware): its fingerprint is on the Echap list of spy-app samples. Once installed it secretly sends messages, calls, photos and location to whoever put it there.`;
const FOLDER_TREAT = PHONE
  ? "Delete it: open the Files app, find it (the path is above), press and hold it, then Delete. If you ever installed or opened it, run “Check my phone” again and change your Google, WhatsApp and bank passwords from another device."
  : "Delete it: select it in File Explorer and press Shift+Delete. If you ever opened or ran it, press “Scan everything”, then change your email and bank passwords from another device.";
// Vigil's own checks (deeplook.rs, 29 Sep) send `why`: plain words per rule, shown instead of a rule name.
const ownWhy = (x) => (x.why || []).filter(Boolean);
function folderLookWords(all) {
  if (!all.length) return "";
  const own = all.filter((x) => ownWhy(x).length);
  const look = all.filter((x) => !ownWhy(x).length);
  const parts = [];
  if (look.length) {
    const lnk = look.filter((x) => /\.lnk$/i.test(x.name)).length;
    const listed = look.filter((x) => x.listWeak).length;
    const why = [lnk ? `${plural(lnk, "shortcut starts", "shortcuts start")} a script or a web address` : "",
      listed ? `${plural(listed, "short text file is", "short text files are")} on the list only because ordinary templates get uploaded next to malware` : ""].filter(Boolean);
    parts.push(`${plural(look.length, "file only matched a loose pattern", "files only matched loose patterns")}${why.length ? `: ${why.join("; ")}` : ""}. That is common in ordinary files, so I'm not calling ${look.length === 1 ? "it" : "them"} harmful.`);
  }
  if (own.length) {
    parts.push(`${plural(own.length, "file is", "files are")} worth a look, not harmful.`);
  }
  // 29 Sep 2026, his tap "One folded line": his laptop gave ~300 of these, so names and paths go
  // in one folded list (folderLookFold), never into this sentence.
  parts.push(`Each one is in the folded list “${plural(all.length, "file", "files")} worth a look”, with what it is. If you don't recognise ${all.length === 1 ? "it" : "one"}, check it with “Is this safe?”.`);
  return parts.join(" ");
}
// Why a loose find is only worth a look, in words (the rule names mean nothing to him).
function lookWhy(x) {
  if (ownWhy(x).length) return ownWhy(x).join(" ");
  if (/\.lnk$/i.test(x.name)) return "A shortcut that starts a script or a web address - ordinary shortcuts do this too.";
  if (x.listWeak) return "A short text file on the malware list only because ordinary templates get uploaded next to malware.";
  return `It matched a loose pattern (${(x.rules || []).map((r) => r.rule).join(", ") || "a list entry"}) that ordinary files match too.`;
}
// Every weak find in ONE folded line that opens to the list; harmful finds stay loud elsewhere.
const LOOK_SHOWN = 200;
function folderLookFold(f) {
  const all = folderLook(f);
  if (!all.length) return "";
  return `<details class="look-fold"><summary>${esc(plural(all.length, "file", "files"))} worth a look</summary><ul>`
    + all.slice(0, LOOK_SHOWN).map((x) => `<li><b>${esc(x.name)}</b> <code>${esc(x.path)}</code> ${esc(lookWhy(x))}</li>`).join("")
    + `</ul>${all.length > LOOK_SHOWN ? `<p>And ${esc((all.length - LOOK_SHOWN).toLocaleString("en-IN"))} more like these.</p>` : ""}</details>`;
}
// The online fingerprint look-up (hashonline.rs; his tap 29 Sep 2026: "fingerprints only").
// `o` = {ran, asked, remembered, bad, known, unknown, failed, notAsked, error}. Empty when nothing was asked.
// Plain text: callers escape it.
function onlineNote(o) {
  const asked = Number(o?.asked || 0) + Number(o?.remembered || 0);
  if (!o?.ran || !asked) return "";
  const n = (x) => Number(x || 0).toLocaleString("en-IN");
  const got = asked - Number(o.failed || 0);
  return ` I also asked a free public checker (CIRCL) about ${plural(asked, "fingerprint", "fingerprints")} of files no list knew - only the fingerprints left this ${DEVICE}, never the files.`
    + (got ? ` ${o.bad ? `${n(o.bad)} known as malware` : "None is known as malware"}${o.known ? `; ${n(o.known)} known as ordinary files` : ""}${o.unknown ? `; ${n(o.unknown)} never seen (normal for your own and brand-new files)` : ""}.` : "")
    + (o.failed ? ` ${n(o.failed)} could not be asked (${o.error || "no answer"}).` : "")
    + (o.notAsked ? ` ${n(o.notAsked)} more wait for the next check.` : "");
}
function folderSlip(x) {
  const rules = (x.rules || []).map((r) => r.rule).join(", ");
  const other = (x.rules || []).filter((r) => r.set !== "Vigil").map((r) => r.rule).join(", ");
  const what = x.blocked ? "Windows refused to open it because Defender says it is a virus - Defender has caught it, but the file is still in this folder."
    : ownWhy(x).length ? [x.list ? (x.stalkerware ? spyFile(x.stalkerware) : "Its exact file is on MalwareBazaar's public list of malware samples.") : "", ownWhy(x).join(" "),
      other ? `It also matches rules written to recognise known malware (${other}).` : ""].filter(Boolean).join(" ")
    : x.list && x.stalkerware ? [spyFile(x.stalkerware), rules ? `Its contents also match malware rules (${rules}).` : ""].filter(Boolean).join(" ")
    : x.list && rules ? `Its exact file is on MalwareBazaar's public list of malware samples, AND its contents match malware rules (${rules}).`
    : x.list ? "Its exact file is on MalwareBazaar's public list of malware samples - not a guess: this very file has been caught doing harm before."
    : `Its contents match rules written to recognise known malware (${rules}). Strong evidence, not proof - a few safe tools look alike.`;
  const said = x.online ? `${what} Reported by: ${x.online}.` : what;
  return `<article class="slip sev-severe"><div class="slip-head"><span class="slip-label">DIAGNOSIS</span><b>${esc(x.name)}</b><span class="slip-count">${esc(x.root || "")}</span></div>`
    + `<p><b>Where:</b> <code>${esc(x.path)}</code></p><p><b>What it is:</b> ${esc(said)}</p><p><b>Treatment:</b> ${esc(FOLDER_TREAT)}</p></article>`;
}
function folderRow() {
  const f = state.folders;
  const base = PHONE
    ? { id: "d-folders", how: "p-folders", care: "A harmful file is on this phone", name: "Every file in phone storage swept" }
    : { id: "d-folders", how: "folders", care: "A harmful file is in your folders", name: "Downloads, Desktop and Temp swept" };
  if (f?.needsAccess && !state.foldersRunning) {
    return { ...base, when: null, flow: () => allowFiles(), flowLabel: "Allow and sweep",
      note: "Not swept yet: Android lets me read your Download folder, WhatsApp files and the rest only after you switch on “All files access” for Virus Vigil. I only read files to fingerprint them - nothing is changed, moved or sent.",
      deep: `check_folders: needsAccess (Android ${f.sdk ?? "?"}); Environment.isExternalStorageManager() false` };
  }
  if (!f || !f.checked) {
    return { ...base, when: null, flow: () => sweepFoldersNow(), flowLabel: "Sweep them now",
      note: state.foldersRunning ? "Reading every file there now - I'll tell you at once if one is harmful."
        : f?.error || f?.list?.error ? `Not swept: ${f.error || f.list.error}` : "Every file there against known malware - not done yet.",
      deep: `check_folders: ${JSON.stringify(f || null).slice(0, 300)}` };
  }
  const bad = folderBad(f);
  const L = f.list || {}, Y = f.yara || {};
  const where = (f.roots || []).map((r) => r.name).join(", ");
  const rules = parseInt(Y.tag, 10) || 0;
  let note;
  if (bad.length) {
    note = `${bad.slice(0, 3).map((x) => x.name).join(", ")}${bad.length > 3 ? ` and ${bad.length - 3} more` : ""} ${bad.length === 1 ? "is" : "are"} harmful. Delete ${bad.length === 1 ? "it" : "them"} - don't open. First one: ${bad[0].path}`;
  } else {
    note = `None of the ${f.files.toLocaleString("en-IN")} files in ${where} (${(f.bytes / 1e9).toFixed(1)} GB) `
      + (L.checked ? `is one of ${listSize(L)}${folderLook(f).some((x) => x.listWeak) ? ` - apart from the short text files mentioned below` : ""}` : "could be looked up (the known-malware list isn't downloaded yet)")
      + (Y.ran ? `, and ${Y.read.toLocaleString("en-IN")} of them were read by ${rules.toLocaleString("en-IN")} malware rules${Y.big ? ` (${Y.big.toLocaleString("en-IN")} files over ${Y.maxMb} MB, like videos, were fingerprinted only)` : ""}.` : `; the malware rules could not run (${Y.reason || "not ready"}).`)
      + (f.unread ? ` ${plural(f.unread, "file was", "files were")} in use and could not be read.` : "")
      + (f.phone && f.sealed ? ` Each app's private folder (Android/data) is sealed by Android from every other app, so those were not read - apps themselves were fingerprinted separately.` : "")
      + (f.skippedDirs ? ` ${plural(f.skippedDirs, "program-building folder was", "program-building folders were")} skipped (like node_modules or .git - libraries a programming tool fetched, not your downloads).` : "")
      // Newest first, so a capped sweep leaves the OLDEST files, and the next sweep starts from the
      // newest again - those files are not "left for later", they are not read. Said as such.
      + onlineNote(f.online)
      + (folderLook(f).length ? ` ${folderLookWords(folderLook(f))}` : "")
      + (f.capped ? ` ${f.left.toLocaleString("en-IN")} older files were not read${f.leftNewestMs ? ` (last changed on ${fmtDate(f.leftNewestMs)} or before)` : ""} - there are more files here than one sweep reads.` : "");
  }
  return { ...base, trustable: false, when: f.time, fold: bad.length ? "" : folderLookFold(f),
    ok: bad.length ? false : L.checked && Y.ran && !f.capped ? true : undefined,
    ...(bad.length ? {} : { flow: () => sweepFoldersNow(), flowLabel: "Sweep them again" }),
    note,
    deep: `check_folders: ${f.files} files read (${f.fresh} fresh, rest remembered), ${f.total} found in ${(f.roots || []).map((r) => `${r.name} ${r.files}`).join(", ")}; `
      + `list ${L.checked ? `${L.full ? L.count + " full" : L.recent + " recent only"}, ${L.ageHours ?? "?"} h old` : `not used (${L.error || "-"})`}; `
      + `YARA ${Y.ran ? `${rules} rules, ${Y.read} read, ${Y.big} over ${Y.maxMb} MB, ${Y.failed} failed` : `did not run (${Y.reason || "-"})`}; `
      + `unread ${f.unread}, cloud-only skipped ${f.cloud}, program-building folders skipped ${f.skippedDirs ?? "-"}, folders unlistable ${f.badDirs}, capped ${f.capped}, newest not read ${f.leftNewestMs ? new Date(f.leftNewestMs).toISOString() : "-"}, walk ${f.walkMs ?? "-"} ms of ${f.ms} ms. `
      + `Hits: ${bad.map((x) => `${x.path}${x.sha256 ? " " + x.sha256 : ""}${x.blocked ? " (blocked by Windows)" : ""}${(x.rules || []).length ? " rules " + x.rules.map((r) => r.set + "/" + r.rule).join(",") : ""}`).join("; ") || "none"}` };
}
async function sweepFoldersNow() {
  const live = thinkingLive(PHONE ? "Reading every file in phone storage..." : "Reading every file in Downloads, Desktop and Temp...");
  let f;
  try { f = await refreshFolders(live.set); }
  finally { live.done(); }
  if (!f) return say(`<p>That sweep is already running - I'll tell you here if it finds anything.</p>`);
  if (f.needsAccess) {
    return say(`<p>The switch is still off, so I can't read your phone's files yet. Android asks for “All files access” before any app may open another app's downloads.</p>`,
      { choices: [{ label: "Allow and sweep", kind: "main", run: allowFiles }, { label: "Not now", kind: "quiet", run: bye }] });
  }
  if (folderBad(f).length) { if (!f.said) showHow([folderRow()], 0); return; }
  say(`<p><b>${esc(folderRow().note)}</b></p>${folderLookFold(f)}<p>That took ${secsWords(f.ms || 0)}: ${Number(f.fresh || 0).toLocaleString("en-IN")} files read fresh, the rest remembered from last time (same file, same size, same date).</p>`,
    { choices: [{ label: "Check again", kind: "main", run: () => guarded(checkup) }, { label: "Read everything again from scratch", run: () => guarded(rereadAll) }, { label: "Not now", kind: "quiet", run: bye }] });
}
// Phone: the one switch Android needs before an app may read other apps' downloads (Android 11+).
async function allowFiles() {
  state.awaitFiles = true;
  say(`<p>I'll open the switch. Turn on <b>“Allow access to manage all files”</b> for Virus Vigil, then come back - I'll start the sweep by myself.</p><p>I only read files to fingerprint them. Nothing is changed, moved or sent anywhere.</p>`);
  await openPhoneSettings("allFiles");
}
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && state.awaitFiles) { state.awaitFiles = false; guarded(sweepFoldersNow); }
});
// "Read everything again from scratch": forget what was remembered, so every byte is read again.
async function rereadAll() {
  const r = await invoke("forget_fingerprints");
  state.known = null; state.folders = null;
  say(`<p>I forgot every remembered fingerprint (${esc((r.removed || []).join(", ") || "none were saved")}). Reading every byte again - this is the slow, full run.</p>`);
  if (PHONE) await phoneSweep(); else await sweepFoldersNow();
}

function doseState(d) {
  if (d.manual) return ticks[d.id] ? "given" : "due";
  if (d.ok === true) return "given";
  if (d.ok === false) return "open";
  return "due";
}

const CHECK = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5 10 17.5 19 7"/></svg>`;

function stampHtml(d, st) {
  const when = d.manual ? ticks[d.id] : d.when || state.scan?.time;
  if (st === "given") {
    const inner = `${CHECK}<span class="d">${when ? stampDate(when) : ""}</span>`;
    return d.manual
      ? `<button type="button" class="stamp given" data-tick="${d.id}" title="Tap to undo">${inner}</button>`
      : `<span class="stamp given" title="On">${inner}</span>`;
  }
  if (st === "open") return `<span class="stamp open" title="Needs care">!<span class="d">fix</span></span>`;
  return d.manual
    ? `<button type="button" class="stamp due" data-tick="${d.id}" title="Tap when you've done this">tap</button>`
    : `<span class="stamp due">due</span>`;
}

function allDoses() {
  const s = state.scan;
  if (PHONE) return { laptop: s ? phoneDoses(s) : [], browsers: [], deeper: s ? appDoses(s) : [], past: phonePast(s) };
  const g = {
    laptop: s ? laptopDoses(s) : [],
    browsers: s ? [...browserDoses(s), ...addonDoses(state.addons)] : [],
    deeper: s ? deeperDoses(s) : [],
    past: pastDoses(s),
  };
  for (const d of [...g.laptop, ...g.deeper]) d.sysFix = sysFixOf(d);
  return g;
}

function renderCard(pressed) {
  const g = allDoses();
  const groups = [
    [PHONE ? "This phone" : "This laptop", g.laptop],
    ["Browsers", g.browsers],
    [PHONE ? "Apps" : "Deeper checks", g.deeper],
    [PHONE ? "Takeover signs & accounts" : "Old infections & accounts", g.past],
  ];
  let html = "";
  if (!state.scan) html += `<p class="card-empty">Not checked yet - press “Check my ${DEVICE}”.</p>`;
  for (const [title, doses] of groups) {
    if (!doses.length) continue;
    const given = doses.filter((d) => doseState(d) === "given").length;
    html += `<section class="dose-group"><h3><span>${esc(title)}</span><span class="count">${given}/${doses.length}</span></h3><ul class="doses">`;
    for (const d of doses) {
      const st = doseState(d);
      const guided = st !== "given" && hasGuide(d);
      const tag = guided ? `button type="button" class="dose-body" data-guide="${d.id}"` : `span class="dose-body"`;
      html += `<li class="dose${guided ? " guided" : ""}" data-state="${st}" data-id="${d.id}"><${tag}><span class="dose-name">${esc(d.name)}</span>`
        + (d.note ? `<span class="dose-note">${esc(d.note)}</span>` : "")
        + (d.deep ? `<span class="dose-note deep">${esc(d.deep)}</span>` : "")
        + (guided ? `<span class="dose-go">${doable(d) ? "I can fix this ›" : "Show me how ›"}</span>` : "")
        + `</${guided ? "button" : "span"}>${stampHtml(d, st)}${d.fold || ""}</li>`;
    }
    html += `</ul></section>`;
  }
  $("#card-body").innerHTML = html;
  if (pressed) $(`#card-body [data-id="${pressed}"] .stamp`)?.classList.add("press");
  $("#card-date").textContent = state.scan ? fmtDate(state.scan.time) : "—";

  const flat = [...g.laptop, ...g.browsers, ...g.deeper, ...g.past];
  const given = flat.filter((d) => doseState(d) === "given").length;
  const open = flat.filter((d) => doseState(d) === "open").length;
  const ring = $("#ring");
  const total = flat.length;
  ring.dataset.tone = !state.scan ? "idle" : open ? "care" : "good";
  $("#ring-given").textContent = state.scan ? given : "\u2013";
  $("#ring-total").textContent = state.scan ? total : "\u2013";
  $("#ring-arc").style.strokeDashoffset = String(263.9 * (1 - (state.scan && total ? given / total : 0)));
  document.querySelector(".pass").classList.toggle("care", !!open);
  $("#strip-count").textContent = state.scan ? `${given} of ${flat.length} done` + (open ? ` · ${open} need care` : "") : "not checked yet";
}

function setTick(id, on) {
  if (on) ticks[id] = new Date().toISOString();
  else delete ticks[id];
  store.set("vv.ticks", ticks);
  renderCard(on ? id : null);
}
$("#card-body").addEventListener("click", (e) => {
  const b = e.target.closest("[data-tick]");
  if (b) return setTick(b.dataset.tick, !ticks[b.dataset.tick]);
  const g = e.target.closest("[data-guide]");
  if (!g || state.busy) return;
  const d = Object.values(allDoses()).flat().find((x) => x.id === g.dataset.guide);
  if (!d) return;
  document.body.classList.remove("card-open");
  $("#card-strip").setAttribute("aria-expanded", "false");
  you(d.care || d.name);
  guide(d);
});

// A tap on any row that isn't done. The app does it itself when it can (browser fixer);
// otherwise Vigil walks through the steps. Every not-done row must land somewhere here.
function hasGuide(d) {
  return !!(doable(d) || d.flow || HOWTO[d.how] || d.acc || d.id === "past-reviewed");
}
function guide(d) {
  if (d.fixable) return fixFlow([d]);
  if (d.asrFix) return asrFlow(d);
  if (d.sysFix) return allFlow([d]);
  if (d.flow) return guarded(d.flow);
  if (d.acc) return sweep(ACCOUNTS.indexOf(d.acc), true);
  if (d.id === "past-reviewed") return guarded(hacked);
  if (d.manual && d.id.startsWith("br-")) return showManual(d);
  showHow([d], 0);
}
$("#card-strip").addEventListener("click", () => {
  const open = document.body.classList.toggle("card-open");
  $("#card-strip").setAttribute("aria-expanded", String(open));
});

// ---------- 1. Check my laptop ----------
const pathHtml = (steps) => `<ol class="path">${steps.map((s, i) => `<li><span class="n">${i + 1}</span>${esc(s)}</li>`).join("")}</ol>`;

async function checkup() {
  if (PHONE) return phoneCheckup();
  const t0 = performance.now();
  const done = thinking("Checking this laptop - a few seconds...");
  // The add-on check runs alongside. It must never hold up or break the checkup: a failure
  // just means no add-on row, and if it finishes after the summary the card catches up.
  const addons = invoke("extension_audit").then((r) => { state.addons = r; renderCard(); }, () => {});
  let s;
  try { s = await invoke("scan_system"); await Promise.race([addons, new Promise((ok) => setTimeout(ok, 8000))]); }
  finally { done(); }
  state.scan = s;
  state.checkMs = performance.now() - t0;
  // Not awaited: the first sweep reads every file in Downloads, Desktop and Temp; the card and chat
  // update when it is done.
  refreshFolders();
  renderCard();
  summarize();
}

function summarize() {
  const g = allDoses();
  const auto = [...g.laptop, ...g.browsers, ...g.deeper].filter((d) => !d.manual);
  const openAuto = auto.filter((d) => doseState(d) === "open");
  // A red row in the "past" group (harmful files in the folders, a full scan that caught something)
  // is not a protection to count, but it must never sit under "All protections are on" (26 Sep:
  // a later summary said exactly that while the folder sweep had found 3 harmful files).
  const pastOpen = g.past.filter((d) => !d.manual && doseState(d) === "open");
  const open = [...pastOpen, ...openAuto];
  const given = auto.length - openAuto.length;
  const doables = open.filter(doable);
  const manualBrowsers = g.browsers.filter((d) => d.manual && !ticks[d.id]);
  const others = open.filter((d) => !doable(d));

  // His rule 25 Sep 13:50: the confident all-clear only once EVERY row on the card is given - which
  // on a laptop includes "Every file scanned" (Defender's own record, clean) and the second scanner.
  const every = [...g.laptop, ...g.browsers, ...g.deeper, ...g.past];
  // On a phone a check Android refused has NO row, so "every row given" alone could pass with it missing.
  const phoneMissing = PHONE ? phoneUnchecked(g.deeper.map((d) => d.id)) : [];
  const allClear = every.length > 0 && every.every((d) => doseState(d) === "given") && !phoneMissing.length;
  const sweepOffer = sweepDue();

  let html = PHONE && state.checkMs != null ? phoneVerdict() : "";
  if (allClear) {
    // 29 Sep 2026 (LEGAL-CHECK.md O3): say what was measured, never promise protection - a false
    // guarantee is a "misleading advertisement" under the Consumer Protection Act 2019 s.2(28).
    html += `<p><b>No threats found in anything I checked on this ${DEVICE}.</b></p>`
      + `<p>Every one of the ${every.length} rows on your card is done${PHONE || (state.scan && avPicture(state.scan).otherPrimary) ? "" : ", and Windows Defender opened every file and found nothing"}. I'll keep an eye on it - check again after anything unusual. No app can promise a ${DEVICE} is 100% safe: new threats appear every day.</p>`;
  } else if (!open.length) {
    html += `<p><b>All ${auto.length} protections I can check are on.</b> I've stamped them on your card.</p>`;
  } else {
    html += `<p><b>${openAuto.length ? `${given} of ${auto.length} protections are on.` : `All ${auto.length} protections I can check are on - but`}</b> ${plural(open.length, "thing needs", "things need")} care:</p><ul>`
      + open.map((d) => `<li><b>${esc(d.care || d.name)}</b> - ${esc(d.note)}</li>`).join("") + `</ul>`;
    if (doables.length) html += `<p>I can do ${doables.length === open.length ? (open.length === 1 ? "it" : "all of them") : `${doables.length} of them`} for you, behind one Windows Yes box.</p>`;
  }
  const todo = [...g.laptop, ...g.browsers, ...g.deeper, ...g.past].filter((d) => doseState(d) === "due").length - manualBrowsers.length;
  if (sweepOffer) html += `<p><b>First, let's scan every file on this laptop once</b> - so we know nothing harmful is here right now.</p>`;
  if (todo > 0 && !allClear) html += `<p>Your pass also has ${plural(todo, "check", "checks")} we do together, like your accounts - the empty circles.</p>`;
  if (manualBrowsers.length) html += `<p>${manualBrowsers.map((d) => esc(d.name)).join(", ")} can't be set from outside - I'll show you the switch.</p>`;
  html += checkupChecked(g);
  html += deep(auto.map((d) => `<b>${esc(d.id)}</b> ${doseState(d)} - ${esc(d.deep)}`).join("<br>"));

  const c = [];
  // His idea 7 Oct 2026: one opt-in button that does every step Vigil would otherwise hand over -
  // the settings behind one Windows Yes box, then the full scan. allFlow asks before anything changes.
  if (doables.length) c.push({ label: doables.length > 1 ? "Do it all for me" : "Do it for me", kind: "main", run: () => allFlow(doables, { all: true }) });
  if (sweepOffer) c.push({ label: "Scan everything first", kind: doables.length ? undefined : "main", run: () => guarded(sweepIntro) });
  // Phone (his words 8 Oct 2026): Vigil does what Android allows, then walks through the rest one by one.
  const phoneAll = PHONE && (phoneHandRows().length > 0 || !!state.folders?.needsAccess);
  // A catch (known-malware app, harmful file) keeps its own "Show me how" as the main button, below.
  const urgent = PHONE && !!((state.known?.found || []).length || folderBad(state.folders).length);
  if (phoneAll) c.push({ label: "Do it all for me", kind: urgent ? undefined : "main", run: phoneAllFlow });
  if (PHONE && state.folders?.needsAccess) c.push({ label: "Allow and sweep", kind: phoneAll ? undefined : "main", run: allowFiles });
  // A "Stop" said during the checkup loses its buttons when this summary follows it (only the newest
  // choices stay), so a catch keeps its way out here, first (29 Sep, known.mjs caught it).
  if (PHONE) {
    const kf = state.known?.found || [], s = state.scan;
    if (kf.length && s) {
      const hits = kf.map((f) => (s.apps || []).find((a) => a.pkg === f.pkg) || { pkg: f.pkg, label: `${f.pkg} (came with the phone)` });
      c.unshift(...appButtons(hits), { label: "Show me how", kind: "main", run: () => showHow([knownRow(s)].filter(Boolean), 0) });
    } else if (folderBad(state.folders).length) {
      c.unshift({ label: "Show me how", kind: "main", run: () => showHow([folderRow()], 0) });
    }
  }
  if (others.length) c.push({ label: "Show me how to fix the rest", run: () => showHow(others, 0) });
  for (const d of manualBrowsers) c.push({ label: `Show me ${d.name}`, run: () => showManual(d) });
  c.push({ label: "Was I hacked before?", run: () => guarded(hacked) });
  c.push({ label: "More checks ›", run: moreChecks });
  if (state.offerUndo) { state.offerUndo = false; c.push({ label: "Undo my changes", kind: "quiet", run: () => guarded(undoFlow) }); }
  if (!open.length) c.push({ label: "That's all, thanks", kind: "quiet", run: bye });
  say(html, { choices: c });
}

// "What I checked" under a checkup: every row it read, by name, grouped as on the card, and how long
// it took. Shown once, right after a fresh checkup (state.checkMs is set only there).
function checkupChecked(g) {
  if (state.checkMs == null) return "";
  const ms = state.checkMs; state.checkMs = null;
  const read = (ds) => ds.filter((d) => !d.manual);
  const groups = [[PHONE ? "This phone" : "This laptop", read(g.laptop)], ["Browsers", read(g.browsers)], [PHONE ? "Apps" : "Deeper checks", read(g.deeper)]];
  const li = groups.filter(([, ds]) => ds.length).map(([t, ds]) => `<b>${esc(t)}</b>: ${ds.length} - <span class="names">${ds.map((d) => esc(d.name)).join(" · ")}</span>`);
  const a = state.addons;
  if (!PHONE && a?.list?.count > 0) li.push(`<b>Add-ons</b>: ${a.extensions?.length ?? addonGroups(a).all.length} in ${a.profilesRead || 0} browser profiles, against ${a.list.count.toLocaleString("en-IN")} known-bad ones`);
  const apps = PHONE && Array.isArray(state.scan?.apps) ? state.scan.apps.length : 0;
  if (apps) li.push(`<b>Every installed app</b> (${apps}) against ${SPY_LIST.apps} known spy apps`);
  const k = PHONE && state.known;
  const n0 = (x) => Number(x || 0).toLocaleString("en-IN");
  if (k?.checked && k.time === state.scan?.time) li.push(`<b>Every app's own file</b> (${n0(k.files)} files, ${n0(k.fresh)} read fresh, the rest remembered) against ${listSize(k)} - fingerprints, nothing sent`
    + (k.patterns?.ran ? `; the code inside them read with the malware rules (${n0(k.patterns.read)} read now, ${n0(k.patterns.remembered)} remembered)` : `; their code NOT read (${esc(k.patterns?.reason || "no answer")})`));
  else if (apps) li.push(`<b>Apps against known malware: NOT compared</b> - ${esc(k?.error || "the known-malware list isn't downloaded yet (it needs internet once)")}`);
  const f = PHONE && state.folders;
  if (PHONE) li.push(f?.needsAccess ? `<b>Phone storage: NOT read</b> - Android needs “All files access” switched on for Virus Vigil first`
    : f?.checked ? `<b>Every file in phone storage</b>: ${n0(f.files)} files, ${n0(f.fresh)} read fresh this time, the rest remembered (same name, size and date as last time)`
    : `<b>Phone storage: NOT read</b> - ${esc(f?.error || f?.list?.error || "unknown")}`);
  const n = groups.reduce((k, [, ds]) => k + ds.length, 0);
  if (!n) return "";
  return `<details class="checked" open><summary><b>What I checked</b> (${n} things in ${(ms / 1000).toFixed(1)} seconds)</summary><ul>${li.map((x) => `<li>${x}</li>`).join("")}</ul></details>`;
}

// The phone checkup's first line (29 Sep, his words: "it needs to say that all things were done, all
// checks were done, give confidence to the user"). Confident ONLY when every file check really ran
// to the end; otherwise it names exactly what was not checked, so the confidence is never borrowed.
function phoneVerdict() {
  // Same rule as knownRow: an app check from an earlier scan, or with no app list, is not this scan's (31 Oct 2026).
  const appsRead = Array.isArray(state.scan?.apps);
  const k = appsRead && state.known?.time === state.scan?.time ? state.known : null, f = state.folders;
  const n = (x) => Number(x || 0).toLocaleString("en-IN");
  const coded = ruleBad(k).filter((h) => !(k.found || []).some((x) => x.pkg === h.pkg)).length;
  const bad = (k?.found?.length || 0) + coded + folderBad(f).length;
  if (bad) return `<p class="verdict bad"><b>Scan finished - I found ${bad === 1 ? "1 harmful thing" : `${bad} harmful things`} (above). Deal with ${bad === 1 ? "it" : "them"} first.</b></p>`;
  const missed = [];
  if (!appsRead) missed.push("your apps - Android wouldn't give me the list of apps");
  else if (!k?.checked) missed.push(`your apps against known malware - ${esc(k?.error || "the list isn't downloaded yet (it needs internet once)")}`);
  else {
    if (!k.full) missed.push("the full known-malware list (only the last 48 hours' list is on the phone; the rest downloads on Wi-Fi)");
    if (k.unread?.length) missed.push(`${n(k.unread.length)} app files Android would not let me open`);
    // 29 Sep: the code inside the apps is read too; when it could not be, that is said.
    const P = k.patterns;
    if (!P?.ran) missed.push(`the code inside your apps - ${esc(P?.reason || "the malware rules did not answer")} (their fingerprints were checked)`);
    else {
      const crashedA = P.crashSkipped || [];
      if (crashedA.length) missed.push(`${crashedA.length === 1 ? "1 app file" : `${n(crashedA.length)} app files`} that made Virus Vigil stop before - fingerprinted, but their code not read: ${crashedA.slice(0, 5).map((p) => `<code>${esc(p)}</code>`).join(", ")}`);
      const failedA = (P.failed || 0) - crashedA.length;
      if (failedA > 0) missed.push(`the code of ${n(failedA)} app files the pattern check could not read${P.reason ? ` (${esc(P.reason)})` : ""}`);
    }
  }
  for (const o of [k?.online, f?.online]) if (o?.failed) missed.push(`the online look-up of ${Number(o.failed).toLocaleString("en-IN")} fingerprints - ${esc(o.error || "no answer")} (they were checked here, on the phone)`);
  if (f?.needsAccess) missed.push("the files in phone storage - “All files access” is off for Virus Vigil");
  else if (!f?.checked) missed.push(`the files in phone storage - ${esc(f?.error || f?.list?.error || "the sweep did not finish")}`);
  else {
    if (f.capped) missed.push(`${n(f.left)} files in storage - time ran out; the next check carries on from there`);
    if (f.unread) missed.push(`${n(f.unread)} files in storage Android would not let me open`);
    if (!f.yara?.ran) missed.push(`the malware-pattern check - ${esc(f.yara?.reason || "the patterns did not load")}`);
    const crashed = f.crashSkipped || [];
    if (crashed.length) missed.push(`${crashed.length === 1 ? "1 file" : `${n(crashed.length)} files`} that made Virus Vigil stop before - fingerprinted, but not read for patterns: ${crashed.slice(0, 5).map((p) => `<code>${esc(p)}</code>`).join(", ")}`);
    const failed = (f.yara?.failed || 0) - crashed.length;
    if (f.yara?.ran && failed > 0) missed.push(`${n(failed)} files the pattern check could not read${f.yara.reason ? ` (${esc(f.yara.reason)})` : ""}`);
  }
  if (missed.length) return `<p class="verdict part"><b>Scan finished, but not everything was checked.</b> Nothing harmful in what I read. Not checked:</p><ul>${missed.map((m) => `<li>${m}</li>`).join("")}</ul>`;
  const rules = parseInt(f.yara.tag, 10) || 0;
  const big = f.yara.big ? ` The ${n(f.yara.big)} very large ${f.yara.big === 1 ? "file" : "files"} (over ${f.yara.maxMb} MB, like videos) ${f.yara.big === 1 ? "was" : "were"} checked by fingerprint.` : "";
  return `<p class="verdict ok"><b>Scan complete - every check ran to the end, and nothing harmful was found on this phone.</b></p>`
    + `<p>I checked all ${n(k.apps)} apps (${n(k.files)} app files, and the code inside each) and all ${n(f.files)} files in your phone's storage (${(Number(f.bytes || 0) / 1e9).toFixed(2)} GB) against ${listSize(k)}, and read each file for ${n(rules)} malware patterns.${big}${esc(onlineNote({ ran: true, asked: Number(k.online?.asked || 0) + Number(f.online?.asked || 0), remembered: Number(k.online?.remembered || 0) + Number(f.online?.remembered || 0), bad: 0, known: Number(k.online?.known || 0) + Number(f.online?.known || 0), unknown: Number(k.online?.unknown || 0) + Number(f.online?.unknown || 0) }))} Each app's private data is sealed by Android - Google Play Protect watches that part.</p>`;
}

// The checks you run on purpose, behind one button so the summary stays short.
async function moreChecks() {
  if (PHONE) return phoneMoreChecks();
  const u = await undoInfo(); // the undo button shows only while there is something to put back
  say(`<p>Which one?</p>`, { choices: [
    { label: "Scan everything", run: () => guarded(sweepIntro) },
    { label: "Before a big payment", run: () => guarded(paymentFlow) },
    { label: "Scan with Windows Defender", run: scanIntro },
    { label: "Deep check (asks for admin)", run: deepIntro },
    { label: "What starts by itself?", run: () => guarded(startupFlow) },
    { label: "Check my browser add-ons", run: () => guarded(addonsFlow) },
    { label: "Who used my camera or mic?", run: () => guarded(cameraFlow) },
    { label: "Has my password leaked?", run: passwordFlow },
    { label: "Guard my files from ransomware", run: ransomwareFlow },
    ...(u.available ? [{ label: "Undo my changes", run: () => guarded(undoFlow) }] : []),
    { label: "Not now", kind: "quiet", run: bye },
  ] });
}

// Is another antivirus on duty (so Defender's scans have no engine)? Reads the laptop only if
// no checkup has run yet; a failed read returns "unknown" and the old wording stays.
async function avNow() {
  if (state.scan) return avPicture(state.scan);
  const done = thinking("Seeing which antivirus is on...");
  try { return avPicture(await invoke("scan_system")); } catch { return avPicture(null); } finally { done(); }
}
const otherAvScanNote = (av) => `<p><b>Your antivirus is ${esc(av.other.name)}</b>, so Windows switched Defender off by itself - that's normal. But my scan buttons use Defender, so <b>run the scan inside ${esc(av.other.name)}</b> instead (open it from the Start menu, then Scan). For a second opinion from a different engine, I can walk you through a free one-time scanner.</p>`;

// A Defender quick scan on request. Defender does the finding; what it caught is read back from
// its own record (threat_history), keeping only what was caught since the scan started.
async function scanIntro() {
  const av = await avNow();
  if (av.otherPrimary) return say(otherAvScanNote(av) + deep(`Defender realTime off / not Normal mode; ${esc(av.other.name)} reports real-time on (SecurityCenter2). Microsoft: with another antivirus on a home PC Defender runs in disabled mode and files aren't scanned.`),
    { choices: [GO.second(), { label: "Try Defender's scan anyway", run: () => guarded(scanFlow) }, { label: "Not now", kind: "quiet", run: bye }] });
  say(`<p>A <b>quick scan</b> looks in the places harmful programs hide: what's running, what starts with Windows, and the system folders. It usually takes <b>1 to 10 minutes</b>, and you can keep using the laptop.</p>`
    + deep(`MpCmdRun -Scan -ScanType 1 (quick scan), no admin needed. Results from Get-MpThreatDetection, detections since the scan started.`),
  { choices: [{ label: "Start the scan", kind: "main", run: () => guarded(scanFlow) },
    { label: "Full scan instead", run: fullScanIntro }, { label: "Offline scan (restarts)", run: offlineIntro },
    { label: "Not now", kind: "quiet", run: bye }] });
}

// FULL scan: every file on the laptop. Started and left running; not waited for.
async function fullScanIntro() {
  const av = await avNow();
  if (av.otherPrimary) return say(otherAvScanNote(av).replace("run the scan inside", "run a full scan inside"),
    { choices: [GO.second(), { label: "Not now", kind: "quiet", run: bye }] });
  say(`<p>A <b>full scan</b> opens every file on the laptop. It takes <b>an hour or more</b> and makes the laptop slower meanwhile, so start it when you won't need it - and keep it plugged in.</p>`
    + `<p>I start it and step aside. Whatever it catches, Defender deals with and keeps a record of - press <b>“Was I hacked before?”</b> afterwards and I'll read that record to you.</p>`
    + deep("MpCmdRun -Scan -ScanType 2, started in the background, no admin needed. Not waited for."),
  { choices: [{ label: "Start the full scan", kind: "main", run: () => guarded(async () => {
      const r = await invoke("defender_full_scan").catch((e) => ({ started: false, error: String(e) }));
      say(r.started ? `<p><b>The full scan has started.</b> You can close me - it keeps going. Come back in an hour or two and press “Was I hacked before?”.</p>`
        : `<p><b>It didn't start</b>: ${esc(r.error)}. You can start one yourself: Windows Security → Virus &amp; threat protection → Scan options → Full scan.</p>`,
      { choices: [{ label: "Open Windows Security", keep: true, run: () => openUrl("windowsdefender://threat") }] });
    }) }, { label: "Not now", kind: "quiet", run: bye }] });
}

// OFFLINE scan: the one that catches what hides while Windows runs. The PC restarts - ask first.
async function offlineIntro() {
  const av = await avNow();
  // Microsoft's pages don't say whether the offline scan runs while another antivirus is primary.
  const warn = av.otherPrimary ? `<p><b>Heads-up:</b> your antivirus is ${esc(av.other.name)}, so Windows has Defender switched off. The offline scan may refuse to start like that - if it does, use ${esc(av.other.name)}'s own boot or rescue scan instead.</p>` : "";
  say(warn + `<p>An <b>offline scan</b> runs <b>before Windows starts</b>, so nothing harmful is awake to hide from it. Use it when a normal scan finds nothing but something still feels wrong - or after a “free” game or crack.</p>`
    + `<p><b>Your laptop will restart about a minute after you press Yes</b>, the scan takes about 15 minutes on a blue screen, then Windows starts as normal. <b>Save and close your work first.</b></p>`
    + `<p>Afterwards: Windows Security → Protection history shows what it found, or press “Was I hacked before?”.</p>`
    + deep("Start-MpWDOScan, needs admin (Windows asks). Microsoft Defender Offline."),
  { choices: [{ label: "My work is saved - restart and scan", kind: "main", run: () => guarded(async () => {
      const done = thinking("Waiting for you to press Yes on Windows' box...");
      let r; try { r = await invoke("defender_offline_scan"); } catch (e) { r = { ok: false, errors: [String(e)] }; } finally { done(); }
      if (r.cancelled) say(`<p>You pressed No, so <b>nothing happens</b> - no restart.</p>`);
      else if (r.ok) say(`<p><b>Done - the laptop will restart in about a minute</b> and scan before Windows starts. See you after.</p>`);
      else say(`<p><b>It didn't start</b>: ${esc((r.errors || []).join("; "))}. You can start it yourself: Windows Security → Virus &amp; threat protection → Scan options → Microsoft Defender Offline scan.</p>`,
        { choices: [{ label: "Open Windows Security", keep: true, run: () => openUrl("windowsdefender://threat") }] });
    }) }, { label: "Not now", kind: "quiet", run: bye }] });
}

// ---------- scan EVERYTHING (his rule 25 Sep 13:45: "he should first scan everything") ----------
// Defender opens every file (its full scan, started and followed by the pid Vigil got back, never
// waited on - it takes an hour or more and keeps going if Vigil is closed); meanwhile Vigil reads
// what starts by itself, the add-ons and Defender's record; then a second company's scanner once.
// State lives in vv.sweep: {pid, started} while running; {fullStart, fullEnd, found, sigs} after.
const SWEEP_DAYS = 30;
const sweepGet = () => store.get("vv.sweep", null);
const sweepSet = (s) => store.set("vv.sweep", s);
const sweepRunning = (s = sweepGet()) => !!(s?.pid && !s.fullEnd && !s.stopped);
// Defender's threat record was really read (31 Oct 2026: threats.ps1 now says ok:false when it could not).
const thOk = (th) => !!th && th.ok !== false && Array.isArray(th.items);
const sweepClean = (s = sweepGet()) => !!(s?.fullEnd && s.found === 0 && Date.now() - new Date(s.fullEnd).getTime() < SWEEP_DAYS * 864e5);
const openSec = { label: "Open Windows Security", keep: true, run: () => openUrl("windowsdefender://threat") };

async function sweepIntro() {
  if (PHONE) return phoneSweep();
  const av = await avNow();
  if (av.otherPrimary) return say(otherAvScanNote(av).replace("run the scan inside", "run a full scan inside"),
    { choices: [GO.second(), { label: "Not now", kind: "quiet", run: bye }] });
  if (sweepRunning()) { say(`<p><b>The full scan is already running</b> - I'll tell you here when Defender finishes.</p>`); return sweepWatch(); }
  say(`<p><b>Let's scan everything once</b>, so we know nothing harmful is on this laptop right now. Three parts:</p><ol>`
    + `<li><b>Windows Defender opens every file on the laptop.</b> Usually one to two hours. You can keep working (it's slower meanwhile) - keep it plugged in. You can even close me: the scan keeps going, and I pick it up when you open me again.</li>`
    + `<li><b>Meanwhile I read</b> what starts by itself, your browser add-ons, and everything Defender has caught before.</li>`
    + `<li><b>Then a second scanner from a different company looks once.</b> Two different engines catch more than one.</li></ol>`
    + deep("MpCmdRun -Scan -ScanType 2 (full), followed by pid + name (scan_alive) and Defender's own FullScanStartTime/EndTime (scan_record)."),
  { choices: [{ label: "Start scanning everything", kind: "main", run: () => guarded(sweepStart) }, { label: "Not now", kind: "quiet", run: bye }] });
}

async function sweepStart() {
  const r = await invoke("defender_full_scan").catch((e) => ({ started: false, error: String(e) }));
  if (!r.started) return say(`<p><b>The full scan didn't start</b>: ${esc(r.error)}. You can start one yourself: Windows Security → Virus &amp; threat protection → Scan options → Full scan.</p>`, { choices: [openSec] });
  sweepSet({ pid: r.pid, started: new Date().toISOString() });
  renderCard();
  const done = thinking("Defender has started. Meanwhile I'm reading what starts by itself, your add-ons and Defender's record...");
  let su, ad, th;
  try { [su, ad, th] = await Promise.all([invoke("startup_items").catch(() => null), invoke("extension_audit").catch(() => null), invoke("threat_history").catch(() => null)]); }
  finally { done(); }
  if (ad) { state.addons = ad; renderCard(); }
  const li = [], flags = [];
  if (su?.items) {
    const warns = su.items.filter((i) => startupBin(i).bin === "warn");
    li.push(`All ${su.items.length} programs that start by themselves - ${warns.length ? `<b>${warns.length} using a malware trick</b>` : "none using a malware trick"}`);
    if (warns.length) flags.push(`<div class="flag careful"><b>${esc(warns.map((i) => i.name).join(", "))}</b> ${warns.length === 1 ? "starts" : "start"} by itself using a trick malware uses. Look at ${warns.length === 1 ? "it" : "them"} under “What starts by itself?”.</div>`);
  } else li.push(`What starts by itself - <b>couldn't be read</b>`);
  if (ad?.list?.count > 0) {
    const { all, known } = addonGroups(ad);
    li.push(`All ${all.length} browser add-ons against ${ad.list.count.toLocaleString("en-IN")} known-bad ones - ${known.length ? `<b>${known.length} on the list</b>` : "none on the list"}`);
    if (known.length) flags.push(`<div class="flag danger"><b>${esc(known.map((a) => a.name).join(", "))}</b> ${known.length === 1 ? "is" : "are"} on the public list of harmful add-ons. Remove ${known.length === 1 ? "it" : "them"}.</div>`);
  } else li.push(`Browser add-ons - <b>couldn't be checked</b> (the list of known-bad ones isn't here yet)`);
  if (th && !thOk(th)) li.push(`Defender's record of what it has caught here - <b>couldn't be read</b>`);
  if (thOk(th)) {
    const active = (th.items || []).filter((i) => i.active);
    li.push(`Defender's record of all ${(th.items || []).length} things it has caught here - ${active.length ? `<b>${active.length} still active</b>` : "none still active"}`);
    if (active.length) flags.push(`<div class="flag danger"><b>Defender lists ${plural(active.length, "threat", "threats")} as still active.</b> Open Windows Security → Protection history and press “Start actions”.</div>`);
  }
  say(`<p><b>Windows Defender is now opening every file.</b> I'll tell you here when it finishes - you can use the laptop, or close me.</p>` + flags.join("")
    + `<details class="checked" open><summary><b>What I checked meanwhile</b> (${li.length})</summary><ul>${li.map((x) => `<li>${x}</li>`).join("")}</ul></details>`,
  { choices: [...(flags.length ? [{ label: "What starts by itself?", run: () => guarded(startupFlow) }, { label: "Check my browser add-ons", run: () => guarded(addonsFlow) }] : []), { label: "OK", kind: "quiet", run: bye }] });
  sweepWatch();
}

// Follows the running full scan without blocking anything else: one status line, updated every
// 20 s. "Still running" = Vigil's own pid is still MpCmdRun; finished = Defender's own record.
let sweepTimer = null;
function sweepWatch() {
  if (sweepTimer || !sweepRunning()) return;
  const t0 = new Date(sweepGet().started).getTime();
  const line = say(`<p class="sweep-live"><b>Scanning every file…</b> <span class="t"></span></p>`).querySelector(".sweep-live");
  const tick = async () => {
    const s = sweepGet();
    if (!sweepRunning(s)) { clearInterval(sweepTimer); sweepTimer = null; return; }
    const alive = await invoke("scan_alive", { pid: s.pid }).then((r) => r.alive).catch(() => null);
    const m = Math.round((Date.now() - t0) / 60000);
    if (alive !== false) { line.querySelector(".t").textContent = `running for ${m < 1 ? "under a minute" : plural(m, "minute", "minutes")} (started ${hm(s.started)})`; return; }
    clearInterval(sweepTimer); sweepTimer = null;
    line.innerHTML = `<b>Defender's full scan has stopped</b> - reading its record…`;
    await sweepFinish();
  };
  sweepTimer = setInterval(tick, 20000);
  tick();
}

async function sweepFinish() {
  const s = sweepGet();
  const [rec, th] = await Promise.all([invoke("scan_record").catch(() => null), invoke("threat_history").catch(() => null)]);
  const started = new Date(s.started).getTime();
  // Both ends must belong to OUR scan: an older full scan (scheduled, or one run by hand last week)
  // has a start before ours and must never be read as this one finishing.
  const finished = !!(rec?.fullEnd && rec?.fullStart && new Date(rec.fullStart).getTime() >= started - 60000 && new Date(rec.fullEnd) >= new Date(rec.fullStart));
  if (!finished) {
    // The scanner exited but Defender records no full scan finishing after ours began: it was
    // stopped (restart, cancelled) or failed. Never counted as a clean scan.
    sweepSet({ ...s, pid: null, stopped: new Date().toISOString() });
    renderCard();
    return say(`<p><b>The full scan stopped before it finished</b> - maybe the laptop restarted or the scan was cancelled. So I can't say every file was checked.</p>`,
      { choices: [{ label: "Start it again", kind: "main", run: () => guarded(sweepStart) }, openSec, { label: "Not now", kind: "quiet", run: bye }] });
  }
  if (!thOk(th)) {
    // The scan finished, but what it caught could not be read: never recorded as clean.
    sweepSet({ fullStart: rec.fullStart, fullEnd: rec.fullEnd, found: null, unread: true, sigs: rec.fullSigs, engine: rec.engine, started: s.started });
    renderCard();
    return say(`<p><b>Defender's full scan finished, but I couldn't read what it found.</b> So I can't call it clean. Open Windows Security → Protection history to see the result.</p>`,
      { choices: [{ label: "Open Windows Security", keep: true, run: () => openUrl("windowsdefender://threat") }, { label: "Not now", kind: "quiet", run: bye }] });
  }
  const fresh = (th?.items || []).filter((i) => i.found && new Date(i.found).getTime() >= started - 60000);
  sweepSet({ fullStart: rec.fullStart, fullEnd: rec.fullEnd, found: fresh.length, sigs: rec.fullSigs, engine: rec.engine, started: s.started });
  renderCard();
  const mins = Math.max(1, Math.round((new Date(rec.fullEnd) - new Date(rec.fullStart)) / 60000));
  const receipt = `<details class="checked" open><summary><b>What I checked</b></summary><ul>`
    + `<li><b>Windows Defender's full scan - every file</b>, by its own record: started ${esc(hm(rec.fullStart))}, finished ${esc(hm(rec.fullEnd))} (${plural(mins, "minute", "minutes")})</li>`
    + (rec.fullSigs ? `<li>With virus definitions ${esc(rec.fullSigs)} and engine ${esc(rec.engine || "?")}</li>` : "")
    + (thOk(th) ? `<li>Read Defender's record of every threat it has caught here (${(th.items || []).length}) - ${fresh.length ? `<b>${fresh.length} from this scan</b>` : "none from this scan"}</li>` : "")
    + `</ul></details>`;
  const second = GO.second();
  if (fresh.length) {
    const groups = new Map();
    for (const i of fresh) { const k = i.name || "unknown"; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(i); }
    const list = [...groups.values()].sort((a, b) => (b[0].severity || 0) - (a[0].severity || 0));
    say(`<p><b>Defender opened every file and caught ${plural(fresh.length, "thing", "things")}.</b></p>` + list.map(slip).join("")
      + `<p>Anything still active: open Windows Security and press “Start actions”. Then check your accounts - some of these steal passwords. After that, let a second scanner look too.</p>` + receipt,
    { choices: [openSec, { label: "Check my accounts", kind: "main", run: () => sweep(0) }, second, { label: "Not now", kind: "quiet", run: bye }] });
  } else {
    say(`<p><b>Defender opened every file on this laptop and found nothing.</b></p><p>Last part: let <b>a second scanner from a different company</b> look once - then tap “Second scanner checked too” on your card.</p>` + receipt,
      { choices: [{ ...second, kind: "main" }, { label: "Later", kind: "quiet", run: bye }] });
  }
}

// ---------- deep check (admin, read-only) ----------
// Folders and file types that should never be excluded: excluding them blinds Defender where
// downloads and malware live.
const EXCL_RISKY_PATH = /^[a-z]:\\?$|\\users(\\[^\\]+)?\\?$|\\(downloads|desktop|documents|appdata|temp|tmp|programdata|public)(\\|$)/i;
const EXCL_RISKY_EXT = /^\.?(exe|dll|scr|com|bat|cmd|ps1|vbs|js|jse|wsf|hta|msi|lnk|zip|rar|7z|iso)$/i;

function deepIntro() {
  say(`<p>The <b>deep check</b> reads three things Windows only shows to an administrator. It <b>changes nothing</b>:</p><ul>`
    + `<li><b>Defender's “don't look here” list</b> - malware adds its own folder so it's never scanned.</li>`
    + `<li><b>Hidden scheduled tasks</b> - a trick that makes a task vanish from every list but still run.</li>`
    + `<li><b>Programs you ran from Downloads or out of a zip</b> - Windows keeps a record, and this is how most “free game” and “crack” infections start.</li></ul>`
    + `<p><b>Windows will show a box asking “Do you want to allow this app to make changes to your device?”</b> Press Yes - it only lets me read. If you press No, nothing happens.</p>`
    + deep("deep.ps1, elevated, read-only: Get-MpPreference Exclusion*, TaskCache\\Tree keys with Id but no SD, C:\\Windows\\Prefetch (*.pf, Xpress-Huffman) paths under Downloads / Temp1_*.zip / Rar$EX / 7z temp."),
  { choices: [{ label: "OK, run the deep check", kind: "main", run: () => guarded(deepFlow) }, { label: "Not now", kind: "quiet", run: bye }] });
}

async function deepFlow() {
  const done = thinking("Waiting for you to press Yes on Windows' box...");
  let r;
  try { r = await invoke("deep_check"); } finally { done(); }
  if (r.cancelled) { say(`<p>You pressed No, so I didn't look. That's fine - it's here under “More checks” whenever you want.</p>`); return; }
  const bad = [], look = [], fine = [];
  // 1. exclusions
  const ex = r.exclusions;
  if (!ex) fine.push(`<li>I <b>couldn't read</b> Defender's “don't look here” list - so I can't say it's empty.</li>`);
  else {
    const all = [...(ex.ExclusionPath || []).map((v) => ["folder", v]), ...(ex.ExclusionExtension || []).map((v) => ["file type", v]),
      ...(ex.ExclusionProcess || []).map((v) => ["program", v]), ...(ex.ExclusionIpAddress || []).map((v) => ["address", v])];
    const risky = all.filter(([k, v]) => (k === "folder" && EXCL_RISKY_PATH.test(v)) || (k === "file type" && EXCL_RISKY_EXT.test(v)) || k === "program");
    const other = all.filter((x) => !risky.includes(x));
    if (risky.length) bad.push(`<li><b>Defender is told not to look at:</b> ${risky.map(([k, v]) => `${k} <b>${esc(v)}</b>`).join(", ")}. Malware does this to itself. Unless you added it on purpose, remove it: Windows Security → Virus &amp; threat protection → Manage settings → Exclusions.</li>`);
    if (other.length) look.push(`<li>Defender skips ${other.map(([k, v]) => `${k} <b>${esc(v)}</b>`).join(", ")}. Fine if you added ${other.length === 1 ? "it" : "them"} (a game or developer folder, say); if not, remove ${other.length === 1 ? "it" : "them"}.</li>`);
    if (!all.length) fine.push(`<li>Defender's “don't look here” list is <b>empty</b> - it looks everywhere.</li>`);
  }
  // 2. hidden tasks
  const ht = r.hiddenTasks;
  if (!ht) fine.push(`<li>I <b>couldn't read</b> the scheduled-task store.</li>`);
  else if (ht.length) bad.push(`<li><b>${plural(ht.length, "hidden scheduled task", "hidden scheduled tasks")}</b>: ${ht.map((t) => `<b>${esc(t.path.replace(/^\\/, ""))}</b>`).join(", ")}. Windows never hides a task by itself - this is a trick malware uses to come back after every restart. Run an <b>offline scan</b>, then get a second opinion (below).</li>`);
  else fine.push(`<li><b>No hidden scheduled tasks</b> among ${r.tasksRead ?? "the"} tasks.</li>`);
  // 3. prefetch
  const pf = r.prefetch;
  if (!pf) fine.push(`<li>I <b>couldn't read</b> Windows' record of programs that ran.</li>`);
  else if (pf.risky?.length) {
    const rows = pf.risky.map((x) => {
      const how = /\\DOWNLOADS\\/i.test(x.path) ? "from Downloads" : "straight out of a zip or archive";
      const state = !x.stillThere ? "the file is gone now" : x.signature === "Valid" ? "signed by its maker" : "<b>still there, and nobody signed it</b>";
      return `<li><b>${esc(x.exe)}</b> - run ${how}, last on ${esc(fmtDate(x.lastRun))}; ${state}.<br><span class="deep-path">${esc(x.path)}</span></li>`;
    });
    look.push(`<li><b>${plural(pf.risky.length, "program was", "programs were")} run from Downloads or out of an archive.</b> Was each one something you meant to install, from its real maker? A “free” game, a crack, or a file a stranger sent is how password stealers get in.<ul>${rows.join("")}</ul></li>`);
  } else fine.push(`<li><b>Nothing was run from Downloads or out of an archive</b> in Windows' record (${pf.read} programs).</li>`);

  // What could not be read is never reported as clean.
  const unread = [ex, ht, pf].filter((x) => !x).length;
  let html = bad.length ? `<p><b>I found ${plural(bad.length, "warning sign", "warning signs")}.</b></p><ul>${bad.join("")}</ul>`
    : unread === 3 ? `<p><b>I couldn't read any of it</b>, so I can't say whether it's clean.</p>`
    : `<p><b>No warning signs${unread ? " in what I could read" : ""}.</b></p>`;
  if (look.length) html += `<p>Worth a look:</p><ul>${look.join("")}</ul>`;
  if (fine.length) html += `<ul>${fine.join("")}</ul>`;
  html += deep(`${esc(JSON.stringify({ tasksRead: r.tasksRead, prefetchRead: pf?.read, prefetchUnread: pf?.unread, errors: r.errors }))}`);
  const c = [];
  if (bad.length || look.length) c.push({ label: "Offline scan (restarts)", kind: bad.length ? "main" : undefined, run: offlineIntro });
  c.push({ label: "Full scan", run: fullScanIntro });
  if (bad.length || look.length) c.push(GO.second());
  if (bad.length) c.push(GO.stealer());
  c.push({ label: "Open Windows Security", keep: true, run: () => openUrl("windowsdefender://threat") });
  c.push({ label: "That's all, thanks", kind: "quiet", run: bye });
  say(html, { choices: c });
}

// "What I checked" after a quick scan. Defender records no count of files scanned, so none is
// shown: its start/finish times, definitions and engine come from its own record (scan_record),
// and a line is listed only if the thing behind it was really read.
const hm = (iso) => new Date(iso).toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
function quickChecked(rec, th, fresh, su, warns, started) {
  const li = [];
  const ran = rec?.quickEnd && new Date(rec.quickEnd).getTime() >= started - 60000;
  if (ran) {
    const secsTook = Math.max(1, Math.round((new Date(rec.quickEnd) - new Date(rec.quickStart)) / 1000));
    li.push(`<b>Windows Defender's quick scan</b>, by its own record: started ${esc(hm(rec.quickStart))}, finished ${esc(hm(rec.quickEnd))} (${secsTook < 90 ? `${secsTook} seconds` : `${Math.round(secsTook / 60)} minutes`})`);
    li.push(`It looked in the programs running now, everything set to start with Windows (the registry's start-up keys and the Startup folders), and the Windows system folders`);
    if (rec.quickSigs) {
      const age = rec.sigsUpdated ? Math.round((Date.now() - new Date(rec.sigsUpdated)) / 3600000) : null;
      li.push(`It used virus definitions ${esc(rec.quickSigs)}${age != null ? ` (updated ${age < 1 ? "within the hour" : age < 48 ? `${age} hours ago` : `${Math.round(age / 24)} days ago`})` : ""} and engine ${esc(rec.engine || "?")}`);
    }
  } else li.push(`Windows Defender's quick scan ran (its own record of the times couldn't be read)`);
  if (th && !thOk(th)) li.push(`Defender's record of what it caught <b>couldn't be read</b> - the result below comes from the scanner's own exit code`);
  if (thOk(th)) li.push(`Read Defender's record of every threat it has ever caught here (${(th.items || []).length}) - ${fresh.length ? `<b>${fresh.length} from this scan</b>` : "none from this scan"}`);
  if (su?.items) {
    const signed = su.items.filter((i) => i.signature === "Valid").length;
    li.push(`Vigil also read all ${su.items.length} programs that start by themselves: ${signed} signed by their maker, ${warns.length ? `<b>${warns.length} using a malware trick</b>` : "none using a malware trick"}`);
  }
  return `<details class="checked" open><summary><b>What I checked</b> (${li.length})</summary><ul>${li.map((x) => `<li>${x}</li>`).join("")}</ul></details>`;
}

async function scanFlow() {
  const started = Date.now();
  const done = thinking("Windows Defender is scanning this laptop - usually 1 to 10 minutes...");
  const el = [...document.querySelectorAll(".msg.thinking")].pop();
  const clock = setInterval(() => {
    const s = Math.round((Date.now() - started) / 1000);
    const t = el?.querySelector(".elapsed") || el?.querySelector(".bubble")?.appendChild(Object.assign(document.createElement("span"), { className: "elapsed" }));
    if (t) t.textContent = ` (${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")})`;
  }, 1000);
  let r, th, rec, su;
  try {
    // Vigil's own read of what starts by itself runs alongside Defender's scan (it takes seconds).
    const sup = invoke("startup_items").catch(() => null);
    r = await invoke("defender_quick_scan").catch((e) => ({ ran: false, reason: String(e) }));
    [th, rec, su] = await Promise.all([r.ran ? invoke("threat_history").catch(() => null) : null,
      r.ran ? invoke("scan_record").catch(() => null) : null, sup]);
  } finally { clearInterval(clock); done(); }
  const mins = Math.max(1, Math.round((Date.now() - started) / 60000));
  const open = { label: "Open Windows Security", keep: true, run: () => openUrl("windowsdefender://threat") };
  if (!r.ran) {
    const av = state.scan ? avPicture(state.scan) : null;
    if (av?.otherPrimary) say(otherAvScanNote(av));
    say(`<p>The scan didn't run${r.reason ? ` (${esc(r.reason)})` : r.exitCode != null ? ` (code ${esc(r.exitCode)})` : ""}.</p><p>You can start one yourself: Windows Security → Virus & threat protection → <b>Quick scan</b>.</p>`
      + deep(esc(r.output || "")), { choices: [open, { label: "Not now", kind: "quiet", run: bye }] });
    return;
  }
  // Detection times come from Defender's clock; a minute of slack either side of our own start.
  const fresh = (th?.items || []).filter((i) => i.found && new Date(i.found).getTime() >= started - 60000);
  const warns = (su?.items || []).filter((i) => startupBin(i).bin === "warn");
  const receipt = quickChecked(rec, th, fresh, su, warns, started);
  const startupFlag = warns.length ? `<div class="flag careful"><b>${plural(warns.length, "program that starts by itself uses", "programs that start by themselves use")} a trick malware uses</b> (${esc(warns.map((i) => i.name).slice(0, 3).join(", "))}). Defender didn't call ${warns.length === 1 ? "it" : "them"} a threat, but look at ${warns.length === 1 ? "it" : "them"}.</div>` : "";
  const startupBtn = warns.length ? [{ label: "What starts by itself?", kind: "main", run: () => guarded(startupFlow) }] : [];
  if (fresh.length) {
    const groups = new Map();
    for (const i of fresh) { const k = i.name || "unknown"; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(i); }
    const list = [...groups.values()].sort((a, b) => (b[0].severity || 0) - (a[0].severity || 0));
    say(`<p>The scan took about ${plural(mins, "minute", "minutes")} and <b>caught ${plural(fresh.length, "thing", "things")}</b>.</p>` + list.map(slip).join("")
      + `<p>Anything still active: open Windows Security and press “Start actions”. Then check your accounts - some of these steal passwords.</p>` + startupFlag + receipt,
    { choices: [open, { label: "Check my accounts", kind: "main", run: () => sweep(0) }, { label: "Not now", kind: "quiet", run: bye }] });
  } else if (r.found) {
    // MpCmdRun said it found something but Defender's record doesn't show it yet.
    say(`<p><b>Defender says the scan found something</b>, but hasn't listed it yet. Open Windows Security → Protection history to see it and deal with it.</p>` + receipt + deep(esc(r.output || "")),
      { choices: [open, { label: "Not now", kind: "quiet", run: bye }] });
  } else {
    say(`<p><b>The quick scan found nothing.</b> It took about ${plural(mins, "minute", "minutes")}.</p>` + startupFlag + receipt
      + `<p>A quick scan covers where harmful programs usually live. A <b>full scan</b> opens every file and takes an hour or more.</p>`
      + deep(`exit ${esc(r.exitCode)}; ${esc(r.output || "")}`),
    { choices: [...startupBtn, { label: "Full scan", run: fullScanIntro }, open, { label: "That's all, thanks", kind: "quiet", run: bye }] });
  }
}

// The check before a big payment (B7). Optional and only on request - UPI is loved for its speed,
// so nothing is ever put in front of ordinary payments (his rule, 24 Sep). Looks for what turns a
// payment into a scam on THIS laptop: a remote-control program running, the shield off, a
// known-bad add-on, a hijacked address book or proxy. Then the four rules that stop the rest.
async function paymentFlow() {
  if (PHONE) return phonePaymentFlow();
  const done = thinking("Checking this laptop before you pay - a few seconds...");
  const fresh = state.scan && Date.now() - new Date(state.scan.time).getTime() < 10 * 60 * 1000;
  let remote, s = state.scan, addons = state.addons;
  try {
    [remote, s, addons] = await Promise.all([
      invoke("remote_tools").catch((e) => ({ ok: false, error: String(e) })),
      fresh ? s : invoke("scan_system").catch(() => s),
      addons || invoke("extension_audit").catch(() => null),
    ]);
  } finally { done(); }
  if (s && s !== state.scan) { state.scan = s; }
  if (addons) state.addons = addons;
  renderCard();

  const levels = [];
  let body = "";
  const running = remote.running || [];
  if (!remote.ok) {
    levels.push("careful");
    body += `<div class="flag careful">I couldn't list the programs running right now${remote.error ? ` (${esc(remote.error)})` : ""}, so I can't tell you whether a screen-sharing app is open.</div>`;
  } else if (running.length) {
    levels.push("danger");
    const tools = [...new Set(running.map((r) => r.tool))];
    body += `<div class="flag danger"><b>${esc(tools.join(", "))} ${tools.length === 1 ? "is" : "are"} running.</b> ${tools.length === 1 ? "It lets" : "These let"} someone else see and control this screen. `
      + `If anyone on a call asked you to install or open ${tools.length === 1 ? "it" : "them"} - “bank support”, “refund team”, “KYC update” - <b>that is the scam: hang up, close ${tools.length === 1 ? "it" : "them"}, and don't pay.</b> If you opened ${tools.length === 1 ? "it" : "them"} yourself for your own reasons, close ${tools.length === 1 ? "it" : "them"} before paying anyway.</div>`;
  } else {
    body += `<div class="flag good">No screen-sharing or remote-control program is running.</div>`;
  }

  const g = s ? { laptop: laptopDoses(s), deeper: deeperDoses(s) } : { laptop: [], deeper: [] };
  const rows = [...g.laptop, ...g.deeper, ...addonDoses(addons)].filter((d) => ["shield", "addons", "deep-hosts", "deep-proxy"].includes(d.id));
  for (const d of rows) {
    if (d.ok === false) { levels.push("danger"); body += `<div class="flag danger"><b>${esc(d.care || d.name)}.</b> ${esc(d.note || "")}</div>`; }
  }
  const okRows = rows.filter((d) => d.ok === true).map((d) => d.name);
  if (okRows.length) body += `<p>Also fine: ${esc(okRows.join(" · "))}.</p>`;
  if (!s) { levels.push("careful"); body += `<div class="flag careful">I couldn't run the laptop checkup, so I only looked for screen-sharing apps.</div>`; }

  body += `<p><b>Then, for the payment itself:</b></p>` + pathHtml([
    "Open the bank's own app, or type its address yourself - never a link from a message.",
    "If someone is on the phone telling you what to press, stop. Real banks never guide you through a payment.",
    "Your UPI PIN only ever SENDS money. Nobody needs it for you to receive money or a refund.",
    "Paying on your phone? The same rule: close any screen-sharing app there first.",
  ]);
  body += deep(`remote: checked ${esc(remote.checked)} programs; running: ${esc(running.map((r) => `${r.process} (${r.path || "path hidden"})`).join(", ") || "none")}. Rows: ${esc(rows.map((d) => `${d.id}=${d.ok}`).join(" "))}. Scan ${fresh ? "reused (under 10 min old)" : "run now"}.`);
  say(verdictHtml(worst(levels)) + body, { choices: [
    { label: "Check again", run: () => guarded(paymentFlow) },
    { label: "That's all, thanks", kind: "quiet", run: bye },
  ] });
}

// Ransomware-safe folders (Controlled folder access). Explained and left to the person - never a
// card row: it also stops honest programs saving into Documents until you allow them (B5).
// Modes from Microsoft's CFA overview: 0 off (default), 1 on, 2 audit, 3/4 disk-only.
const CFA_MODE = {
  0: "switched off (Windows starts with it off)",
  1: "ON - only programs Windows trusts can change your protected folders",
  2: "in watch-only mode: Windows writes down programs it would stop, but stops nothing",
  3: "guarding only the start-up area of the disk, not your folders",
  4: "watching only the start-up area of the disk, not your folders",
};
function ransomwareFlow() {
  if (PHONE) return phoneNotHere("ransomware");
  const mode = state.scan?.extra?.cfa;
  const h = HOWTO.ransomware;
  const open = { label: h.open, keep: true, run: () => openUrl(h.url) };
  const what = `<p><b>Ransomware</b> is a program that scrambles your files and asks for money to unscramble them. `
    + `Windows can lock your <b>Documents, Pictures, Videos, Music and Favorites</b> folders so only programs it trusts can change them (the Desktop isn't included).</p>`;
  const deepText = deep(`Get-MpPreference EnableControlledFolderAccess=${mode ?? "unread"}. Default protected folders per Microsoft: Documents, Favorites, Music, Pictures, Videos (+ Public ones) and boot sectors; folders moved into OneDrive stay protected. Allow an app: Ransomware protection → Allow an app through Controlled folder access.`);
  if (mode == null) {
    say(`${what}<p>I couldn't read whether it's on here.</p>${pathHtml(h.steps)}${deepText}`, { choices: [open, { label: "OK", kind: "quiet", run: bye }] });
    return;
  }
  if (mode === 1) {
    say(`${what}<p><b>Yours is ${CFA_MODE[1]}.</b></p><p>If a program you trust suddenly says it can't save a file, that's this lock. Let it in: Windows Security → Ransomware protection → <b>Allow an app through Controlled folder access</b>.</p>${deepText}`,
      { choices: [open, { label: "Good, thanks", kind: "quiet", run: bye }] });
    return;
  }
  say(`${what}<p>On this laptop it's <b>${esc(CFA_MODE[mode] || `in an unknown mode (${mode})`)}</b>.</p>`
    + `<p><b>The catch:</b> it also stops honest programs you haven't used before from saving into those folders - a game's saves, a photo editor. Windows tells you when it blocks one, and you let it in once. Many people find that annoying, so it's your choice - a <b>backup</b> is the other cure, and it helps even if the lock is off.</p>`
    + deepText, {
    choices: [
      { label: "Show me how to switch it on", kind: "main", run: () => say(`<p>Here's the way - I can't press this one for you:</p>${pathHtml(h.steps)}<p>If a program later can't save, allow it in the same place: <b>Allow an app through Controlled folder access</b>.</p>`, { choices: [open, { label: "Done", kind: "quiet", run: bye }] }) },
      { label: "Leave it as it is", kind: "quiet", run: () => say(`<p>Fine - nothing changed. Keeping a copy of your files elsewhere is the best cure anyway; your card shows whether you have one.</p>`) },
    ],
  });
}

function showHow(list, i) {
  const d = list[i];
  const h = HOWTO[d.how] || {};
  const next = i + 1 < list.length ? { label: "Next one", run: () => showHow(list, i + 1) } : { label: "Check again", kind: "main", run: () => guarded(checkup) };
  if (d.asrFix) {
    say(`<p><b>${esc(d.care || d.name)}</b></p><p>${esc(d.note || "")}</p><p>I can switch this on for you.</p>`,
      { choices: [{ label: "Switch it on for me", kind: "main", run: () => asrFlow(d) }, next] });
    return;
  }
  if (d.sysFix || d.fixable) {
    say(`<p><b>${esc(d.care || d.name)}</b></p><p>${esc(d.note || "")}</p><p>I can do this one for you.</p>`,
      { choices: [{ label: "Do it for me", kind: "main", run: () => (d.fixable ? fixFlow([d]) : allFlow([d])) }, next] });
    return;
  }
  // A row whose fix is one of Vigil's own checks (add-ons) hands over to that check.
  if (d.flow) {
    say(`<p><b>${esc(d.care || d.name)}</b></p><p>${esc(d.note || "")}</p>`, { choices: [{ label: d.flowLabel || "Show me", kind: "main", run: () => guarded(d.flow) }, next] });
    return;
  }
  const c = howButtons(d);
  if (d.manual) c.push({ label: "Done - stamp it", kind: "main", run: () => { setTick(d.id, true); say(`<p>Stamped.</p>`); } });
  c.push(next);
  say(`<p><b>${esc(d.name)}</b></p><p>${esc(d.note || "")}</p><p>I can't press this one for you, so here's the way, step by step:</p>${pathHtml(h.steps || [])}`
    + deep(`${esc(d.deep)}${h.url ? `<br>opens ${esc(h.url)}` : ""}`), { choices: c });
}

// The buttons a guide offers: its own pages, the Settings page, one per app named, "that one is mine".
function howButtons(d) {
  const h = HOWTO[d.how] || {};
  const c = [];
  // A row may carry its own pages (one per program to update) in place of the guide's one.
  for (const l of d.links?.length ? d.links : h.url ? [{ url: h.url, open: h.open }] : []) c.push({ label: l.open, keep: true, run: () => openUrl(l.url) });
  if (h.settings) c.push({ label: h.open || "Open Settings", keep: true, run: () => openPhoneSettings(h.settings) });
  if (d.apps?.length) c.push(...appButtons(d.apps));
  if (d.trustable && d.apps?.length) c.push({ label: d.apps.length === 1 ? "I set this up myself" : "I set these up myself", run: () => trustApps(d) });
  return c;
}

function showManual(d) {
  say(`<p><b>${esc(d.name)}</b> doesn't accept settings from other programs, so here's where the switch is:</p>${pathHtml(HOWTO[d.how].steps)}<p>When it's on, tap its circle on the card to stamp it.</p>`,
    { choices: [{ label: "Done - stamp it", kind: "main", run: () => { setTick(d.id, true); say(`<p>Stamped.</p>`); } }, { label: "Later", kind: "quiet", run: () => say(`<p>No problem - it stays on the card as due.</p>`) }] });
}

function fixFlow(list) {
  const names = list.map((d) => d.name).join(", ");
  say(`<p>I'll switch on the strongest safe-browsing, download blocking and secure DNS in <b>${esc(names)}</b>.</p><p>One question first: <b>where do you keep your passwords?</b></p>`
    + deep(`Chromium: SafeBrowsingProtectionLevel=2, DownloadRestrictions=1, DnsOverHttpsMode=automatic. Edge: SmartScreenEnabled=1, SmartScreenPuaEnabled=1, DownloadRestrictions=1, DnsOverHttpsMode=automatic. Firefox: distribution/policies.json DNSOverHTTPS. All under HKLM\\SOFTWARE\\Policies. Nothing existing is deleted.`), {
    choices: [
      { label: "In my browser", run: () => askCards(list, false, "Then I'll leave the browser's password saving alone.") },
      { label: "In a password manager app", run: () => askCards(list, true, "Then I'll switch off the browser's own password saving, so your passwords live in one safer place.") },
      { label: "I'm not sure", run: () => askCards(list, false, "Then I'll leave password saving as it is - nothing you rely on will disappear.") },
    ],
  });
}

// Bank cards: stealers copy the ones a browser keeps. Stopping NEW saves is a browser setting;
// cards already saved are removed by hand (the card row's guide), so say that here too.
function askCards(list, passwords, first) {
  say(`<p>${esc(first)}</p><p>One more: <b>should the browsers stop saving bank cards?</b> Programs that steal passwords copy saved cards too. You'd type the card number when you pay - a few seconds each time.</p>`
    + deep("AutofillCreditCardEnabled=0 (Chrome, Brave, Edge; Brave honours Chromium policies). Firefox: policies.json AutofillCreditCardEnabled=false (Firefox 125+). Cards already saved are NOT removed by this."), {
    choices: [
      { label: "Stop saving cards (safer)", kind: "main", run: () => explainUac(list, { passwords, cards: true }, "Then I'll stop the browsers saving cards. Cards already saved stay until you remove them - the card row shows you how.") },
      { label: "Keep saving cards", run: () => explainUac(list, { passwords, cards: false }, "Then card saving stays as it is.") },
    ],
  });
}

function explainUac(list, opts, first) {
  say(`<p>${esc(first)}</p><p>Next, <b>Windows will show a box asking “Do you want to allow this app to make changes to your device?”</b> That's Windows checking with you - it's normal. <b>Press Yes.</b> If you press No, nothing changes.</p>`, {
    choices: [
      { label: "OK, go ahead", kind: "main", run: () => guarded(() => applyFix(list, opts)) },
      { label: "Not now", kind: "quiet", run: () => say(`<p>Fine - nothing was changed. The card keeps them marked until you're ready.</p>`) },
    ],
  });
}

async function applyFix(list, opts) {
  const done = thinking("Waiting for you to press Yes on Windows' box...");
  let r;
  try { r = await invoke("apply_fixes", { browsers: list.map((d) => d.browser), blockPasswords: opts.passwords, blockCards: opts.cards }); }
  finally { done(); }
  if (r.cancelled) {
    say(`<p>You pressed No, so <b>nothing was changed</b>. That's fine - try again whenever you like.</p>`, { choices: [{ label: "Try again", run: () => explainUac(list, opts, "Trying again.") }] });
    return;
  }
  const changes = r.changes || [];
  const good = changes.filter((c) => c.ok).length;
  let html = `<p><b>${good} of ${changes.length} settings are now on</b> - I read each one back to be sure.</p>`;
  if (r.errors?.length) html += `<p><b>${plural(r.errors.length, "setting", "settings")} didn't take:</b></p><ul>${r.errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>`;
  html += `<p><b>Close and reopen the browsers</b> for it to take effect. Afterwards the browser may say <b>“Managed by your organization”</b> - that's these settings, put there by you, not a hacker.</p>`;
  if (r.undoSaved) html += `<p>Changed your mind? <b>You can put these back any time</b> - the button is below, and later under “More checks”.</p>`;
  html += deep(changes.map((c) => `${esc(c.where)}\\${esc(c.name)} wanted=${esc(c.wanted)} readBack=${esc(c.readBack)} ${c.ok ? "OK" : "MISMATCH"}`).join("<br>") || "no changes reported");
  say(html);
  state.offerUndo = !!r.undoSaved; // summarize() adds the button; a plain say() here would be cleared by it
  await checkup();
}

// Defender attack-blocking rules: Vigil raises them itself (apply_asr), same Yes box, same undo.
function asrFlow(d) {
  const rare = d.asrFix.includes(ASR_RARE);
  say(`<p>I'll set <b>${esc(d.asrFix.map((id) => ASR_NAMES[id]).join(", "))}</b> to <b>block</b> in Windows Defender.</p>`
    + (rare ? `<p>One thing to know: this rule also stops <b>genuine</b> programs that almost nobody has yet - something a friend made, or a tiny tool from a small website. If that happens, Windows says so, and <b>Windows Security → Protection history</b> lets you allow it. Well-known programs (Chrome, Zoom, games from Steam) are usually not affected.</p>` : "")
    + `<p><b>Windows will show a box asking “Do you want to allow this app to make changes to your device?”</b> Press Yes. If you press No, nothing changes. You can put it back any time.</p>`
    + deep(`Add-MpPreference -AttackSurfaceReductionRules_Ids ${d.asrFix.join(",")} -AttackSurfaceReductionRules_Actions Enabled. Rules already at Block are not touched. The earlier setting of each is kept in %LOCALAPPDATA%\\VirusVigil\\undo.json.`), {
    choices: [
      { label: "OK, switch it on", kind: "main", run: () => guarded(() => applyAsr(d)) },
      { label: "I'd rather do it myself", run: () => say(`<p>Here's the way:</p>${pathHtml(HOWTO[d.how].steps)}`, { choices: [{ label: "Check again", kind: "main", run: () => guarded(checkup) }] }) },
      { label: "Not now", kind: "quiet", run: () => say(`<p>Fine - nothing was changed. The card keeps it marked until you're ready.</p>`) },
    ],
  });
}

async function applyAsr(d) {
  const done = thinking("Waiting for you to press Yes on Windows' box...");
  let r;
  try { r = await invoke("apply_asr", { ids: d.asrFix }); }
  finally { done(); }
  if (r.cancelled) {
    say(`<p>You pressed No, so <b>nothing was changed</b>. That's fine - try again whenever you like.</p>`, { choices: [{ label: "Try again", run: () => asrFlow(d) }] });
    return;
  }
  const changes = r.changes || [];
  const good = changes.filter((c) => c.ok).length;
  let html = `<p><b>${good} of ${plural(changes.length, "rule", "rules")} now blocking</b> - I read each one back from Defender to be sure.</p>`;
  if (r.errors?.length) html += `<p><b>${plural(r.errors.length, "rule", "rules")} didn't take:</b></p><ul>${r.errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>`;
  if (r.undoSaved) html += `<p>Changed your mind? <b>You can put it back any time</b> - the button is below, and later under “More checks”.</p>`;
  html += deep(changes.map((c) => `${esc(ASR_NAMES[c.name] || c.name)} before=${esc(JSON.stringify(c.before))} readBack=${esc(c.readBack)} ${c.ok ? "OK" : "MISMATCH"}`).join("<br>") || "no changes reported");
  say(html);
  state.offerUndo = !!r.undoSaved;
  await checkup();
}

// ---------- "Do it all for me" (his idea, 7 Oct 2026) ----------
// Card row -> the Windows setting fix.ps1 (plan.system) raises for it, only while the row is red. The
// shield only when Defender is the antivirus on duty: another antivirus is updated inside that antivirus.
// NOT here on purpose: tamper lock (Microsoft blocks scripts), memory integrity (driver risk), Secure Boot.
const SYS_FIX = { sigs: "sigs", fw: "fw", smartscreen: "smartscreen", uac: "uac", "deep-guest": "guest", "deep-smb1": "smb1", "deep-rdp": "rdp",
  "deep-assist": "assist", "deep-ext": "ext", "deep-pause": "pause", "deep-cloud": "cloud", "deep-lsa": "lsa", "deep-drivers": "drivers" };
function sysFixOf(d) {
  if (PHONE || d.ok !== false) return null;
  if (d.id === "shield") return d.how === "defender" ? "realtime" : null;
  return SYS_FIX[d.id] || null;
}
function doable(d) { return !!(d.fixable || d.asrFix || d.sysFix); }
function sweepDue() { return !PHONE && !sweepClean() && !sweepRunning() && !avPicture(state.scan).otherPrimary; }
const RESTART_FIX = { uac: "Asking before big changes", lsa: "The password-vault guard" };

// opts.all: called from the summary's "Do it all for me" - also names what stays by hand and starts
// the full scan after. opts.skipRdp: the person uses Remote Desktop themselves.
function allFlow(rows, opts = {}) {
  const list = rows.filter((d) => doable(d) && !(opts.skipRdp && d.sysFix === "rdp"));
  if (!list.length) return say(`<p>There's nothing left that I can switch on for you.</p>`);
  const sys = list.map((d) => d.sysFix).filter(Boolean);
  const asr = [...new Set(list.flatMap((d) => d.asrFix || []))];
  const sweep = !!opts.all && sweepDue();
  const g = allDoses();
  const byHand = !opts.all ? [] : [...g.laptop, ...g.browsers, ...g.deeper, ...g.past]
    .filter((d) => (doseState(d) === "open" && !doable(d)) || (d.manual && d.id.startsWith("br-") && !ticks[d.id]));
  const restart = sys.filter((f) => RESTART_FIX[f]).map((f) => RESTART_FIX[f]);
  const go = { ...opts, sweep };
  const c = [{ label: list.length + (sweep ? 1 : 0) > 1 ? "Yes, do it all" : "Yes, do it", kind: "main", run: () => guarded(() => applyAll(list, go)) }];
  if (sys.includes("rdp") && list.length > 1) c.push({ label: "All but Remote Desktop", run: () => allFlow(rows, { ...opts, skipRdp: true }) });
  if (list.length > 1) c.push({ label: "One by one", run: () => showHow(list, 0) });
  c.push({ label: "Not now", kind: "quiet", run: () => say(`<p>Fine - nothing was changed. The card keeps them marked until you're ready.</p>`) });
  say(`<p><b>Here's what I'll switch on</b>, all behind one Windows Yes box:</p><ul>${list.map((d) => `<li>${esc(d.name)}</li>`).join("")}</ul>`
    + (sweep ? `<p>Then I'll <b>start a full scan of every file</b> - usually one to two hours, and you can keep working.</p>` : "")
    + (list.some((d) => d.fixable) ? `<p>In the browsers, your saved passwords and bank cards are left exactly as they are.</p>` : "")
    + (sys.includes("rdp") ? `<p><b>Remote Desktop:</b> this stops anyone logging in to this laptop over the network. If <b>you</b> use Remote Desktop to reach it, choose “All but Remote Desktop”.</p>` : "")
    + (asr.includes(ASR_RARE) ? `<p><b>Rare new programs:</b> this also stops genuine programs almost nobody has yet. If it blocks one you trust, <b>Windows Security → Protection history</b> lets you allow it.</p>` : "")
    + (restart.length ? `<p>${esc(restart.join(" and "))} ${restart.length > 1 ? "take" : "takes"} effect after your next <b>restart</b>.</p>` : "")
    + (byHand.length ? `<p>These I can't press for you, so they stay on your card marked to do: <b>${esc(byHand.map((d) => d.name).join(", "))}</b>.</p>` : "")
    + `<p><b>Windows will show a box asking “Do you want to allow this app to make changes to your device?”</b> Press Yes. If you press No, nothing changes. You can put everything back any time.</p>`
    + deep(`apply_all browsers=[${list.filter((d) => d.fixable).map((d) => d.browser).join(",")}] passwords/cards untouched; asr=[${asr.join(",")}]; system=[${sys.join(",")}]. Values already safe are not touched. Earlier values kept in %LOCALAPPDATA%\\VirusVigil\\undo.json.`),
  { choices: c });
}

async function applyAll(list, opts) {
  const done = thinking("Waiting for you to press Yes on Windows' box...");
  let r;
  try {
    r = await invoke("apply_all", { browsers: list.filter((d) => d.fixable).map((d) => d.browser), blockPasswords: false, blockCards: false,
      asr: [...new Set(list.flatMap((d) => d.asrFix || []))], system: list.map((d) => d.sysFix).filter(Boolean) });
  } finally { done(); }
  if (r.cancelled) {
    say(`<p>You pressed No, so <b>nothing was changed</b>. That's fine - try again whenever you like.</p>`, { choices: [{ label: "Try again", run: () => allFlow(list, opts) }] });
    return;
  }
  const changes = r.changes || [];
  const good = changes.filter((c) => c.ok).length;
  let html = changes.length ? `<p><b>${good} of ${plural(changes.length, "setting", "settings")} changed</b> - I read each one back to be sure.</p>`
    : r.errors?.length ? "" : `<p><b>Windows already had these set</b>, so nothing needed changing.</p>`;
  if (r.errors?.length) html += `<p><b>${plural(r.errors.length, "setting", "settings")} didn't take:</b></p><ul>${r.errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>`;
  if (list.some((d) => d.fixable) && good) html += `<p><b>Close and reopen the browsers</b> for their settings to take effect. A browser may then say <b>“Managed by your organization”</b> - that's these settings, put there by you, not a hacker.</p>`;
  const restart = [...new Set(changes.filter((c) => c.ok && RESTART_FIX[String(c.name).split("|")[0]]).map((c) => RESTART_FIX[String(c.name).split("|")[0]]))];
  if (restart.length) html += `<p><b>Restart the laptop</b> when convenient - ${esc(restart.join(" and ").toLowerCase())} only ${restart.length > 1 ? "take" : "takes"} effect after it.</p>`;
  if (r.undoSaved) html += `<p>Changed your mind? <b>You can put these back any time</b> - under “More checks”.</p>`;
  html += deep(changes.map((c) => `${esc(c.where)}\\${esc(c.name)} wanted=${esc(c.wanted)} readBack=${esc(c.readBack)} ${c.ok ? "OK" : "MISMATCH"}`).join("<br>") || "no changes reported");
  say(html);
  state.offerUndo = !!r.undoSaved;
  await checkup();
  // He named full scans as part of "do it all": started here, after the settings, only if still due.
  if (opts.sweep && sweepDue()) await sweepStart();
}

// ---------- undo the fixer ----------
async function undoInfo() {
  try { return await invoke("undo_available"); } catch { return { available: false }; }
}

async function undoFlow() {
  const u = await undoInfo();
  if (!u.available) { say(`<p>There's nothing to put back - I haven't changed any settings on this laptop.</p>`); return; }
  const names = (u.browsers || []).join(", ") || "your browsers";
  say(`<p>I'll put the ${plural(u.settings, "setting", "settings")} I changed in <b>${esc(names)}</b> back exactly as they were before I touched them.</p>`
    + `<p><b>Windows will show a box asking “Do you want to allow this app to make changes to your device?”</b> Press Yes. If you press No, nothing changes.</p>`
    + deep("Restores only the policy values the fixer wrote (each to its recorded earlier value, or removes it if there was none) and Firefox's policies.json as it was. The record lives in %LOCALAPPDATA%\\VirusVigil\\undo.json and is deleted only when everything reads back right."), {
    choices: [
      { label: "OK, put them back", kind: "main", run: () => guarded(applyUndo) },
      { label: "Keep them on", kind: "quiet", run: () => say(`<p>Good - they stay on.</p>`) },
    ],
  });
}

async function applyUndo() {
  const done = thinking("Waiting for you to press Yes on Windows' box...");
  let r;
  try { r = await invoke("undo_fixes"); }
  finally { done(); }
  if (r.cancelled) {
    say(`<p>You pressed No, so <b>nothing was changed</b> - the settings are still on.</p>`, { choices: [{ label: "Try again", run: undoFlow }] });
    return;
  }
  const changes = r.changes || [];
  const good = changes.filter((c) => c.ok).length;
  let html = `<p><b>${good} of ${changes.length} settings are back as they were</b> - I read each one back to be sure.</p>`;
  if (r.errors?.length || good < changes.length) html += `<p><b>Not everything went back.</b> I kept the record, so you can try again later.</p>`
    + (r.errors?.length ? `<ul>${r.errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>` : "");
  if (changes.some((c) => c.where !== "Defender ASR")) html += `<p><b>Close and reopen the browsers</b> for it to take effect.</p>`;
  html += deep(changes.map((c) => `${esc(c.where)}\\${esc(c.name)} restoredTo=${esc(c.wanted)} readBack=${esc(c.readBack)} ${c.ok ? "OK" : "MISMATCH"}`).join("<br>") || "no changes reported");
  say(html);
  await checkup();
}

// ---------- 2. Was I hacked before? ----------
function friendly(p, fam) {
  if (fam?.harmless) return "A harmless test file";
  const typeName = { PWS: "Password stealer", TrojanDownloader: "Downloader", TrojanDropper: "Dropper", TrojanSpy: "Spy program", Ransom: "Ransomware",
    Behavior: "Suspicious behaviour", PUA: "Unwanted app", HackTool: "Hacking tool", VirTool: "Malware-making tool", BrowserModifier: "Browser hijacker",
    SoftwareBundler: "Sneaky installer", Phish: "Phishing", Misleading: "Fake warning program" }[p.type] || p.type || "Unknown threat";
  return p.family ? `${typeName} — “${p.family}”` : typeName;
}

const ACTION = {
  Quarantined: "Defender locked it away (quarantine), so it can't run.",
  Removed: "Defender deleted it.",
  Cleaned: "Defender cleaned it out.",
  Blocked: "Defender stopped it before it could run.",
  Allowed: "Someone chose to ALLOW this. If that wasn't you on purpose, open Windows Security and remove it.",
};

function cleanResource(r) {
  return String(r).replace(/^[a-z]+:_/i, "");
}

function slip(group) {
  const first = group[0];
  const p = parseThreatName(first.name);
  const fam = FAMILIES[p.family];
  const type = THREAT_TYPES[p.type];
  const sev = fam?.harmless ? "harmless" : SEVERITY[first.severity] || "unknown";
  const active = group.some((i) => i.active);
  const actions = [...new Set(group.map((i) => i.action).filter(Boolean))];
  const dates = group.map((i) => i.found).filter(Boolean).sort();
  const files = [...new Set(group.flatMap((i) => i.resources || []).map(cleanResource))];

  let h = `<article class="slip sev-${sev}"><div class="slip-head"><span class="slip-label">DIAGNOSIS</span><b>${esc(friendly(p, fam))}</b>`
    + `<span class="slip-count">caught ${plural(group.length, "time", "times")} · ${fmtDate(dates.at(-1))}</span></div>`;
  if (fam?.harmless) h += `<p>${esc(fam.plain)}</p>`;
  else {
    if (type) h += `<p><b>What it is:</b> ${esc(type.plain)} <span class="like">${esc(type.like)}</span></p>`;
    if (fam) h += `<p>${esc(fam.plain)}</p>`;
    if (p.platform && PLATFORMS[p.platform]) h += `<p><b>What it was:</b> ${esc(PLATFORMS[p.platform])}.</p>`;
    if (p.suffix && SUFFIXES[p.suffix]) h += `<p><b>How it was caught:</b> ${esc(SUFFIXES[p.suffix])}</p>`;
  }
  h += `<p><b>Treatment:</b> ${active ? "<b>It is still active.</b> Open Windows Security and press “Start actions”." : esc(actions.map((a) => ACTION[a] || a).join(" "))}</p>`;
  h += deep(`<b>name</b> ${esc(p.raw)}<br><b>type</b> ${esc(p.type)} <b>platform</b> ${esc(p.platform)} <b>family</b> ${esc(p.family)} <b>variant</b> ${esc(p.variant)} <b>suffix</b> ${esc(p.suffix)}<br>`
    + `<b>severity</b> ${esc(first.severity)} (${esc(sev)}) <b>first</b> ${esc(dates[0])} <b>last</b> ${esc(dates.at(-1))}<br>`
    + (first.process ? `<b>process</b> ${esc(first.process)}<br>` : "")
    + files.slice(0, 6).map((f) => esc(f)).join("<br>") + (files.length > 6 ? `<br>… and ${files.length - 6} more` : ""));
  return h + `</article>`;
}

async function hacked() {
  if (PHONE) return phoneHacked();
  const done = thinking("Reading Windows Defender's record of everything it has caught on this laptop...");
  let th;
  try { th = await invoke("threat_history"); }
  finally { done(); }
  state.threats = th;
  if (!thOk(th)) {
    say(`<p><b>I couldn't read Windows Defender's record</b>, so I can't say whether it has caught anything here. Open Windows Security → Protection history to look yourself.</p>`,
      { choices: [{ label: "Open Windows Security", keep: true, run: () => openUrl("windowsdefender://threat") }, { label: "Not now", kind: "quiet", run: bye }] });
    return;
  }
  const items = th.items || [];
  const av = state.scan ? avPicture(state.scan) : null;
  if (av?.other) say(`<p>What follows is <b>Windows Defender's</b> record only. ${esc(av.other.name)} keeps its own - open it and look at its history or quarantine too${av.otherPrimary ? ", because it is the antivirus on duty now" : ""}.</p>`);
  if (!items.length) {
    say(`<p><b>Good news: Defender has no record of catching anything on this laptop.</b></p><p>Thieves also steal logins from phones and other computers, so the next part is worth doing anyway: a quick walk through your accounts.</p>`,
      { choices: [{ label: "Check my accounts", kind: "main", run: () => sweep(0) }, { label: "What starts by itself?", run: () => guarded(startupFlow) }, { label: "Not now", kind: "quiet", run: bye }] });
    return;
  }
  const groups = new Map();
  for (const i of items) {
    const k = i.name || "unknown";
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(i);
  }
  const list = [...groups.values()].sort((a, b) => (b[0].severity || 0) - (a[0].severity || 0));
  const active = items.filter((i) => i.active).length;
  const stealer = list.some((g) => { const p = parseThreatName(g[0].name); return p.type === "PWS" || FAMILIES[p.family]?.stealer; });

  let html = `<p>Defender has caught <b>${plural(items.length, "thing", "things")}</b> on this laptop, <b>${plural(list.length, "kind", "kinds")}</b>. `
    + (active ? `<b>${active} ${active === 1 ? "is" : "are"} still active - deal with ${active === 1 ? "it" : "them"} first.</b>` : `<b>None are still active.</b>`) + `</p>`;
  html += list.map(slip).join("");
  html += stealer
    ? `<p><b>One of these steals passwords.</b> Even though it was caught, change your important passwords from a clean device and log out other sessions. The account check below does it step by step.</p>`
    : `<p>Being caught means the door held. Still, the surest way to know nobody got in is a quick walk through your accounts.</p>`;
  say(html, { choices: [{ label: "Check my accounts", kind: "main", run: () => sweep(0) }, { label: "What starts by itself?", run: () => guarded(startupFlow) }, { label: "Not now", kind: "quiet", run: bye }] });
  setTick("past-reviewed", true);
}

function sweep(i, single) {
  if (single) {
    const a = ACCOUNTS[i];
    const c = [];
    if (a.url) c.push({ label: "Open the page", keep: true, run: () => openUrl(a.url) });
    if (a.id === "acc-leaks") c.push({ label: "Check a password here", run: passwordFlow });
    c.push({ label: "All good - stamp it", kind: "main", run: () => { setTick(a.id, true); say(`<p>Stamped.</p>`); } });
    c.push({ label: "I found something strange", run: () => strange(a, i, true) });
    c.push({ label: "Walk me through all of them", run: () => sweep(0) });
    say(`<p><b>${esc(a.name)}</b>${a.phone ? " (on your phone)" : ""}</p>${pathHtml(a.steps)}<p>Look for: ${esc(a.look)}.</p>`
      + (a.url ? deep(`opens ${esc(a.url)} in your browser. Vigil sees nothing on that page.`) : ""), { choices: c });
    return;
  }
  if (i >= ACCOUNTS.length) {
    const left = ACCOUNTS.filter((a) => !ticks[a.id]).length;
    say(left
      ? `<p>That's the round done. <b>${plural(left, "check is", "checks are")} still unstamped</b> on your card - tap its circle once you've done it.</p>`
      : `<p><b>Every account check is stamped.</b> If a thief had a key, you've changed the locks.</p>`, { choices: [{ label: `Check my ${DEVICE} again`, run: () => guarded(checkup) }, { label: "Done", kind: "quiet", run: bye }] });
    return;
  }
  const a = ACCOUNTS[i];
  const c = [];
  if (a.url) c.push({ label: "Open the page", keep: true, run: () => openUrl(a.url) });
  if (a.id === "acc-leaks") c.push({ label: "Check a password here", run: passwordFlow });
  c.push({ label: "All good", kind: "main", run: () => { setTick(a.id, true); sweep(i + 1); } });
  c.push({ label: "I found something strange", run: () => strange(a, i) });
  c.push({ label: "Skip this one", kind: "quiet", run: () => sweep(i + 1) });
  say(`<p><b>${i + 1} of ${ACCOUNTS.length} · ${esc(a.name)}</b>${a.phone ? " (on your phone)" : ""}</p>${pathHtml(a.steps)}<p>Look for: ${esc(a.look)}.</p>`
    + (a.url ? deep(`opens ${esc(a.url)} in your browser. Vigil sees nothing on that page.`) : ""), { choices: c });
}

function strange(a, i, single) {
  const next = single ? () => say(`<p>Stamped. Well done for checking.</p>`) : () => sweep(i + 1);
  say(`<p>Good that you looked. Do these now, in this order:</p><ol>`
    + `<li><b>Log that device out</b> on the page you have open.</li>`
    + `<li><b>Change the password</b> - from a device you trust.</li>`
    + `<li><b>Turn on two-step verification</b> (a code on your phone as well as the password).</li>`
    + `<li>If money moved or someone is threatening you: <b>call 1930</b> (national cyber-crime helpline) or report at <b>cybercrime.gov.in</b>, and call your bank.</li></ol>`, {
    choices: [
      { label: single ? "Done - stamp it" : "Done - next account", kind: "main", run: () => { setTick(a.id, true); next(); } },
      { label: "What is two-step?", run: () => { say(`<p>${esc(GLOSSARY["2fa"])}</p>`, { choices: [{ label: single ? "OK" : "Next account", run: single ? bye : () => sweep(i + 1) }] }); } },
    ],
  });
}

// ---------- 3. Is this safe? ----------
function safeIntro() {
  if (PHONE) return phoneSafeIntro();
  say(`<p>Paste a <b>link</b> or a <b>message</b> in the box below, or <b>choose a file</b> (an app, a download, an attachment) - or drag it onto this window.</p><p>I look at it here on this laptop. <b>The file is never uploaded</b> - only its fingerprint (a code worked out from it) is asked about online.</p>`,
    { choices: [{ label: "Choose a file", run: chooseFile }] });
  $("#ask-input").focus();
}

// The name someone actually registered: "netbanking.sbi.co.in" -> "sbi.co.in", not "co.in".
// A subset of the public suffix list - the two-part endings people meet here, India first.
const TWO_PART = new Set(["co.in", "net.in", "org.in", "gov.in", "nic.in", "ac.in", "edu.in", "res.in", "firm.in", "gen.in", "ind.in", "mil.in",
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "gov.au", "edu.au", "co.nz", "co.za", "co.jp",
  "com.br", "com.cn", "com.sg", "com.my", "com.pk", "com.bd", "com.np", "com.lk", "com.tr", "com.mx", "com.ar", "com.hk", "co.id", "co.kr"]);
function registrable(host) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[")) return host;
  const parts = host.split(".");
  const n = parts.length >= 3 && TWO_PART.has(parts.slice(-2).join(".")) ? 3 : 2;
  return parts.slice(-n).join(".");
}

function checkUrl(raw) {
  const s = raw.replace(/[)\].,;!?'"]+$/, "");
  const explicitHttp = /^http:\/\//i.test(s);
  let u;
  try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : "https://" + s); } catch { return null; }
  const host = u.hostname.toLowerCase().replace(/^www\./, "");
  const flags = [];
  const add = (level, text, code) => flags.push({ level, text, code });

  if (u.username || u.password) add("danger", `It has an “@” in it. Everything before the @ is ignored - the real site is <b>${esc(host)}</b>.`, "userinfo");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[")) add("danger", "The address is a bare number instead of a name. Real banks and shops always use names.", "ip-host");
  if (host.split(".").some((l) => l.startsWith("xn--"))) add("danger", "It uses look-alike letters (for example a Russian “а” pretending to be an English “a”).", "punycode");
  if (/\.apk$/i.test(u.pathname)) add("danger", "It downloads an Android app file (.apk). Real banks, courier and government services never send apps this way.", "apk");

  let realBrand = null;
  const labels = host.split(/[.-]/);
  for (const [brand, domains] of Object.entries(BRANDS)) {
    const mentions = labels.includes(brand) || (brand.length >= 5 && host.includes(brand));
    if (!mentions) continue;
    const real = domains.some((d) => host === d || host.endsWith("." + d));
    if (real) realBrand = { brand, domain: domains[0] };
    else add("danger", `It uses the name “${esc(brand)}” but it is <b>not</b> ${esc(brand)}'s real website (that's ${esc(domains[0])}).`, "brand:" + brand);
  }
  if (explicitHttp) add("careful", "It starts with http:// not https:// - the connection isn't locked, so what you type can be read on the way.", "no-https");
  if (SHORTENERS.includes(host)) add("careful", "It's a shortened link - it hides where it really goes. Don't open it unless you trust whoever sent it.", "shortener");
  const tld = host.split(".").pop();
  if (RISKY_TLDS.includes(tld)) add("careful", `It ends in “.${esc(tld)}” - a cheap ending that scam sites use a lot.`, "tld:" + tld);
  return { url: u, host, flags, realBrand, site: registrable(host) };
}

// Look each link's name (and its parent names) up in the local copy of the public phishing
// list. Shared sites are never looked up by name - anyone can publish on them - and get their
// own note instead. The flags are added to each check before the verdict is worked out.
// The list's makers stopped updating it (Phishing.Database, last change 2 Oct 2026): say so once it is
// a week old, from their own commit date, never from our download time (31 Oct 2026).
// 2 Nov 2026: two lists (Phishing.Database + CERT Polska). Each list's own makers' date decides
// its own line; an answer without `lists` (older back end) keeps the one-list wording.
const phishStale = (phish) => {
  if (!(phish?.count > 0)) return "";
  const lists = Array.isArray(phish.lists) ? phish.lists.filter((l) => l.count > 0) : null;
  if (!lists) return phish.sourceDays >= 7
    ? `<p><small>The public phishing list hasn't been updated by its makers for ${phish.sourceDays} days, so very new phishing sites may not be on it.</small></p>` : "";
  const old = lists.filter((l) => l.sourceDays >= 7);
  if (!old.length) return "";
  const fresh = lists.filter((l) => l.sourceDays != null && l.sourceDays < 7).map((l) => esc(l.source));
  const what = old.map((l) => `${esc(l.source)} hasn't been updated by its makers for ${l.sourceDays} days`).join("; ");
  return `<p><small>${what}${fresh.length ? `. ${fresh.join(" and ")} is up to date, but it mostly lists sites aimed at people in Poland, so very new phishing sites elsewhere may not be on either list.` : ", so very new phishing sites may not be on it."}</small></p>`;
};
async function phishCheck(checks) {
  const ask = new Set();
  for (const c of checks) {
    c.shared = SHARED_HOSTS.includes(c.host);
    if (c.shared) {
      c.flags.push({ level: "careful", code: "shared", text: `<b>${esc(c.host)}</b> is a shared site - anyone can put a page there, so the address alone can't tell you whose page it is. Fake login pages love these. Never sign in from a link like this.` });
      continue;
    }
    c.names = [];
    const parts = c.host.split(".");
    for (let i = 0; i <= parts.length - 2; i++) {
      const n = parts.slice(i).join(".");
      if (i > 0 && PLATFORM_BASES.includes(n)) break;
      c.names.push(n);
    }
    c.names.forEach((n) => ask.add(n));
    if (c.url.hostname.toLowerCase() !== c.host) ask.add(c.url.hostname.toLowerCase());
  }
  if (!ask.size) return { count: null, found: [] };
  let r;
  try { r = await invoke("phish_lookup", { names: [...ask] }); }
  catch (e) { return { count: 0, found: [], error: String(e) }; }
  const found = new Set((r.found || []).map((n) => n.toLowerCase()));
  for (const c of checks) {
    const hit = (c.names || []).find((n) => found.has(n)) || (found.has(c.url.hostname.toLowerCase()) ? c.url.hostname.toLowerCase() : null);
    // Which list named it, from the back end's foundBy (older answers carry none: the original list).
    const by = (r.foundBy && (r.foundBy[hit] || Object.entries(r.foundBy).find(([k]) => k.toLowerCase() === hit)?.[1])) || ["Phishing.Database"];
    if (hit) c.flags.unshift({ level: "danger", code: "phish-list", text: `<b>${esc(hit)}</b> is on a public list of phishing sites (${by.map(esc).join(" and ")}). Don't open it, and never type a password or OTP there.` });
  }
  return r;
}

function verdictHtml(level) {
  if (level === "danger") return `<span class="verdict danger">Looks dangerous</span>`;
  if (level === "careful") return `<span class="verdict careful">Be careful</span>`;
  return `<span class="verdict none">Nothing known found<small>(that is not proof it is safe)</small></span>`;
}
const worst = (levels) => (levels.includes("danger") ? "danger" : levels.includes("careful") ? "careful" : "none");

// One checked link, as shown in the chat (used for pasted messages and for QR codes).
function linkBlock(c) {
  let html = `<p><b>${esc(c.host)}</b></p>`;
  if (!c.flags.length && c.realBrand) html += `<div class="flag good">This is ${esc(c.realBrand.brand)}'s real website. Still type important addresses yourself rather than tapping links in messages.</div>`;
  for (const f of c.flags) html += `<div class="flag ${f.level}">${f.text}</div>`;
  html += deep(`<b>host</b> ${esc(c.url.hostname)} <b>site</b> ${esc(c.site)} <b>path</b> ${esc(c.url.pathname)} <b>flags</b> ${esc(c.flags.map((f) => f.code).join(", ") || "none")}`);
  return html;
}

// What a QR code in a picture says. A UPI code is a request to PAY someone; any other code
// that is a link gets the same checks as a pasted link. Returns {levels, html}.
async function qrReport(qr) {
  const out = { levels: [], html: "" };
  if (!qr) return out;
  if (!qr.read) {
    out.html += `<div class="flag careful">I couldn't open this picture to look for a QR code${qr.error ? ` (${esc(qr.error)})` : ""}.</div>`;
    out.levels.push("careful");
    return out;
  }
  const codes = qr.codes || [];
  if (!codes.length) return out; // an ordinary picture: nothing to say
  const upiRule = SCAMS.find((s) => s.id === "upi");
  out.html += `<p><b>This picture has ${codes.length === 1 ? "a QR code" : `${codes.length} QR codes`} in it.</b></p>`;
  const links = [];
  for (const code of codes) {
    if (/^upi:/i.test(code)) {
      let p;
      try { p = new URL(code).searchParams; } catch { p = new URLSearchParams(code.split("?")[1] || ""); }
      const fields = [["Pays to (UPI id)", p.get("pa")], ["Name written in the code", p.get("pn")], ["Amount", p.get("am") ? `₹${p.get("am")}` : null], ["Note", p.get("tn")]].filter(([, v]) => v);
      const bait = upiRule && upiRule.test.test([p.get("pn"), p.get("tn")].join(" "));
      out.levels.push(bait ? "danger" : "careful");
      out.html += `<div class="flag ${bait ? "danger" : "careful"}"><b>This is a UPI payment code - scanning it SENDS money${p.get("pa") ? ` to ${esc(p.get("pa"))}` : ""}.</b> ${esc(upiRule ? upiRule.why : "")}`
        + (bait ? `<br><b>This code talks about a refund or receiving money - that is the scam.</b> ${esc(upiRule.do)}` : `<br>Only scan it if you mean to pay this person. The name inside a QR is typed by whoever made it - before entering your PIN, check the name your payment app shows.`)
        + `</div>`;
      if (fields.length) out.html += `<p>${fields.map(([k, v]) => `${esc(k)}: <b>${esc(v)}</b>`).join("<br>")}</p>`;
    } else {
      const c = URL_TOKEN.test(code.trim()) ? checkUrl(code.trim()) : null;
      if (c) links.push(c);
      else out.html += `<p>One code just holds text: <b>${esc(code.length > 200 ? code.slice(0, 200) + "…" : code)}</b></p>`;
    }
  }
  if (links.length) {
    const phish = await phishCheck(links);
    out.html += `<p>${links.length === 1 ? "A code opens this link" : "Codes open these links"} - I checked ${links.length === 1 ? "it" : "them"} without opening:</p>`;
    for (const c of links) { out.html += linkBlock(c); out.levels.push(...c.flags.map((f) => f.level)); }
    if (phish.count === 0) out.html += `<p><small>The public phishing list isn't on this ${DEVICE} yet, so I only checked the address itself.</small></p>`;
    out.html += phishStale(phish);
  }
  out.html += deep(`QR codes read on this laptop (${codes.length}): ${codes.map(esc).join("<br>")}`);
  return out;
}

const URL_TOKEN = /^(https?:\/\/\S+|www\.\S+|[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}(\/\S*)?)$/i;

async function analyze(text) {
  const t = text.trim();
  if (!t) return;

  // "what starts by itself?" - a question, not a message to check
  if (/^(?:what|which)\b.*\b(?:start|run|open|launch)s?\b.*\b(?:by itself|by themselves|automatically|on (?:its own|boot|start-?up|sign-?in))\b|^(?:start-?up|autorun)(?:\s+(?:programs?|apps?|items?|list))?\s*\??$/i.test(t)) {
    guarded(startupFlow);
    return;
  }
  // "has my password leaked?" - never checks the text itself (it may BE a password)
  if (/^(?:(?:has|have|was|were|is|are)\s+(?:my|this|the)\s+passwords?\b.*\b(?:leak|pwn|hack|breach|expos|stol)|(?:check|test)\s+(?:my\s+|a\s+)?passwords?\b|passwords?\s+(?:leak|check))/i.test(t)) {
    passwordFlow();
    return;
  }
  // "who used my camera?" / "is my mic on?" - short questions only: a long message about a camera
  // ("I recorded you through your webcam, pay...") is a scam to check, not a question.
  if (!/https?:|www\./i.test(t) && t.split(/\s+/).length <= 12 && /\b(?:camera|webcam|cam|mic|microphone)\b/i.test(t)
    && /^(?:who|which|what|is|are|has|have|did|does|can|could|check|show|list|someone|somebody|any(?:one|body))\b/i.test(t)) {
    guarded(cameraFlow);
    return;
  }
  // "check my extensions" / "are my add-ons safe?" - no link in it, so it is a question, not a message
  if (!/https?:|www\.|\.[a-z]{2,}\//i.test(t) && /^(?:(?:please\s+)?(?:check|scan|show|list|audit)(?:\s+(?:my|the|all))?|(?:are|is)\s+(?:my|these|the)|(?:what|which))\b[^:]*\b(?:extensions?|add-?ons?|plug-?ins?)\b[^:]*$/i.test(t)) {
    guarded(addonsFlow);
    return;
  }
  // phone: "check my apps" / "are my apps safe?" - short and anchored, so a message that merely mentions apps is still checked
  if (PHONE && /^(?:(?:please\s+)?(?:check|scan|show|list|audit)(?:\s+(?:my|the|all))*(?:\s+(?:my|the))?\s+(?:installed\s+)?apps?|(?:are|is)\s+(?:my|these|the)\s+apps?\s+(?:safe|ok|okay|fine))\s*[?.!]?$/i.test(t)) {
    guarded(phoneAppsFlow);
    return;
  }

  // "protect my files from ransomware" - a question about the folder lock, not a message
  if (!/https?:|www\./i.test(t) && t.split(/\s+/).length <= 12 && /ransom/i.test(t) && /\b(?:protect|guard|lock|safe|stop|folders?|files?)\b/i.test(t)) {
    ransomwareFlow();
    return;
  }

  // "I'm about to make a big payment" - the person asking, in the first person. A pasted message
  // ("you need to pay Rs 5000 now") has no "I" and goes on to be checked as a message.
  if (!/https?:|www\./i.test(t) && t.split(/\s+/).length <= 14
    && (/\b(?:i'?m|i am|i'?ll|i will|i want to|i have to|i need to|before i|can i|should i|is it safe to)\s+(?:about to\s+|going to\s+)?(?:make\s+(?:a\s+)?(?:big\s+|large\s+)?)?(?:pay|payment|send money|transfer)\b/i.test(t)
      || /^(?:(?:a|my)\s+)?(?:big|large)\s+(?:payment|transaction|transfer)s?\s*\??$/i.test(t))) {
    guarded(paymentFlow);
    return;
  }

  // "what is phishing?" - a word to explain
  const q = /^(?:what\s+is|what's|whats|what\s+are|define|meaning\s+of|explain)\s+(?:an?\s+|the\s+)?(.+?)\s*\??$/i.exec(t);
  const term = (q ? q[1] : t).toLowerCase().replace(/s$/, "");
  const gloss = GLOSSARY[term] || GLOSSARY[term + "s"] || GLOSSARY[(q ? q[1] : t).toLowerCase()];
  if (gloss && (q || t.split(/\s+/).length <= 2)) {
    say(`<p>${esc(gloss)}</p>`);
    return;
  }

  const urls = t.split(/\s+/).filter((w) => URL_TOKEN.test(w.replace(/[)\].,;!?'"]+$/, "")) && !/^\S+@\S+\.\S+$/.test(w));

  // "I shared my OTP" / "money got deducted" / "help" - the person has a PROBLEM: ask a few
  // tap-questions to pin it down, then guide (triage.js). A link in the same message is checked
  // first, and the questions follow it.
  const howTo = HOW_TO.test(t) && ANSWERS.find((e) => e.test.test(t));
  if (howTo && !urls.length) { libraryAnswer(howTo, "answer"); return; }
  const problem = detectProblem(t);
  // A pattern fired but the words point almost surely elsewhere: ask, the pattern's family first.
  const doubt = problem && !urls.length && doubtFamilies(t, problem);
  if (doubt) { closestAsk(doubt, t); return; }
  if (problem && !urls.length) { triage(problem, t); return; }
  // "how do I remove a virus?" / "is public wifi safe?" - a question, not a message to check
  if (!problem && !urls.length && t.split(/\s+/).length <= 20 && (looksLikeQuestion(t) || t.split(/\s+/).length <= 8)) {
    const ans = ANSWERS.find((e) => e.test.test(t));
    if (ans) { libraryAnswer(ans, "answer"); return; }
  }
  // Nothing matched, but the words lean towards something having happened: one "Which is
  // closest?" question with the likeliest problems (his tap 25 Sep 20:53), not a guess.
  const closest = !problem && !urls.length && closestFamilies(t);
  if (closest) { closestAsk(closest, t); return; }
  // Worried but not recognised ("kuch galat ho gaya", "need help asap"): ask what happened,
  // rather than check it as a message or say "no good answer".
  if (!problem && !urls.length && isDistress(t) && !SCAMS.some((s) => s.test.test(t))) { triage("vague", t); return; }

  const checks = urls.map(checkUrl).filter(Boolean);
  const phish = await phishCheck(checks);
  const scams = SCAMS.filter((s) => s.test.test(t) && !(s.id === "apk" && checks.some((c) => c.flags.some((f) => f.code === "apk"))));

  const levels = [...checks.flatMap((c) => c.flags.map((f) => f.level)), ...scams.map(() => "danger")];
  const level = worst(levels);
  let html = verdictHtml(level);

  for (const c of checks) html += linkBlock(c);
  for (const s of scams) {
    html += `<div class="flag danger"><b>${esc(s.title)}.</b> ${esc(s.why)}<br><b>What to do:</b> ${esc(s.do)}</div>`;
  }
  if (!checks.length && !scams.length && looksLikeQuestion(t)) {
    if (await aiAnswer(t)) return;
    if (await offerOnline(t)) return;
    noAnswer();
    return;
  }
  if (!checks.length && !scams.length) {
    html += `<p>I didn't find a link or a known trick in that. If a stranger is rushing you, asking for money, a code or an app - that alone is the warning sign.</p>`;
  } else if (level === "none") {
    html += `<p>I didn't find a known trap. If it came from a stranger or feels rushed, check with the company through its own app or website.</p>`;
  }
  if (checks.length && phish.count === 0) html += `<p><small>The public phishing list isn't on this ${DEVICE} yet, so I only checked the address itself.</small></p>`;
  if (checks.length) html += phishStale(phish);
  html += deep(`matched scam patterns: ${esc(scams.map((s) => s.id).join(", ") || "none")}. Phishing list: ${!phish.count ? `not available (${esc(phish.error || "-")})` : Array.isArray(phish.lists)
    ? phish.lists.map((l) => `${esc(l.source)} ${l.count ? `${Number(l.count).toLocaleString("en-IN")} names, downloaded ${l.ageHours} h ago${l.sourceDays != null ? `, last changed by its makers ${l.sourceDays} days ago` : ""}` : `not available (${esc(l.error || "-")})`}`).join("; ")
    : `${phish.count.toLocaleString("en-IN")} names, downloaded ${phish.ageHours} h ago${phish.sourceDays != null ? `, last changed by its makers ${phish.sourceDays} days ago` : ""}`}. All checks ran on this laptop; nothing was sent anywhere.`);
  say(html, { choices: [{ label: "Check something else", kind: "quiet", keep: true, run: () => $("#ask-input").focus() }] });
  if (problem) triage(problem, t);
}

async function chooseFile() {
  let p;
  try { p = await pickFile(); } catch (e) { say(`<p>I couldn't open the file picker: ${esc(e)}</p>`); return; }
  if (!p) return;
  guarded(() => checkFile(typeof p === "string" ? p : p.path));
}

// Vigil's own look inside the file (sniff.rs), where Windows says it came from (Mark of the Web)
// and who signed it. These catch the SHAPES malware arrives in; none of them can say a file is
// safe. Returns {levels, html}. A code the page has no words for is still shown, never dropped.
const LINK_FLAGS_FOR_DOWNLOADS = /^(phish-list|ip-host|punycode|userinfo|brand:|tld:)/;
async function lookReport(r) {
  const out = { levels: [], html: "" };
  const L = r.look;
  const fill = (s, d) => esc(s).replace("{d}", `<b>${esc(d)}</b>`);
  if (L && L.read === false) {
    out.levels.push("careful");
    out.html += `<div class="flag careful">I couldn't open this file to look inside it${L.error ? ` (${esc(L.error)})` : ""}.</div>`;
  }
  const flags = L?.flags || [];
  const rank = { danger: 0, careful: 1, info: 2 };
  const rows = flags.filter((f) => !LOOK[f.code]?.act && f.code !== "can-run").sort((a, b) => (rank[a.level] ?? 1) - (rank[b.level] ?? 1));
  for (const f of rows) {
    const k = LOOK[f.code] || { t: `Something unusual inside (${f.code})`, why: f.detail ? `Detail: {d}` : "", do: "Only open it if you trust where it came from." };
    if (f.level === "info") { out.html += `<p>${fill(k.t, f.detail)}. ${fill(k.why, f.detail)}</p>`; continue; }
    out.levels.push(f.level);
    let why = fill(k.why, f.detail);
    if (f.code === "pdf-code" && f.detail) why += ` <b>This one runs its code as soon as the file is opened.</b>`;
    out.html += `<div class="flag ${f.level === "danger" ? "danger" : "careful"}"><b>${fill(k.t, f.detail)}.</b> ${why}<br><b>What to do:</b> ${esc(k.do)}</div>`;
  }
  // What a script does, as one list: each part alone is also done by honest install scripts.
  const acts = flags.filter((f) => LOOK[f.code]?.act);
  if (acts.length) {
    const lv = worst(acts.map((f) => f.level));
    if (lv !== "none") out.levels.push(lv);
    out.html += `<div class="${lv === "none" ? "" : `flag ${lv}`}"><b>What this script does if it is run:</b><ul>${acts.map((f) => `<li>${esc(LOOK[f.code].t)}</li>`).join("")}</ul>`
      + (lv === "none" ? "" : `Some honest install scripts do these too, so this alone isn't proof - but only run it if you know exactly what it is for.`) + `</div>`;
  }

  // Can it run, and who signed it.
  const canRun = flags.find((f) => f.code === "can-run");
  const s = r.signer;
  const runnable = canRun || L?.kind === "program" || (!L?.read && /^(exe|msi|bat|cmd|ps1|vbs|js|scr|com|jar|lnk|hta)$/.test(r.ext));
  if (PHONE) {
    if (runnable) out.html += `<p>This is a Windows program file - it can't run on this phone. Don't send it on to a computer unless you trust where it came from.</p>`;
  } else if (s?.status === "HashMismatch") {
    out.levels.push("danger");
    out.html += `<div class="flag danger"><b>This file was changed after its maker signed it.</b> The signature${s.signer ? ` from ${esc(s.signer)}` : ""} no longer matches what's inside - someone may have tampered with it.<br><b>What to do:</b> Don't run it. Get a fresh copy from the maker's own website.</div>`;
  } else if (s?.status === "NotTrusted") {
    out.levels.push("danger");
    out.html += `<div class="flag danger"><b>It carries a signature Windows doesn't trust</b>${s.signer ? ` (in the name of “${esc(s.signer)}”)` : ""}. Anyone can make a signature like this for free, so it proves nothing about who made it - and pretending to be a real maker is a common trick.<br><b>What to do:</b> Don't run it unless you know exactly where it came from.</div>`;
  } else if (s?.status === "Valid") {
    out.html += `<div class="flag good">Signed by <b>${esc(s.signer || "its maker")}</b>, and the signature is intact - the file hasn't been changed since they signed it.</div>`
      + `<p><small>A signature tells you who made it, not that it is harmless. Check that this is the maker you expected.</small></p>`;
  } else if (runnable && !r.defender?.found) {
    out.levels.push("careful");
    const unsigned = s?.status === "NotSigned";
    out.html += `<div class="flag careful">This is a <b>program</b> - opening it lets it do things on your laptop.${unsigned ? ` <b>Nobody signed it.</b> Programs from well-known makers almost always carry their maker's signature; some small free tools don't, but most harmful programs don't either.` : ""} Only run programs from makers you trust, downloaded from their own website.</div>`;
  }

  // Where it came from: the address Windows saved when it was downloaded, checked like a link.
  const o = r.origin;
  if (o?.marked) {
    const c = /^https?:\/\//i.test(o.host || "") ? checkUrl(o.host) : null;
    if (c) {
      out.phish = await phishCheck([c]);
      out.phishHost = c.host;
      const ref = /^https?:\/\//i.test(o.referrer || "") ? checkUrl(o.referrer) : null;
      out.html += `<p>Downloaded from <b>${esc(c.host)}</b>${ref && ref.host !== c.host ? ` (the page you were on: ${esc(ref.host)})` : ""}.</p>`;
      for (const f of c.flags.filter((f) => LINK_FLAGS_FOR_DOWNLOADS.test(f.code))) {
        out.levels.push(f.level);
        out.html += `<div class="flag ${f.level}">${f.text}</div>`;
      }
    } else {
      out.html += `<p>Windows marked this file as downloaded from the internet.</p>`;
    }
  }
  const lookDeep = `<b>Vigil's look</b> real type=${esc(L?.kind ?? "not read")}${L?.partial ? " (first 24 MB only)" : ""} flags=${esc(flags.map((f) => f.code).join(", ") || "none")}`
    + `<br><b>signature</b> ${esc(s ? `${s.status}${s.signer ? ` (${s.signer})` : ""}` : "not checked")}`
    + `<br><b>downloaded from</b> ${esc(o?.marked ? `${o.host || "?"} zone=${o.zone ?? "?"}${o.referrer ? ` ref=${o.referrer}` : ""}` : o ? "no mark" : "not read")}`;
  out.html += deep(lookDeep);
  return out;
}

// "What I checked": one line per check that REALLY ran on this file, with its real count and
// time, built only from what check_file returned (his rule 25 Sep: a check that finishes fast
// must show its work - never a fake delay). A check that did not run is never listed.
const secs = (ms) => ms == null ? "" : ms < 1000 ? ` <span class="t">${Math.max(ms, 1)} ms</span>` : ` <span class="t">${(ms / 1000).toFixed(1)} s</span>`;
const mb = (n) => n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} bytes`;
const CHECKED = {
  type: (c) => `Read its first ${mb(c.n)} to see what it <b>really</b> is, whatever its name says`,
  name: () => `Its name, for tricks: reversed letters, a hidden second ending (bill.pdf.exe), spaces pushing the ending out of sight`,
  "hidden-page": () => `Looked for a web page or script dressed up as a harmless file`,
  "zip-office": (c) => `Opened the document's ${c.n} parts: macros, a template fetched from the internet, hidden objects`,
  "zip-android": (c) => `Opened the app's ${c.n} parts`,
  "zip-archive": (c) => `Opened the archive and read all ${c.n} names inside: programs, locked files, name tricks`,
  "zip-unreadable": () => `Tried to open the archive (it would not open - it may be damaged or a different format)`,
  ole: () => `Looked inside the old-style Office file for macros`,
  pdf: () => `Looked inside the PDF for code that runs, commands that launch programs, and attached files`,
  shortcut: () => `Read which program the shortcut really starts`,
  script: (c) => `Read all ${c.lines.toLocaleString("en-IN")} lines for ${c.n} warning signs: hidden code, downloading, switching the antivirus off, deleting backups...`,
};
function checkedList(r, look) {
  const ms = r.ms || {};
  const li = [];
  if (r.sha256) li.push(`Worked out its fingerprint (SHA-256) from all ${mb(r.size)}${secs(ms.hash)}`);
  const kn = r.known;
  if (kn?.checked) li.push(`Looked its fingerprint up among ${(Number(kn.count) + Number(kn.recent || 0)).toLocaleString("en-IN")} known malware samples (MalwareBazaar${kn.ageHours != null ? `, list ${kn.ageHours < 24 ? "from today" : `${Math.round(kn.ageHours / 24)} days old`}` : ""})${kn.full === false ? ` - <b>only the last 48 hours' samples</b>: the full list of over a million downloads once you're on Wi-Fi` : ""}${secs(ms.known)}`);
  const on = r.online;
  if (on?.said) li.push(`Asked a free public checker (CIRCL hashlookup) about its fingerprint only - ${on.said === "bad" ? "<b>it knows this file as malware</b>" : on.said === "known" ? "it knows this file, and no malware collection reported it" : "it has never seen this file (normal for your own files and brand-new ones)"}`);
  const L = r.look;
  if (L?.read) {
    const cs = L.checked || [];
    cs.forEach((c, i) => { const f = CHECKED[c.code]; li.push((f ? f(c) : `Check “${esc(c.code)}”`) + (i === cs.length - 1 ? secs(ms.look) : "")); });
    if (L.partial) li.push(`<b>Only the first ${mb(L.readBytes)}</b> of this big file was read for these checks`);
  }
  if (r.signer) li.push(`Checked who signed it and whether it was changed since${secs(ms.sign)}`);
  if (r.origin) li.push(r.origin.marked ? `Read where Windows says it was downloaded from` : `Looked for Windows' “downloaded from the internet” mark (none)`);
  if (look.phish?.count) li.push(`Looked up <b>${esc(look.phishHost)}</b> in a list of ${look.phish.count.toLocaleString("en-IN")} phishing sites`);
  if (r.apk?.read) li.push(`Read the app's ${(r.apk.permissions || []).length} permissions against ${Object.keys(PERMISSIONS).length} risky ones and ${DANGER_COMBOS.length} banking-trojan combinations${secs(ms.apk)}`);
  if (r.apk?.read && r.apk.package) li.push(`Checked its app id against ${SPY_LIST.apps} known spy apps`);
  if (r.qr) li.push(`Looked for a QR code in the picture${secs(ms.qr)}`);
  if (r.yara?.ran) li.push(`Compared it against ${Number(r.yara.rules).toLocaleString("en-IN")} public malware patterns (ReversingLabs, bartblaze and YARAhub)${secs(ms.yara)}`);
  if (r.defender?.ran) li.push(`Windows Defender scanned it with its full engine${secs(ms.defender)}`);
  if (!li.length) return "";
  const total = ms.total != null ? ` - ${ms.total < 1000 ? "under a second" : `${(ms.total / 1000).toFixed(1)} seconds`}` : "";
  return `<details class="checked" open><summary><b>What I checked</b> (${plural(li.length, "check", "checks")}${total})</summary><ul>${li.map((x) => `<li>${x}</li>`).join("")}</ul></details>`;
}

async function checkFile(path) {
  let base = String(path).split(/[\\/]/).pop();
  if (PHONE && /^content:/i.test(path)) base = "a file you picked or shared";
  you(`Check this file: ${base}`);
  const done = thinking(PHONE ? "Checking it here on this phone: its fingerprint and what's inside..." : "Checking it here on this laptop: its fingerprint, what's inside, known malware patterns and a Windows Defender scan...");
  let r;
  try {
    // A picked or shared file on Android is a content:// address. Kotlin copies it into the
    // app's own cache first so Rust can read it; it is never sent anywhere.
    if (PHONE && /^content:/i.test(path)) path = (await invoke("phone", { cmd: "copyToCache", args: { uri: path } })).path;
    r = await invoke("check_file", { path });
  }
  finally { done(); }

  const levels = [];
  let body = "";
  const d = r.defender || {};
  if (d.found) {
    levels.push("danger");
    body += d.blocked
      ? `<div class="flag danger"><b>Windows Defender says this is a threat and has already locked it</b> - nothing, not even me, can open it. ${r.stillThere ? "Defender will move it to quarantine; you can also delete it." : "Defender has already removed it."} Don't try to get it back.</div>`
      : `<div class="flag danger"><b>Windows Defender says this is a threat${d.threat ? `: ${esc(d.threat)}` : ""}.</b> ${r.stillThere ? "Don't open it - delete it." : "Defender has already removed it."}</div>`;
  } else if (d.reason === "phone") {
    // No Defender on a phone: say nothing rather than a warning about a scan that cannot exist.
  } else if (!d.ran) {
    levels.push("careful");
    body += `<div class="flag careful">Windows Defender couldn't scan it${d.reason ? ` (${esc(d.reason)})` : d.exitCode != null ? ` (code ${esc(d.exitCode)})` : ""}, so I only have my own checks.</div>`;
  } else if (!PHONE && state.scan && avPicture(state.scan).otherPrimary) {
    const o = avPicture(state.scan).other.name;
    levels.push("careful");
    body += `<div class="flag careful">Windows Defender is switched off because <b>${esc(o)}</b> is your antivirus, so its “nothing found” may mean nothing was really scanned. Right-click the file and scan it with ${esc(o)}.</div>`;
  } else {
    body += `<div class="flag good">Windows Defender scanned it and found nothing known.</div>`;
  }

  // Its fingerprint on MalwareBazaar's list of known malware samples (local list, nothing sent).
  // This is the strongest single sign here: the very same file was shared as malware before.
  const k = r.known || {};
  if (k.checked && k.found && k.stalkerware) {
    levels.push("danger");
    body += `<div class="flag danger"><b>This exact file is ${esc(k.stalkerware)}, a known spy app (stalkerware).</b> Its fingerprint is on the Echap list of spy-app samples. Once installed it secretly sends the phone's messages, calls, photos and location to whoever put it there.<br><b>What to do:</b> Don't install it - delete it. If someone asked you to put it on a phone, that is the warning sign.</div>`;
  } else if (k.checked && k.found) {
    levels.push("danger");
    body += `<div class="flag danger"><b>This exact file is a known malware sample.</b> Its fingerprint is on MalwareBazaar's public list of files that security researchers have shared as malware.<br><b>What to do:</b> Don't open it. Delete it${PHONE ? "" : ", then run “Scan everything” in case it ran before"}.</div>`;
  } else if (k.checked === false && k.error && k.error !== "phone") {
    body += `<p>I couldn't look its fingerprint up in the list of known malware (${esc(k.error)}), so that part was skipped.</p>`;
  }
  // The online checker (only the fingerprint was sent; his tap 29 Sep 2026).
  const o = r.online;
  if (o?.said === "bad") {
    levels.push("danger");
    body += `<div class="flag danger"><b>A free public checker knows this exact file as malware</b> (CIRCL hashlookup; reported by ${esc(o.source || "a malware collection")}). Only its fingerprint was asked about - the file never left this ${DEVICE}.<br><b>What to do:</b> Don't open it. Delete it${PHONE ? "" : ", then run “Scan everything” in case it ran before"}.</div>`;
  } else if (o && !o.said && o.error) {
    body += `<p>I couldn't ask the online checker about its fingerprint (${esc(o.error)}), so that part was skipped.</p>`;
  }

  // Layer 2: public malware patterns (YARA-X, laptop). A match is evidence, not proof - but the
  // rules were measured at 0 false alarms over 45,676 clean programs (25 Sep), so it is shown as danger.
  const y = r.yara || {};
  const yStrong = (y.matches || []).filter((m) => !m.weak);
  if (y.ran && y.matches?.length && !yStrong.length) {
    levels.push("careful");
    const sets = [...new Set(y.matches.map((m) => m.set))].join(" and ");
    body += `<div class="flag careful"><b>It matches ${plural(y.matches.length, "loose pattern", "loose patterns")}</b> (${esc(sets)}'s public rules: ${esc(y.matches.map((m) => m.rule).join(", "))}). These also turn up in ordinary files - a shortcut that starts a script, a program packed to be smaller - so this alone doesn't make it harmful.<br><b>What to do:</b> If you know where it came from and trust that, it's fine. If not, use “Ask VirusTotal” below for a second opinion before opening it.</div>`;
  } else if (y.ran && y.matches?.length) {
    levels.push("danger");
    const sets = [...new Set(y.matches.map((m) => m.set))].join(" and ");
    const say1 = (m) => { const w = m.what || {}; const t = w.description || [w.malware_type, w.malware || w.malware_family].filter(Boolean).join(" "); return `<li><b>${esc(m.rule)}</b>${t ? ` - ${esc(t)}` : ""}</li>`; };
    body += `<div class="flag danger"><b>It matches ${plural(y.matches.length, "pattern", "patterns")} known from malware</b> (${esc(sets)}'s public rules):<ul>${y.matches.map(say1).join("")}</ul><b>What to do:</b> Don't open it. Use “Ask VirusTotal” below for a second opinion, then delete it.</div>`;
  } else if (y.ran === false && y.reason === "off-here") {
    body += `<p>My malware-pattern check is switched off on this phone: it stopped the app while loading, several times, so I turned it off rather than let it keep crashing. The other checks ran.</p>`;
  } else if (y.ran === false && y.reason !== "phone") {
    body += `<p>My malware-pattern check couldn't read it${y.reason ? ` (${esc(y.reason)})` : ""}, so that part was skipped.</p>`;
  }

  const look = await lookReport(r);
  levels.push(...look.levels);
  body += look.html;

  if (r.apk) {
    if (!r.apk.read) {
      levels.push("careful");
      body += `<div class="flag careful">I couldn't read this app's list of permissions (${esc(r.apk.error)}).</div>`;
    } else {
      const perms = r.apk.permissions || [];
      const known = perms.filter((x) => PERMISSIONS[x]).sort((a, b) => ["severe", "high", "watch", "normal"].indexOf(PERMISSIONS[a].risk) - ["severe", "high", "watch", "normal"].indexOf(PERMISSIONS[b].risk));
      const combos = DANGER_COMBOS.filter((c) => c.needs.every((n) => perms.includes(n)));
      if (combos.length) levels.push("danger");
      else if (known.some((x) => PERMISSIONS[x].risk === "severe")) levels.push("danger");
      else if (known.some((x) => PERMISSIONS[x].risk === "high")) levels.push("careful");
      // Its app id against the public spy-app list (the same list the phone's p-spy row uses).
      const spy = r.apk.package ? spyOf({ pkg: r.apk.package }) : null;
      if (spy && !k.stalkerware) {
        levels.push("danger");
        body += `<div class="flag danger"><b>This is ${esc(spy.name)}, a known spy app (stalkerware).</b> Once installed it secretly sends the phone's messages, calls, photos and location to whoever put it there. Don't install it - and if someone asked you to put it on a phone, that is the warning sign.</div>`;
      }
      for (const c of combos) body += `<div class="flag danger">${esc(c.says)}</div>`;
      // "offers" = special services the app sets itself up as (accessibility, notification reader...),
      // told apart from what it asks for by the manifest parser. Older results have no split.
      const offers = r.apk.offers || [];
      const asks = r.apk.method === "parsed" ? r.apk.requested : perms;
      const permLine = (x) => `<div class="perm ${PERMISSIONS[x].risk}"><span class="dot"></span><span>${esc(PERMISSIONS[x].plain)}</span></div>`;
      const shownAsks = known.filter((x) => PERMISSIONS[x].risk !== "normal" && !offers.includes(x));
      const shownOffers = known.filter((x) => offers.includes(x));
      if (r.apk.method === "fallback") {
        levels.push("careful");
        body += `<div class="flag careful">This app's permission list is written in an unusual, broken way - something honest apps almost never do, and a trick some harmful apps use to hide from checkers. I read what I could, but I can't be sure the list below is complete.</div>`;
      }
      body += `<p><b>This Android app asks to:</b></p>`
        + (shownAsks.length ? shownAsks.map(permLine).join("") : `<p>nothing unusual.</p>`);
      if (shownOffers.length) body += `<p><b>It also sets itself up as a special helper that:</b></p>` + shownOffers.map(permLine).join("");
      body += `<p>Only install apps from the Play Store unless you really trust who made this one.</p>`;
      body += deep(`read by: ${esc(r.apk.method || "text search")}<br>app id: ${esc(r.apk.package || "not read")}${spy ? ` = ${esc(spy.name)} on ${esc(SPY_LIST.credit)}` : r.apk.package ? " (not on the spy-app list)" : ""}<br>asks for (${asks.length}): ${asks.map(esc).join(", ") || "none"}<br>offers: ${offers.map(esc).join(", ") || "none"}`);
    }
  }

  const qr = await qrReport(r.qr);
  levels.push(...qr.levels);
  body += qr.html;
  body += checkedList(r, look);

  // VirusTotal: a link to its website with the fingerprint, never its API and never an upload (his tap
  // 25 Sep: its free API "can not be used as a substitute for antivirus products"). It matters most when
  // no engine here looked at the file: a phone, a failed Defender scan, or Defender off for another antivirus.
  const noEngine = d.reason === "phone" || !d.ran || (!PHONE && !!state.scan && avPicture(state.scan).otherPrimary);
  if (r.sha256) body += `<p class="vt-note">${noEngine ? "<b>No virus scanner here looked inside this file.</b> " : ""}“Ask VirusTotal” opens its website with this file's fingerprint only, and shows what about 70 virus scanners say about it. <b>If it says it has never seen the file, don't press Upload there</b> - uploaded files are shared with security companies.</p>`;
  body += deep(`<b>file</b> ${esc(r.name)} (${esc(r.size)} bytes)<br><b>SHA-256</b> ${esc(r.sha256 || "not read - Windows locked the file")}<br><b>Defender</b> ran=${esc(d.ran)} exit=${esc(d.exitCode)} found=${esc(d.found)} blocked=${esc(!!d.blocked)}${y.reason === "phone" ? "" : `<br><b>patterns</b> `}${y.reason === "phone" ? "" : esc(y.ran ? `${y.rules} rules from ${y.files} files, ${(y.matches || []).map((m) => `${m.rule} (${m.file})`).join(", ") || "no match"}` : `not run${y.reason ? `: ${y.reason}` : ""}`)}`);
  say(verdictHtml(worst(levels)) + body, {
    choices: [
      // A locked file has no fingerprint to look up.
      ...(r.sha256 ? [{ label: "Ask VirusTotal (sends only the fingerprint)", kind: noEngine && !d.found ? "main" : undefined, keep: true, run: () => openUrl(`https://www.virustotal.com/gui/file/${r.sha256}`) }] : []),
      { label: "Check another file", run: chooseFile },
    ],
  });
}

// ---------- what starts by itself ----------
const LOLBIN = ["mshta.exe", "regsvr32.exe"];
const fileName = (p) => String(p || "").split(/[\\/]/).pop();
const folderOf = (p) => String(p || "").replace(/[\\/][^\\/]*$/, "");
const shortPub = (p) => String(p || "").replace(/\s+(Corporation|Corp\.?|Inc\.?|LLC|Ltd\.?|Limited|GmbH|AG|Foundation)$/i, "").replace(/^Microsoft Windows.*$/, "Microsoft");

// Each item lands in exactly one bin. Warning signs are tested FIRST, so a live launcher
// can never be filed as a harmless leftover.
function startupBin(i) {
  const why = [];
  if (i.encoded) why.push("runs hidden, coded instructions");
  if (i.web) why.push("downloads code from the internet");
  if (i.tempPlace) why.push("runs from a Temp, Downloads or Public folder");
  if (LOLBIN.includes(fileName(i.path).toLowerCase())) why.push(`uses ${fileName(i.path)}, a Windows tool attackers borrow`);
  if (why.length) return { bin: "warn", why };
  if (i.launcher) return i.target && i.targetExists === false ? { bin: "leftover" } : { bin: "script" };
  if (!i.exists) return { bin: "leftover" };
  if (i.signature !== "Valid") return { bin: "unsigned" };
  return { bin: "known" };
}

async function startupFlow() {
  if (PHONE) return phoneNotHere("startup");
  const done = thinking("Listing everything that starts by itself...");
  let r;
  try { r = await invoke("startup_items"); }
  finally { done(); }
  const items = r.items || [];
  const bins = { warn: [], known: [], script: [], unsigned: [], leftover: [] };
  for (const i of items) { const b = startupBin(i); bins[b.bin].push({ ...i, why: b.why }); }
  const off = (i) => (i.enabled ? "" : " <small>(already switched off)</small>");
  const where = { "scheduled task": "a scheduled task", "you": "your sign-in", "all users": "every sign-in" };

  let html = `<p><b>${items.length === 1 ? "1 thing starts by itself" : `${items.length} things start by themselves`} on this laptop</b> when you sign in or on a timer.</p>`;
  if (bins.warn.length) {
    html += `<p><b>${plural(bins.warn.length, "one shows", "show")} a trick malware uses - look at ${bins.warn.length === 1 ? "it" : "these"} first:</b></p><ul>`
      + bins.warn.map((i) => `<li><b>${esc(i.name)}</b>${off(i)} - ${esc(i.why.join("; "))}.</li>`).join("") + `</ul>`
      + `<p>If you don't know ${bins.warn.length === 1 ? "it" : "one"}: switch it off (Task Manager → Startup apps, or Task Scheduler for tasks), then run a full scan in Windows Security.</p>`;
  } else {
    html += `<p><b>None shows the tricks malware uses</b> - hidden coded commands, downloading code, or running from a Temp or Downloads folder.</p>`;
  }
  if (bins.known.length) {
    const pubs = [...new Set(bins.known.map((i) => shortPub(i.publisher)))];
    html += `<p><b>${bins.known.length}</b> come from makers Windows can verify: ${esc(pubs.slice(0, 8).join(", "))}${pubs.length > 8 ? ` and ${pubs.length - 8} more` : ""}.</p>`;
  }
  if (bins.script.length) {
    const byTarget = new Map();
    for (const i of bins.script) {
      const k = i.target || `${fileName(i.path)} (typed-in command)`;
      if (!byTarget.has(k)) byTarget.set(k, []);
      byTarget.get(k).push(i);
    }
    html += `<p><b>${bins.script.length}</b> run scripts - small programs written as plain text. Scripts are almost never signed, so the only question is: <b>do you know these?</b></p><ul>`
      + [...byTarget].map(([t, g]) => `<li><b>${esc(fileName(t))}</b> - ${g.length > 1 ? `${g.length} tasks` : esc(g[0].name)}${folderOf(t) && folderOf(t) !== t ? ` <small>in ${esc(folderOf(t))}</small>` : ""}</li>`).join("") + `</ul>`;
  }
  if (bins.unsigned.length) {
    html += `<p><b>${bins.unsigned.length}</b> ${bins.unsigned.length === 1 ? "program isn't" : "programs aren't"} signed by the maker - normal for small free tools, but check you know ${bins.unsigned.length === 1 ? "it" : "them"}:</p><ul>`
      + bins.unsigned.map((i) => `<li><b>${esc(i.name)}</b>${off(i)} <small>${esc(fileName(i.path))}, ${esc(where[i.source] || i.source)}</small></li>`).join("") + `</ul>`;
  }
  if (bins.leftover.length) {
    html += `<p><b>${bins.leftover.length}</b> ${bins.leftover.length === 1 ? "is a leftover" : "are leftovers"} pointing to something that's gone (${esc(bins.leftover.map((i) => i.name).join(", "))}) - harmless; tidy ${bins.leftover.length === 1 ? "it" : "them"} away in Startup apps if you like.</p>`;
  }
  html += deep(items.map((i) => `<b>${esc(i.name)}</b> [${esc(i.source)}${i.enabled ? "" : ", off"}] ${esc(i.signature ?? "missing")} ${esc(i.publisher ?? "")}<br><small>${esc(i.command)}</small>`).join("<br>"));
  say(html, { choices: [
    { label: "Open Startup apps", keep: true, run: () => openUrl("ms-settings:startupapps") },
    { label: "That's all, thanks", kind: "quiet", run: bye },
  ] });
}

// ---------- who used my camera or microphone? ----------
// Windows' own record (camera.ps1). Measured 24 Sep: a program recording the mic directly was
// NEVER logged, so an empty or short list is "what Windows recorded", never "nobody listened".
const ago = (iso) => {
  const d = ageDays(iso);
  if (d < 1 / 24) return "in the last hour";
  if (d < 1) return `${Math.round(d * 24)} h ago`;
  if (d < 2) return "yesterday";
  if (d < 60) return `${Math.round(d)} days ago`;
  return `on ${fmtDate(iso)}`;
};
// "Microsoft.WindowsCamera_8wekyb3d8bbwe" -> "Windows Camera"; "chrome.exe" -> "chrome"
const APP_NAMES = { immersivecontrolpanel: "Windows Settings", WhatsAppDesktop: "WhatsApp", SkypeApp: "Skype", ZuneVideo: "Films & TV", BingWeather: "Weather" };
const appName = (a) => {
  // "claude.exe.old.1789496614640" is an earlier copy an updater set aside: same program.
  if (!a.packaged) return a.name.replace(/\.exe(?:\.old(?:\.\d+)?)?$/i, "");
  const last = a.name.replace(/_[a-z0-9]{13}$/i, "").split(".").pop();
  return APP_NAMES[last] || last.replace(/([a-z])([A-Z])/g, "$1 $2");
};

async function cameraFlow() {
  if (PHONE) return phoneCameraFlow();
  const done = thinking("Reading Windows' record of who used the camera and microphone...");
  let r;
  try { r = await invoke("camera_use"); }
  finally { done(); }
  if (!r.ok) { say(`<p>I couldn't read Windows' camera and microphone record (${esc(r.error)}).</p>`); return; }
  const label = { webcam: "camera", microphone: "microphone" };
  let html = "";
  const now = [];
  for (const dev of r.devices || []) {
    const word = label[dev.device] || dev.device;
    if (!dev.read) { html += `<p>Windows keeps no record for the ${word} on this laptop.</p>`; continue; }
    // One line per program, newest use first (the same program can sit under several keys).
    const byName = new Map();
    for (const a of dev.apps || []) {
      const k = appName(a).toLowerCase();
      const g = byName.get(k);
      if (!g || a.lastStart > g.lastStart) byName.set(k, { ...a, inUse: a.inUse || !!g?.inUse, shown: appName(a) });
      else if (a.inUse) g.inUse = true;
    }
    const apps = [...byName.values()].sort((a, b) => (a.lastStart < b.lastStart ? 1 : -1));
    for (const a of apps.filter((x) => x.inUse)) now.push(`${a.shown} - ${word}`);
    // Unsigned = the file is there and no maker vouches for it. Gone = the app updated into a new
    // folder or was removed; its signature can't be read, which is NOT the same as unsigned.
    // Temp / Downloads / Public: where downloaded malware runs from (same test as the startup check),
    // so those are a warning whether the file is still there or not.
    const temp = apps.filter((a) => !a.packaged && /\\(?:Temp|Downloads)\\|\\Users\\Public\\/i.test(a.path || ""));
    const odd = apps.filter((a) => !a.packaged && !temp.includes(a) && a.exists !== false && a.signature && a.signature !== "Valid");
    const gone = apps.filter((a) => !a.packaged && !temp.includes(a) && a.exists === false);
    const tempFlag = !temp.length ? "" : `<div class="flag careful"><b>Ran from a Temp or Downloads folder:</b> ${temp.map((a) => `<b>${esc(a.shown)}</b>${a.exists === false ? " (now gone)" : ""}`).join(", ")}. Real apps are installed properly; programs that run straight from those folders are how downloaded malware often works. If you don't know ${temp.length === 1 ? "it" : "them"}, run a full scan in Windows Security.</div>`;
    html += `<p><b>${word[0].toUpperCase() + word.slice(1)}:</b> Windows has recorded ${plural(apps.length, "app", "apps")} using it${dev.allowedForApps === "Deny" ? " - and it's <b>switched off</b> for apps now" : ""}.</p>`;
    if (apps.length) {
      html += `<ul>` + apps.slice(0, 6).map((a) => `<li><b>${esc(a.shown)}</b> - ${a.inUse ? "<b>using it now</b>" : `last ${esc(ago(a.lastStart))}`}</li>`).join("") + `</ul>`;
      if (apps.length > 6) html += `<p><small>and ${apps.length - 6} more (switch on Details to see all).</small></p>`;
    }
    html += tempFlag;
    if (odd.length) {
      html += `<div class="flag careful">Not from a maker Windows can verify: ${odd.map((a) => `<b>${esc(a.shown)}</b>`).join(", ")}. Fine if you know ${odd.length === 1 ? "it" : "them"} - small free tools are often unsigned.</div>`;
    }
    if (gone.length) html += `<p><small>${esc(gone.map((a) => a.shown).join(", "))} ${gone.length === 1 ? "is" : "are"} no longer where ${gone.length === 1 ? "it was" : "they were"} - usually an app that updated or was removed. If you don't know ${gone.length === 1 ? "it" : "one of them"}, look at the full path in Details.</small></p>`;
    html += deep(apps.map((a) => `<b>${esc(a.shown)}</b> ${a.inUse ? "IN USE" : ""} start=${esc(a.lastStart)} stop=${esc(a.lastStop)} sig=${esc(a.signature)} allowed=${esc(a.allowed)}<br><small>${esc(a.path || a.name)}</small>`).join("<br>") || "none");
  }
  if (now.length) {
    html = `<div class="flag careful"><b>In use right now: ${esc(now.join(", "))}.</b> If you aren't on a call or recording, close ${now.length === 1 ? "that app" : "those apps"} - and if you don't know ${now.length === 1 ? "it" : "them"}, run a full scan in Windows Security.</div>` + html;
  }
  html += `<p>This is <b>what Windows has recorded</b>. It doesn't record every program - some reach the microphone without leaving a line here - so a short list can't prove nobody listened. The surest guard is the switch in Settings: turn off access for any app you don't use for calls.</p>`;
  say((now.length ? "" : `<p><b>Nothing is using them right now</b> - as far as Windows can tell.</p>`) + html, { choices: [
    { label: "Open camera settings", keep: true, run: () => openUrl("ms-settings:privacy-webcam") },
    { label: "Open microphone settings", keep: true, run: () => openUrl("ms-settings:privacy-microphone") },
    { label: "That's all, thanks", kind: "quiet", run: bye },
  ] });
}

// ---------- browser add-ons ----------
// location codes from Chromium's ManifestLocation: 1 store, 4 developer (unpacked), 8 command line,
// 6/7/9 put there by a program or a policy on this laptop.
const BY_POLICY = [7, 9];
const OUTSIDE_STORE = [4, 8];
const EXT_PAGE = { chrome: "chrome://extensions", edge: "edge://extensions", brave: "brave://extensions", opera: "opera://extensions", firefox: "about:addons" };
// Firefox (extensions.ps1): foreign = put there by another program or outside the profile; signedState <= 0 = unsigned or broken signature.
const ffOutside = (a) => a.browser === "firefox" && (a.foreign === true || (a.signedState != null && a.signedState <= 0));

// extension_audit's answer, grouped: the same add-on in several profiles is one entry.
function addonGroups(r) {
  const byId = new Map();
  for (const e of r.extensions || []) {
    if (!byId.has(e.id)) byId.set(e.id, { ...e, where: [] });
    byId.get(e.id).where.push(e);
  }
  const all = [...byId.values()];
  const known = all.filter((a) => a.known);
  const outside = all.filter((a) => !a.known && (OUTSIDE_STORE.includes(a.location) || (a.fromStore === false && !BY_POLICY.includes(a.location)) || a.where.some(ffOutside)));
  return { all, known, outside };
}

// The card row. Only a check against the known-bad list earns a row: with no list, nothing was
// checked, so there is no row (never a "done" stamp for a check that didn't happen).
function addonDoses(r) {
  if (!r || !(r.list?.count > 0)) return [];
  const { all, known, outside } = addonGroups(r);
  const base = { id: "addons", name: "No known-bad browser add-ons", flow: addonsFlow, flowLabel: "Show me my add-ons",
    deep: `${all.length} add-ons in ${r.profilesRead || 0} profiles; list ${r.list.count} ids; on list: ${known.map((a) => a.id).join(", ") || "none"}; outside the store: ${outside.map((a) => a.name).join(", ") || "none"}` };
  if (known.length) return [{ ...base, ok: false, care: "A known-bad add-on is installed",
    note: `${known.map((a) => a.name).join(", ")} ${known.length === 1 ? "is" : "are"} on the public list of harmful add-ons. Remove ${known.length === 1 ? "it" : "them"} now.` }];
  return [{ ...base, ok: true,
    note: `None of your ${plural(all.length, "add-on", "add-ons")} is on the public list of harmful ones.` + (outside.length ? ` ${outside.length} came from outside the official store - worth a look in More checks.` : "") }];
}

async function addonsFlow() {
  if (PHONE) return phoneNotHere("addons");
  const done = thinking("Looking at the add-ons in every browser profile...");
  let r;
  try { r = await invoke("extension_audit"); }
  finally { done(); }
  state.addons = r;
  renderCard();
  const list = r.list || {};
  const { all, known, outside } = addonGroups(r);
  const places = (a) => {
    const m = new Map();
    for (const w of a.where) { if (!m.has(w.browserName)) m.set(w.browserName, []); m.get(w.browserName).push(w.profile + (w.enabled === false ? " - off" : "")); }
    return [...m].map(([b, ps]) => `${b} (${ps.join(", ")})`).join("; ");
  };
  const everySite = (a) => (a.hosts || []).some((h) => ALL_SITES.test(h));
  const powers = (a) => (a.permissions || []).filter((p) => EXT_POWERS[p]).map((p) => EXT_POWERS[p]);

  const wide = all.filter((a) => !a.known && !outside.includes(a) && everySite(a));
  const rest = all.length - known.length - outside.length - wide.length;

  let html = `<p><b>${plural(all.length, "add-on", "add-ons")}</b> across ${plural(r.profilesRead || 0, "browser profile", "browser profiles")}.</p>`;
  if (list.count > 0) {
    const age = list.fetched ? "today's" : list.ageHours != null && list.ageHours < 30 ? "the recent" : "an older";
    html += known.length
      ? `<p><b>${plural(known.length, "add-on is", "add-ons are")} on the public list of known-bad add-ons.</b> Remove ${known.length === 1 ? "it" : "them"} now:</p><ul>`
        + known.map((a) => `<li><b>${esc(a.name)}</b> - ${esc(places(a))}</li>`).join("") + `</ul>`
        + `<p>In each browser, type ${[...new Set(known.flatMap((a) => a.where.map((w) => EXT_PAGE[w.browser])))].map((u) => `<b>${esc(u)}</b>`).join(" or ")} in the address bar and press Remove. Then change the passwords you typed in that browser, from a clean device.</p>`
      : `<p><b>None is on the public list of ${list.count.toLocaleString("en-IN")} known-bad add-ons.</b></p>`;
    html += `<p><small>Checked against ${age} list from The Privacy Commons Institute (chrome-mal-ids, CC BY 4.0). Only the list was downloaded - nothing about you was sent.</small></p>`;
  } else {
    html += `<p><b>I couldn't get the list of known-bad add-ons${list.error ? ` (${esc(list.error)})` : ""}, so this is NOT a check against it</b> - only a look at what each add-on is allowed to do. Try again when you're online.</p>`;
  }
  const ff = all.filter((a) => a.where.some((w) => w.browser === "firefox"));
  if (ff.length && list.count > 0) html += `<p><small>That list covers Chrome-store add-ons, so for the ${plural(ff.length, "Firefox add-on", "Firefox add-ons")} I only looked at what each is allowed to do and where it came from.</small></p>`;
  if (outside.length) {
    html += `<p><b>${plural(outside.length, "add-on didn't", "add-ons didn't")} come from the official store</b> (developer mode, added from a file, or put there by another program). Fine if you added ${outside.length === 1 ? "it" : "them"} yourself - ${outside.length === 1 ? "remove it if you don't recognise it" : "remove any you don't recognise"}:</p><ul>`
      + outside.map((a) => `<li><b>${esc(a.name)}</b> - ${esc(places(a))}</li>`).join("") + `</ul>`;
  }
  if (wide.length) {
    html += `<p><b>${wide.length}</b> can read and change <b>every website you open</b> - including your bank and email. That's normal for ad-blockers and AI helpers; just keep only the ones you use:</p><ul>`
      + wide.map((a) => { const p = powers(a); return `<li><b>${esc(a.name)}</b>${a.where.every((w) => w.enabled === false) ? " <small>(switched off)</small>" : ""}${a.where.every((w) => BY_POLICY.includes(w.location)) ? " <small>(put there by a setting on this laptop)</small>" : ""}${p.length ? ` - also ${esc(p.slice(0, 2).join("; "))}` : ""}</li>`; }).join("") + `</ul>`;
  }
  if (rest > 0) html += `<p>The other ${rest} only work on particular sites or need little.</p>`;
  html += deep(all.map((a) => `<b>${esc(a.name)}</b> ${esc(a.id)} v${esc(a.version)} loc=${esc(a.location)} store=${esc(a.fromStore)} known=${a.known}<br><small>${esc(places(a))} · sites: ${esc((a.hosts || []).slice(0, 6).join(" "))} · ${esc((a.permissions || []).join(" "))}</small>`).join("<br>")
    + `<br>list: ${esc(JSON.stringify(list))}`);
  say(html, { choices: [{ label: "That's all, thanks", kind: "quiet", run: bye }] });
}

// ---------- has my password leaked? ----------
// The password is hashed HERE (SHA-1, the browser's own crypto). Only the first 5 characters of
// the hash go to Have I Been Pwned; its reply lists every leaked hash that starts that way
// (padded with fakes), and the match happens here. The password is never shown in the chat,
// never stored, and never handed to PowerShell or Rust.
async function sha1Hex(text) {
  const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

function passwordFlow() {
  const m = say(`<p><b>Type a password to see if it has turned up in a data leak.</b></p>`
    + `<p>It never leaves this ${DEVICE}. I turn it into a code (a “hash”), send only the <b>first 5 characters</b> of that code to the leak database, get back every leaked code that starts the same way, and compare them here.</p>`
    + `<form class="ask pw-form" autocomplete="off"><label class="sr" for="pw-input">Password to check</label>`
    + `<input id="pw-input" type="password" autocomplete="off" spellcheck="false" placeholder="Password to check">`
    + `<button type="submit" class="ask-send">Check</button></form>`,
    { choices: [{ label: "Not now", kind: "quiet", run: bye }] });
  const form = m.querySelector("form");
  const input = m.querySelector("input");
  input.focus();
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = input.value;
    input.value = "";
    if (!pw) return;
    form.querySelectorAll("input, button").forEach((x) => (x.disabled = true));
    you("(a password - not shown)");
    const done = thinking("Checking the leak database...");
    let hash, r;
    try {
      hash = await sha1Hex(pw);
      r = await invoke("pwned_range", { prefix: hash.slice(0, 5) });
    } catch (err) { r = { ok: false, error: String(err) }; }
    finally { done(); }
    if (!r.ok) {
      say(`<p><b>I couldn't reach the leak database</b>, so I can't say either way. Check your internet and try again.</p>` + deep(esc(r.error || "")),
        { choices: [{ label: "Try again", run: passwordFlow }, { label: "Not now", kind: "quiet", run: bye }] });
      return;
    }
    const suffix = hash.slice(5);
    const line = (r.body || "").split(/\r?\n/).find((l) => l.split(":")[0].trim().toUpperCase() === suffix);
    const count = line ? parseInt(line.split(":")[1], 10) || 0 : 0; // padding lines have count 0
    const html = count > 0
      ? `<span class="verdict danger">Leaked</span><p><b>This password has turned up ${count.toLocaleString("en-IN")} ${count === 1 ? "time" : "times"} in data leaks.</b> Criminals try leaked passwords on every site, so stop using it everywhere.</p><p>Change it first on your <b>email</b> and <b>bank</b>, and give every site its own password - a password manager makes that easy.</p>`
      : `<span class="verdict none">Not found in any known leak<small>(that is not proof it is strong)</small></span><p>Still, use it on only one site, and make it long - a short sentence is easier to remember and harder to guess.</p>`;
    say(html + deep(`sent: ${esc(hash.slice(0, 5))} · reply: ${(r.body || "").split(/\r?\n/).length} hashes · match: ${line ? "yes" : "no"}`),
      { choices: [{ label: "Check another password", run: passwordFlow }, { label: "That's all, thanks", kind: "quiet", run: bye }] });
  });
}

// ---------- a free question, answered by the local AI ----------
// Only when no built-in rule answered, only for a question (never a pasted message), and only
// with a vetted model on THIS laptop (ai.ps1). Two independent guards withhold an answer that
// advises switching protection off, or that carries a phone number we cannot vouch for
// (a model in testing invented "011-1930"). Every answer is labelled as possibly wrong.
const AI_NUMBERS_OK = ["1930", "112", "100", "101", "102", "108", "181", "1098"];
const AI_OFF = /\b(?:turn(?:ing)?|switch(?:ing)?|shut(?:ting)?)\s+(?:\w+\s+){0,3}off\b|\bdisabl\w*\b|\buninstall\w*\b/i;
const AI_PROTECTION = /\b(?:defender|anti-?virus|firewall|windows security|protection|smartscreen|security)\b/i;
const AI_NEGATION = /\b(?:never|don't|dont|do not|not|no|without|avoid)\b/i;

function aiGuard(answer) {
  for (const s of answer.split(/(?<=[.!?\n])\s+/)) {
    if (AI_OFF.test(s) && AI_PROTECTION.test(s) && !AI_NEGATION.test(s)) return "it seemed to suggest switching a protection off";
  }
  for (const m of answer.matchAll(/\+?\d[\d\s-]{2,}\d/g)) {
    const tok = m[0].trim();
    const grouped = /\d[\s-]+\d/.test(tok);
    const digits = tok.replace(/\D/g, "");
    if ((grouped || digits.length >= 8) && !AI_NUMBERS_OK.includes(tok)) return "it gave a phone number I can't vouch for";
  }
  return null;
}

// Markdown-ish answer -> safe HTML: escape everything first, then only **bold** and line breaks.
const aiHtml = (s) => esc(s.trim()).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/\n/g, "<br>");

const looksLikeQuestion = (t) => /\?\s*$|^(?:what|how|why|when|where|who|which|should|can|could|is|are|do|does|did|will|would|am|tell me|explain)\b/i.test(t);

// A button that hands over to one of Vigil's own checks, named in answers.js `go`
const GO = {
  hacked: () => ({ label: "Was I hacked before?", run: () => guarded(hacked) }),
  accounts: () => ({ label: "Check my accounts", run: () => sweep(0) }),
  password: () => ({ label: "Has my password leaked?", run: passwordFlow }),
  checkup: () => ({ label: PHONE ? "Check my phone" : "Check this laptop", run: () => guarded(checkup) }),
  apps: () => (PHONE ? { label: "Check my apps", run: () => guarded(phoneAppsFlow) } : { label: "What starts by itself?", run: () => guarded(startupFlow) }),
  payment: () => ({ label: "Before a big payment", run: () => guarded(paymentFlow) }),
  camera: () => ({ label: "Who used my camera or mic?", run: () => (PHONE ? phoneCameraFlow() : guarded(cameraFlow)) }),
  file: () => ({ label: "Choose a file", run: chooseFile }),
  second: () => ({ label: "Get a second opinion", run: () => libraryAnswer(ANSWERS.find((e) => e.id === "second-opinion"), "answer") }),
  stealer: () => ({ label: "After a password stealer", run: () => libraryAnswer(ANSWERS.find((e) => e.id === "after-stealer"), "answer") }),
};

function libraryAnswer(e, kind) {
  const { say: text, steps } = forPlatform(e, PHONE);
  let html = kind === "first-aid" ? `<div class="flag danger"><b>${esc(e.title)}.</b> ${esc(text)}</div>` : `<p><b>${esc(e.title)}</b></p><p>${esc(text)}</p>`;
  if (steps.length) html += pathHtml(steps);
  html += deep(`answer: ${esc(kind)} "${esc(e.id)}" from the built-in library - answered on this ${DEVICE}, nothing was sent anywhere.`);
  const c = [
    ...(e.go || []).map((k) => GO[k]?.()).filter(Boolean),
    ...((PHONE ? e.phone : e.laptop)?.links || e.links || []).map((l) => ({ label: l.label, keep: true, run: () => openUrl(l.url) })),
    { label: "Ask something else", kind: "quiet", keep: true, run: () => $("#ask-input").focus() },
  ];
  say(html, { choices: c });
}

// ---------- triage: ask before answering a problem (RULES.md 24 Sep 2026 20:08) ----------
// Each question is a row of tap buttons. What the typed message already says is picked without
// asking (and shown, so a wrong pick can be seen). "Skip" answers with what is known so far.
// One tap question when Vigil is unsure which problem it is. Each button opens that problem's
// questions with the person's own words (so answers already in the message are still picked up);
// "Something else" opens the full menu; "None of these" lets them type it differently.
function closestAsk(fams, text) {
  const c = fams.filter((f) => CLOSEST_LABELS[f] && PROBLEMS[f]).map((f) => ({ label: CLOSEST_LABELS[f], run: () => triage(f, text) }));
  c.push({ label: "Something else ›", kind: "quiet", run: () => triage("vague", "") });
  c.push({ label: "None of these - I'll type it", kind: "quiet", run: () => $("#ask-input").focus() });
  say(`<p><b>I want to get this right. Which is closest to what happened?</b></p>`, { choices: c });
}

function triage(fam, text) {
  const f = PROBLEMS[fam];
  if (!f) return;
  const pre = f.urgent ? `<div class="flag danger">${esc(f.urgent)}</div>` : "";
  askNode(f.start, {}, text, [], [], pre);
}

function askNode(nodeId, ctx, text, trail, noted, pre = "") {
  const node = NODES[nodeId];
  const auto = autoPick(node, text, PHONE);
  if (auto) {
    return pickOption(nodeId, auto, ctx, text, [...trail, `${nodeId}=${auto.label} (from your message)`], [...noted, auto.label], pre);
  }
  let html = pre;
  if (noted.length) html += `<p><small>From what you wrote: ${noted.map((n) => `<b>${esc(n)}</b>`).join(" · ")}.</small></p>`;
  html += `<p><b>${esc(node.ask)}</b></p>`;
  const c = optionsFor(node, PHONE).map((o) => ({ label: o.label, run: () => pickOption(nodeId, o, ctx, text, [...trail, `${nodeId}=${o.label}`], noted, "") }));
  if (!node.noSkip) c.push({ label: "Skip - just tell me what to do", kind: "quiet", run: () => skipAhead(nodeId, ctx, text, [...trail, `${nodeId}=skip`], noted) });
  say(html, { choices: c });
}

// Skipping one question must not throw away what the message already said about the NEXT ones
// ("my husband put a spy app on my phone": skipping "which device?" still means the spy answer).
// Carries on only where every option of the skipped question leads to the same next question.
function skipAhead(nodeId, ctx, text, trail, noted) {
  const node = NODES[nodeId];
  const nexts = new Set(optionsFor(node, PHONE).map((o) => nextOf(node, o)));
  let id = nexts.size === 1 ? [...nexts][0] : null;
  let c = ctx;
  const t = [...trail], n = [...noted];
  while (id) {
    const auto = autoPick(NODES[id], text, PHONE);
    if (!auto) break;
    c = { ...c, ...(auto.set || {}) };
    t.push(`${id}=${auto.label} (from your message)`);
    n.push(auto.label);
    id = nextOf(NODES[id], auto);
  }
  triageAnswer(familyOf(nodeId), c, t, n, "");
}

function pickOption(nodeId, opt, ctx, text, trail, noted, pre) {
  const c = { ...ctx, ...(opt.set || {}) };
  const next = nextOf(NODES[nodeId], opt);
  if (next) askNode(next, c, text, trail, noted, pre);
  else triageAnswer(familyOf(nodeId), c, trail, noted, pre);
}

// Helplines a phone can dial straight from an answer (opens the dialer with the number typed in;
// the person still presses call). Only these fixed numbers are allowed by the opener scope
// (capabilities/default.json). Not on the laptop: tel: there opens an app-picker, not a call.
const HELPLINES = { 1930: "Call 1930 (cyber fraud)", 112: "Call 112 (emergency)", 181: "Call 181 (women helpline)", 1098: "Call 1098 (child helpline)" };
function callButtons(...texts) {
  if (!PHONE) return [];
  const t = texts.join(" ");
  return Object.keys(HELPLINES).filter((n) => new RegExp(`(^|[^\\d])${n}(?!\\d)`).test(t))
    .map((n) => ({ label: HELPLINES[n], keep: true, run: () => openUrl(`tel:${n}`) }));
}

function triageAnswer(fam, ctx, trail, noted, pre) {
  const r = leafFor(fam, ctx, PHONE);
  let html = pre;
  if (noted.length) html += `<p><small>From what you wrote: ${noted.map((n) => `<b>${esc(n)}</b>`).join(" · ")}.</small></p>`;
  html += r.danger ? `<div class="flag danger"><b>${esc(r.title)}.</b> ${esc(r.say)}</div>` : `<p><b>${esc(r.title)}</b></p><p>${esc(r.say)}</p>`;
  if (r.steps.length) html += pathHtml(r.steps);
  html += deep(`triage "${esc(fam)}": ${esc(trail.join(" · ") || "no questions")} - worked out on this ${DEVICE}, nothing was sent anywhere.`);
  const c = [
    ...callButtons(r.say, ...r.steps),
    ...(r.go || []).map((k) => GO[k]?.()).filter(Boolean),
    ...(r.links || []).map((l) => ({ label: l.label, keep: true, run: () => openUrl(l.url) })),
    ...(fam === "vague" ? [] : [{ label: "That's not what happened", kind: "quiet", run: () => triage("vague", "") }]),
    { label: "Ask something else", kind: "quiet", keep: true, run: () => $("#ask-input").focus() },
  ];
  if (fam === "vague") setTimeout(() => $("#ask-input").focus(), 0);
  say(html, { choices: c.filter((x, i) => c.findIndex((y) => y.label === x.label) === i) });
}

async function aiAnswer(question) {
  if (state.ai === false) return false;
  const done = thinking("Thinking it over, on this laptop...");
  let r;
  try { r = await invoke("ask_local_ai", { question }); }
  catch (e) { r = { ok: false, error: String(e) }; }
  finally { done(); }
  if (!r.ok || !r.answer) {
    if (r.error === "no-ollama" || r.error === "no-model") state.ai = false;
    return false;
  }
  const why = aiGuard(r.answer);
  if (why) {
    say(`<p>I asked the small AI on this laptop, but I'm not showing its answer: ${esc(why)}.</p><p>For anything about money or accounts, call your bank on the number on your card, or 1930 if money was lost.</p>`
      + deep(`model ${esc(r.model)} · ${r.secs} s · withheld: ${esc(why)}`));
    return true;
  }
  say(`<p>${aiHtml(r.answer)}</p><p class="ai-note"><small>Answer from a small AI running on this laptop (${esc(r.model)}) - nothing was sent anywhere. It can be wrong: for money or accounts, check with the bank or company itself.</small></p>`
    + deep(`model ${esc(r.model)} · ${r.secs} s`),
    { choices: [{ label: "Ask something else", kind: "quiet", keep: true, run: () => $("#ask-input").focus() }] });
  return true;
}

function noAnswer(lead = "I don't have a good answer for that one.") {
  say(`<p>${esc(lead)} I can check a link or a message you paste, check a file with the paper-clip, or explain a word - try “what is phishing?”.</p>`
    + (PHONE
      ? `<p>You can also ask: “Check my apps”, “Who used my camera?”, “Is it safe to pay?” or “Has my password leaked?”</p>`
      : `<p>You can also ask: “What starts by itself?”, “Check my browser add-ons”, “Who used my camera?” or “Has my password leaked?”</p>`));
}

// The online AI (his 24 Sep 19:45 rule). Rust strips personal details (redact.rs); the page shows
// EXACTLY the text that would leave and sends only on a tap. Rust strips the original again when
// sending, so what goes is what was shown. Nothing from the device goes with it.
const REMOVED_WORDS = { link: "links", email: "e-mail addresses", "upi id": "UPI ids", password: "a password or PIN",
  "id number": "PAN / IFSC codes", number: "phone, card or account numbers", code: "codes like an OTP", name: "names" };
async function offerOnline(question) {
  let r;
  try { r = await invoke("ask_online_ai", { question, device: DEVICE, send: false }); }
  catch { return false; }
  if (!r.ok) return false;
  const removed = r.removed.map((k) => REMOVED_WORDS[k] || k);
  say(`<p>My own library has no answer for that. I can ask a free online AI (${esc(r.provider)}) instead.</p>`
    + `<p>Only this would leave your ${DEVICE} - nothing else, no files, no scan results:</p>`
    + `<blockquote class="sent-text">${esc(r.sent)}</blockquote>`
    + (removed.length ? `<p><small>I took out ${esc(removed.join(", "))} before it goes.</small></p>` : `<p><small>I found nothing personal in it to take out.</small></p>`),
    { choices: [
      { label: "Ask the online AI", run: () => askOnline(question) },
      { label: "Don't send", kind: "quiet", run: () => noAnswer("OK - nothing was sent.") },
    ] });
  return true;
}

const ONLINE_ERRORS = {
  "no-key": "the online AI isn't set up in this copy of Vigil",
  busy: "the free online AI is busy or has used up its allowance for now - try again in a minute",
  "nothing-left": "once personal details were taken out, there was nothing left to ask",
};
async function askOnline(question) {
  const done = thinking("Asking the online AI...");
  let r;
  try { r = await invoke("ask_online_ai", { question, device: DEVICE, send: true }); }
  catch (e) { r = { ok: false, error: String(e) }; }
  finally { done(); }
  const again = { label: "Ask something else", kind: "quiet", keep: true, run: () => $("#ask-input").focus() };
  if (!r.ok || !r.answer) {
    const why = ONLINE_ERRORS[r.error] || (String(r.error || "").startsWith("no connection") ? "there's no internet connection right now" : String(r.error || "it failed"));
    say(`<p>I couldn't get an answer: ${esc(why)}.</p><p>For anything about money or accounts, call your bank on the number on your card, or 1930 if money was lost.</p>`, { choices: [again] });
    return;
  }
  const note = deep(`sent to ${esc(r.provider)} (${esc(r.model)}): “${esc(r.sent)}” · ${r.secs} s`);
  const why = aiGuard(r.answer);
  if (why) {
    say(`<p>I asked the online AI, but I'm not showing its answer: ${esc(why)}.</p><p>For anything about money or accounts, call your bank on the number on your card, or 1930 if money was lost.</p>` + note, { choices: [again] });
    return;
  }
  say(`<p>${aiHtml(r.answer)}</p><p class="ai-note"><small>Answer from an online AI (${esc(r.provider)}). Your question went there without personal details. It can be wrong: for money or accounts, check with the bank or company itself.</small></p>` + note,
    { choices: [again] });
}

// ---------- endings ----------
function bye() {
  say(`<p>Your card is up to date. Come back any time something looks odd - a link, a message or a file.</p>`);
}

// ---------- phone mode (Android) ----------
// The phone reads its own facts through the Kotlin plugin (plugins/vigil-phone, PhonePlugin.kt
// "scan"). A field Android would not tell us is null -> NO row, never a verdict (the laptop's rule).
// What no phone app can read at all (Play Protect, USB debugging) is a hand-ticked row with a guide.
// A phone app cannot change another app's settings: every fix is a guide plus a Settings page.
const phone = (cmd, args) => invoke("phone", { cmd, args: args || {} });
async function openPhoneSettings(page, pkg) {
  try { await phone("openSettings", { page, pkg }); }
  catch (e) { say(`<p>I couldn't open that Settings page (${esc(e)}). Open Settings yourself and type what you need into its search box.</p>`); }
}

// Installer package -> store name (PackageManager install source). Anything else, or none, is
// "outside a store". Checked 24 Sep 2026 (Play/F-Droid listings, a developer's published
// getInstallSourceInfo() output): Vivo's store REPORTS com.vivo.appstore though its own app id is
// com.bbk.appstore; Xiaomi's is com.xiaomi.market or com.xiaomi.mipicks (unresolved, both kept);
// newer Amazon Appstore builds report the plain package installer, i.e. "outside a store".
// com.google.android.packageinstaller / com.android.packageinstaller = a file someone opened.
const STORES = {
  "com.android.vending": "the Play Store",
  "com.sec.android.app.samsungapps": "Samsung's Galaxy Store",
  "com.xiaomi.mipicks": "Xiaomi's GetApps store",
  "com.xiaomi.market": "Xiaomi's GetApps store",
  "com.vivo.appstore": "Vivo's App Store",
  "com.bbk.appstore": "Vivo's App Store",
  "com.heytap.market": "the OPPO / Realme store",
  "com.oppo.market": "the OPPO store",
  "com.huawei.appmarket": "Huawei's AppGallery",
  "com.hihonor.appmarket": "Honor's App Market",
  "com.amazon.venezia": "the Amazon Appstore",
  "org.fdroid.fdroid": "F-Droid",
};
// Apps that let SOMEONE ELSE see or control this phone ("install AnyDesk so I can help you").
// Package ids + a name match, so a renamed copy from outside the store is still caught.
const REMOTE_APPS = {
  "com.anydesk.anydeskandroid": "AnyDesk",
  "com.teamviewer.quicksupport.market": "TeamViewer QuickSupport",
  "com.teamviewer.host.market": "TeamViewer Host",
  "com.carriez.flutter_hbb": "RustDesk",
  "com.sand.airdroid": "AirDroid",
  "com.sand.airdroidbiz": "AirDroid Business",
  "com.splashtop.sos": "Splashtop SOS",
  "com.splashtop.streamer.csrs": "Splashtop Streamer",
  "com.zoho.assist.agent": "Zoho Assist",
  "com.remotepc.host": "RemotePC Host",
  "it.nanosystems.supremo.host": "Supremo Mobile Assist",
};
const REMOTE_LABEL = /anydesk|teamviewer|rustdesk|airdroid|quicksupport|quick support|remote support|splashtop|zoho assist|supremo/i;
// Same names, but these only CONTROL other devices - nobody gets into this phone through them.
const REMOTE_CONTROLLERS = new Set(["com.teamviewer.teamviewer.market.mobile", "com.sand.airmirror",
  "com.google.chromeremotedesktop", "com.prosoftnet.rpcnew", "it.nanosystems.Supremo"]);
const isRemote = (a) => !REMOTE_CONTROLLERS.has(a.pkg) && !!(REMOTE_APPS[a.pkg] || REMOTE_LABEL.test(a.label || ""));
// Texts apps people choose on purpose; any other default SMS app is worth one look.
const SMS_APPS = new Set(["com.google.android.apps.messaging", "com.samsung.android.messaging", "com.truecaller",
  "com.microsoft.android.smsorganizer", "org.thoughtcrime.securesms", "com.textra", "xyz.klinker.messenger", "com.moez.QKSMS", "dev.octoshrimpy.quik"]);

const SAW = "android.permission.SYSTEM_ALERT_WINDOW";
const RIP = "android.permission.REQUEST_INSTALL_PACKAGES";
const NLS = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE";
const appNames = (l) => l.map((a) => a.label || a.pkg).join(", ");
const fromStore = (a) => !!STORES[a.installer];
const whereFrom = (a) => (STORES[a.installer] ? `from ${STORES[a.installer]}` : "installed from outside a store");
const RISK_ORDER = ["severe", "high", "watch", "normal"];

// What an app can actually do. Drawing over apps and installing apps are switched on in Settings
// (an "app op"), not granted like the rest, so they count only when that switch is on.
function powersOf(a) {
  const granted = a.granted || [];
  const p = new Set([...granted, ...(a.offers || [])]);
  p.delete(SAW); p.delete(RIP);
  if (a.overlay === "allowed" || (a.overlay === "default" && granted.includes(SAW))) p.add(SAW);
  if (a.installsApps === "allowed" || (a.installsApps === "default" && granted.includes(RIP))) p.add(RIP);
  return [...p];
}
const combosOf = (a) => { const p = powersOf(a); return DANGER_COMBOS.filter((c) => c.needs.every((n) => p.includes(n))); };
const strongOf = (a) => powersOf(a).filter((x) => ["severe", "high"].includes(PERMISSIONS[x]?.risk));

// "I set this up myself" is remembered per row AND per app, so a NEW app with the same power
// is flagged again while the ones already vouched for stay quiet.
const trustKey = (id, pkg) => `trust:${id}:${pkg}`;
function appRow(base, list, bad, good) {
  const flagged = list.filter((a) => !ticks[trustKey(base.id, a.pkg)]);
  const vouched = list.length - flagged.length;
  return { ...base, apps: flagged, trustable: true, ok: !flagged.length,
    note: flagged.length ? bad(flagged) : good + (vouched ? ` (${plural(vouched, "app", "apps")} you said you set up yourself.)` : "") };
}

function phoneDoses(s) {
  const out = [];
  const a = s.android || {};
  if (s.lock != null) out.push({ id: "p-lock", care: "The phone has no screen lock", name: "Screen lock set", ok: s.lock === true, how: "p-lock",
    note: s.lock ? "Nobody can open it without your PIN, pattern or fingerprint." : "Anyone who picks it up can open your apps, your texts and your OTPs.",
    deep: `KeyguardManager.isDeviceSecure=${s.lock}` });
  if (a.patch) {
    const age = ageDays(a.patch);
    out.push({ id: "p-update", care: "Security updates are old", name: "Security updates recent", ok: age <= 120, how: "p-update",
      note: `Android ${a.release}, security update of ${fmtDate(a.patch)}.` + (age > 120 ? " Holes found since then are still open on this phone." : ""),
      deep: `SECURITY_PATCH=${a.patch} (given if <= 120 days) sdk=${a.sdk} ${a.maker} ${a.model}` });
  }
  const enc = s.encryption;
  if ([1, 3, 4, 5].includes(enc)) out.push({ id: "p-encrypt", care: "Storage isn't encrypted", name: "Storage encrypted", ok: enc !== 1, how: "p-encrypt",
    note: enc === 1 ? "A thief could read your photos and files straight off the chip." : enc === 4 ? "Encrypted - a screen lock ties the key to your PIN." : "A thief can't read your files without your lock.",
    deep: `storageEncryptionStatus=${enc} (1 inactive, 3 active, 4 default key, 5 per user)` });
  const w = s.wifi;
  if (w && w.connected && w.security != null) {
    const weak = w.security === 0 || w.security === 1;
    out.push({ id: "p-wifi", care: "This Wi-Fi has no real password", name: "Wi-Fi is locked", ok: !weak, how: "p-wifi",
      note: !weak ? "The Wi-Fi you're on needs a password." : w.security === 0
        ? "You're on an open Wi-Fi: anyone nearby can join it. Use mobile data for banking."
        : "This Wi-Fi uses WEP, a lock that was broken years ago. Use mobile data for banking.",
      deep: `WifiInfo.currentSecurityType=${w.security} (0 open, 1 WEP, 2 WPA2, 4 WPA3, 6 OWE)` });
  }
  out.push({ id: "p-play", name: "Play Protect scanning", manual: true, how: "p-play",
    note: "Google's scanner for apps. Android doesn't let other apps read it - check once and tap.", deep: "no API: Play Protect state is private to Google Play" });
  out.push({ id: "p-usb", name: "USB debugging off", manual: true, how: "p-usb",
    note: "With it on, a computer plugged in can install apps and copy files. Android shows other apps nothing here - check once and tap.",
    deep: "Settings.Global.ADB_ENABLED is not readable by ordinary apps on Android 16 (returns 0)" });
  return out;
}

// Every installed app's own APK against MalwareBazaar's known samples (25 Sep; check_installed).
// Run after each phone checkup and once the list has downloaded; fingerprints are remembered, so a
// repeat run reads only new or updated apps. null = not run yet.
async function refreshKnown(set) {
  const s = state.scan;
  if (!PHONE || !Array.isArray(s?.apps)) return null;
  if (state.knownRunning) {
    const stop = watchProgress("apps", "apps", set, "p-known");
    try { return await state.knownRunning; } finally { stop(); }
  }
  const mine = s.apps.filter((a) => Array.isArray(a.paths) && a.paths.length).map((a) => ({ pkg: a.pkg, paths: a.paths }));
  // 29 Sep: the apps the phone maker put there are fingerprinted too (cheap phones have shipped
  // with malware built in); only their files - their permissions are not judged.
  const maker = (Array.isArray(s.systemApps) ? s.systemApps : []).filter((a) => Array.isArray(a.paths) && a.paths.length).map((a) => ({ pkg: a.pkg, paths: a.paths, maker: true }));
  const apps = [...mine, ...maker];
  let k;
  const run = (async () => {
    const stop = watchProgress("apps", "apps", set, "p-known");
    try { return await invokeOnce("check_installed", { apps }, "apps"); } catch (e) { return { checked: false, error: String(e) }; } finally { stop(); }
  })();
  state.knownRunning = run;
  renderCard();
  try { k = await run; } finally { state.knownRunning = null; }
  const before = state.known;
  state.known = { ...k, mine: mine.length, maker: maker.length, time: s.time };
  renderCard();
  // A new catch is said at once, whatever the person is doing (the card alone could be missed).
  const had = new Set((before?.found || []).map((f) => f.pkg));
  const fresh = (k.found || []).filter((f) => !had.has(f.pkg));
  if (fresh.length) {
    const hits = fresh.map((f) => appOf(s, f));
    say(`<p><b>Stop - I found a known malware app on this phone.</b></p>` + phoneSlip("severe", "Known malware app", hits, knownWhat(fresh), KNOWN_TREAT),
      { choices: [...appButtons(hits), { label: "Show me how", kind: "main", run: () => showHow([knownRow(s)].filter(Boolean), 0) }] });
  }
  // 29 Sep: an app whose code matches malware rules (or hides the test file / a listed file) - said
  // at once too; an app already named above as known malware is not said twice.
  const hadR = new Set(ruleBad(before).map((h) => h.pkg));
  const freshR = ruleBad(k).filter((h) => !hadR.has(h.pkg) && !fresh.some((f) => f.pkg === h.pkg));
  if (freshR.length) {
    const apps = freshR.map((h) => appOf(s, h));
    say(`<p><b>Stop - I found ${freshR.length === 1 ? "an app" : `${freshR.length} apps`} with harmful code on this phone.</b></p>`
      + freshR.map((h) => phoneSlip("severe", "Harmful code inside", [appOf(s, h)], ruleWhat(h), KNOWN_TREAT)).join(""),
      { choices: [...appButtons(apps), { label: "Show me how", kind: "main", run: () => showHow([knownRow(s)].filter(Boolean), 0) }] });
  }
  return k;
}
const appOf = (s, h) => s.apps.find((a) => a.pkg === h.pkg) || { pkg: h.pkg, label: `${h.pkg} (came with the phone)` };
// The code read (check_installed `ruleHits`): strong = harmful, weak = worth a look.
const ruleBad = (k) => (k?.ruleHits || []).filter((h) => !h.weak);
const ruleLook = (k) => (k?.ruleHits || []).filter((h) => h.weak);
const ruleWhat = (h) => (h.why || []).length ? h.why.join(" ")
  : `Its code matches rules written to recognise known malware (${(h.rules || []).map((r) => r.rule).join(", ")}). Strong evidence, not proof - a few safe tools look alike.`;
const KNOWN_WHAT = "Its exact file is on MalwareBazaar's public list of malware samples - not a guess from its permissions: this very app has been caught doing harm before.";
// The Stop's words for listed apps: an Echap spy-app sample is never credited to MalwareBazaar (29 Sep).
// An app named only by the online checker (hashonline.rs, 29 Sep) is credited to it, never to MalwareBazaar.
const onlineWhat = (src) => `Its exact file is known as malware to a free public checker (CIRCL hashlookup; reported by ${src}). Only its fingerprint was asked about - never the app itself.`;
const knownWhat = (found) => {
  const onl = found.filter((f) => f.online && !f.stalkerware);
  const rest = found.filter((f) => !onl.includes(f));
  const spy = rest.filter((f) => f.stalkerware).map((f) => f.stalkerware);
  const base = !rest.length ? "" : spy.length === rest.length ? spyFile(spy.join(", ")) : spy.length ? `${KNOWN_WHAT} (${spy.join(", ")}: on the Echap list of spy-app samples instead.)` : KNOWN_WHAT;
  if (!onl.length) return base;
  const srcs = [...new Set(onl.map((f) => f.online))].join(", ");
  return base ? `${base} (${onl.map((f) => f.pkg).join(", ")}: ${onlineWhat(srcs)})` : onlineWhat(srcs);
};
const KNOWN_TREAT = "Uninstall it now (if it won't uninstall, take its device-admin power away first). Then change your bank, Google and WhatsApp passwords from another device, and call your bank if it could see your texts.";
const listSize = (k) => k.full ? `${Number(k.count).toLocaleString("en-IN")} known malware samples` : `the last 48 hours' ${Number(k.recent).toLocaleString("en-IN")} known malware samples (the full list waits for Wi-Fi)`;

function knownRow(s) {
  const k = state.known;
  if (state.knownRunning && Array.isArray(s.apps)) {
    return { id: "p-known", how: "p-known", care: "An installed app is known malware", name: "No app is known malware", apps: [], trustable: false,
      note: "Fingerprinting every app on this phone now...", deep: "check_installed running" };
  }
  if (!k?.checked || k.time !== s.time || !Array.isArray(s.apps)) return null;
  const listed = (k.found || []).map((f) => appOf(s, f));
  const spyList = (k.found || []).filter((f) => f.stalkerware);
  const mbList = (k.found || []).filter((f) => !f.stalkerware && !f.online).map((f) => appOf(s, f));
  const onlineList = (k.found || []).filter((f) => !f.stalkerware && f.online);
  const coded = ruleBad(k).filter((h) => !listed.some((a) => a.pkg === h.pkg));
  const hits = [...listed, ...coded.map((h) => appOf(s, h))];
  const unread = (k.unread || []).length;
  const P = k.patterns;
  const look = ruleLook(k).filter((h) => !hits.some((a) => a.pkg === h.pkg));
  const skipped = P?.crashSkipped || [];
  // What the code read did, in words (29 Sep): premium apps read installed apps' code; so does Vigil.
  const codeRead = !P ? ""
    : P.ran ? ` I also read the code inside every one of them with the malware rules and my deep look (hidden files, the antivirus test file, files on the list tucked inside)${P.failed ? ` - ${plural(P.failed, "app file", "app files")} could not be read${skipped.length ? `, including ${plural(skipped.length, "one", "ones")} that made Virus Vigil stop before` : ""}` : ""}.`
    : ` Their code was not read (${P.reason || "the malware rules are not ready"}), only fingerprinted.`;
  const lookWords = look.length ? ` Worth a look, not harmful: ${look.slice(0, 3).map((h) => `${appOf(s, h).label || h.pkg} - ${ruleWhat(h)}`).join(" ")}${look.length > 3 ? ` And ${look.length - 3} more.` : ""}` : "";
  return { id: "p-known", how: "p-known", care: listed.length || !coded.length ? "An installed app is known malware" : "An installed app has harmful code", name: "No app is known malware",
    apps: hits, trustable: false, ok: !hits.length,
    note: hits.length
      ? [mbList.length ? `${appNames(mbList)} ${mbList.length === 1 ? "is" : "are"} on the public list of known malware (MalwareBazaar).` : "",
        ...spyList.map((f) => `${appOf(s, f).label || f.pkg} is ${f.stalkerware}, a known spy app (stalkerware): its exact file is on the Echap list of spy-app samples.`),
        ...onlineList.map((f) => `${appOf(s, f).label || f.pkg} is known as malware to a free public checker (CIRCL hashlookup; reported by ${f.online}) - only its fingerprint was asked about.`),
        ...coded.map((h) => `${appOf(s, h).label || h.pkg}: ${ruleWhat(h)}`),
        `Uninstall ${hits.length === 1 ? "it" : "them"} now.`].filter(Boolean).join(" ")
      : `I fingerprinted every app on this phone - ${k.mine ?? k.apps} you installed${k.maker ? ` and ${k.maker} that came with it` : ""} - and none is one of ${listSize(k)}.${unread ? ` ${plural(unread, "app", "apps")} could not be read.` : ""}${codeRead}${onlineNote(k.online)}${lookWords} An app from the Play Store is rarely on the list - it catches apps installed from a file.`,
    deep: `check_installed: ${k.files} APK files of ${k.apps} apps, SHA-256 against ${k.full ? k.count + " (full list)" : k.recent + " (recent list only)"}, list age ${k.ageHours ?? "?"} h, ${k.fresh} read fresh, ${k.ms} ms. `
      + (P ? `Code read: ${P.ran ? `rules ${P.tag}, ${P.read} read, ${P.remembered} remembered, ${P.failed} failed${P.reason ? ` (${P.reason})` : ""}${P.recovered ? ", recovered after a stop" : ""}${skipped.length ? `, skipped: ${skipped.join(", ")}` : ""}` : `not run (${P.reason || "-"})`}. `
        + `Code hits: ${(k.ruleHits || []).map((h) => `${h.pkg} ${h.rules.map((r) => r.set + "/" + r.rule).join(",")}${h.weak ? " (weak)" : ""}`).join("; ") || "none"}. ` : "")
      + `Unreadable: ${(k.unread || []).join(", ") || "none"}. Matches: ${(k.found || []).map((f) => `${f.pkg} ${f.sha256}`).join(", ") || "none"}` };
}

function appDoses(s) {
  const out = [];
  const apps = Array.isArray(s.apps) ? s.apps : null;
  const known = knownRow(s);
  if (known) out.push(known);
  if (apps) {
    const spies = apps.filter((a) => spyOf(a)).map((a) => ({ ...a, spy: spyOf(a) }));
    const noCerts = apps.filter((a) => !Array.isArray(a.certs)).length;
    out.push(appRow({ id: "p-spy", how: "p-spy", care: "A known spy app is installed", name: "No known spy app",
      deep: `checked ${apps.length} installed apps against ${SPY_LIST.apps} known spy apps (${SPY_LIST.packages} app ids, ${SPY_LIST.certs} signing certificates; list: ${SPY_LIST.credit}, ${SPY_LIST.commit}). `
        + (noCerts ? `Certificates unreadable for ${noCerts} app(s) - those were matched by app id only. ` : "")
        + `Matches: ${spies.map((a) => `${a.pkg} = ${a.spy.name} (by ${a.spy.by})`).join(", ") || "none"}` },
    spies,
    (l) => `${l.map((a) => `${a.label || a.pkg} (known spy app: ${a.spy.name})`).join(", ")}. Spy apps secretly send your messages, calls, photos and location to whoever put them here.`,
    "None of your apps is on the public list of known spy apps."));
  }
  if (Array.isArray(s.accessibility)) {
    out.push(appRow({ id: "p-access", how: "p-access", care: "An app can see and tap your screen", name: "No stranger controls the screen",
      deep: `enabled accessibility services: ${s.accessibility.map((r) => r.pkg + (r.system ? " (system)" : "")).join(", ") || "none"}` },
    s.accessibility.filter((r) => !r.system),
    (l) => `${appNames(l)} ${l.length === 1 ? "is" : "are"} switched on as a screen helper (accessibility): it can read everything on screen and tap for you. Fine only if you turned it on yourself for a real need.`,
    "No app you installed is switched on as a screen helper."));
  }
  if (Array.isArray(s.notifReaders)) {
    out.push(appRow({ id: "p-notif", how: "p-notif", care: "An app reads your notifications", name: "No stranger reads your notifications",
      deep: `notification access: ${s.notifReaders.map((r) => r.pkg + (r.system ? " (system)" : "")).join(", ") || "none"}` },
    s.notifReaders.filter((r) => !r.system),
    (l) => `${appNames(l)} ${l.length === 1 ? "is" : "are"} allowed to read every notification - including OTP codes, bank alerts and chat messages. Fine only if you turned it on yourself for a real need, like a smartwatch.`,
    "No app you installed can read your notifications."));
  }
  if (Array.isArray(s.admins)) {
    out.push(appRow({ id: "p-admin", how: "p-admin", care: "An app has device-admin power", name: "No app can lock or wipe the phone",
      deep: `active device admins: ${s.admins.map((r) => r.pkg + (r.system ? " (system)" : "")).join(", ") || "none"}` },
    s.admins.filter((r) => !r.system),
    (l) => `${appNames(l)} can lock or wipe the phone and ${l.length === 1 ? "is" : "are"} hard to uninstall. Fine for a work or school app; otherwise remove it.`,
    "No app you installed has device-admin power."));
  }
  if (apps) {
    const remote = apps.filter(isRemote);
    out.push(appRow({ id: "p-remote", how: "p-remote", care: "A screen-sharing app is installed", name: "No screen-sharing app",
      deep: `remote-control apps: ${remote.map((a) => `${a.pkg} (${a.installer || "no installer"})`).join(", ") || "none"}` },
    remote,
    (l) => `${appNames(l)} lets someone else watch and control this phone. If anyone on a call asked you to install it, that is the scam - uninstall it.`,
    "No app that lets someone else control this phone."));
  }
  if (s.sms) {
    const odd = !s.sms.system && !SMS_APPS.has(s.sms.pkg);
    out.push(appRow({ id: "p-sms", how: "p-sms", care: "An unusual app reads your texts", name: "Texts go to a known app",
      deep: `default SMS app: ${s.sms.pkg} system=${s.sms.system}` },
    odd ? [s.sms] : [],
    (l) => `${appNames(l)} is your texts app, so it reads every SMS - including OTPs. Fine only if you chose it.`,
    `Your texts go to ${s.sms.label || s.sms.pkg}.`));
  }
  if (apps) {
    const outside = apps.filter((a) => !fromStore(a));
    const trojan = outside.filter((a) => combosOf(a).length);
    const blind = outside.filter((a) => a.offers === null);
    const strong = outside.filter((a) => !trojan.includes(a) && strongOf(a).length);
    if (!trojan.length && blind.length) out.push({ id: "p-trojan", name: "Banking-Trojan powers", manual: true, how: "p-trojan", apps: blind,
      note: `Android wouldn't show me what ${appNames(blind)} can do. Check ${blind.length === 1 ? "it" : "them"} in Accessibility and Notification access, then tap.`,
      deep: `offers unread (null) for: ${blind.map((a) => a.pkg).join(", ")}` });
    else out.push(appRow({ id: "p-trojan", how: "p-trojan", care: "An app has banking-Trojan powers", name: "No app with banking-Trojan powers",
      deep: trojan.map((a) => `${a.pkg}: ${combosOf(a).map((c) => c.needs.map((n) => n.replace("android.permission.", "")).join("+")).join(", ")}`).join("; ") || "no outside-store app matches a pair" },
    trojan,
    (l) => `${appNames(l)} came from outside a store and can do what banking Trojans do - control the screen or read your texts or notifications, with the internet to send them on.`,
    "No app from outside a store has the power pairs banking Trojans use."));
    out.push(appRow({ id: "p-outside", how: "p-outside", care: "Apps from outside a store have strong powers", name: "Outside-store apps look ordinary",
      deep: `outside a store (${outside.length}): ${outside.map((a) => `${a.pkg} (${a.installer || "no installer"})`).join(", ") || "none"}` },
    strong,
    (l) => `${appNames(l)} came from outside a store and ${l.length === 1 ? "has" : "have"} strong powers: ${[...new Set(l.flatMap(strongOf))].slice(0, 3).map((x) => PERMISSIONS[x].plain.split(" - ")[0].split(" (")[0]).join("; ")}.`,
    outside.length ? "The apps from outside a store have only ordinary powers." : "Every app you installed came from a store."));
    // Only when the phone did not say who actually HAS notification access (the live p-notif row above).
    const listeners = apps.filter((a) => (a.offers || []).includes(NLS));
    const unseen = apps.filter((a) => a.offers === null);
    if (!Array.isArray(s.notifReaders)) out.push(listeners.length || unseen.length
      ? { id: "p-notif", name: "Who reads your notifications", manual: true, how: "p-notif", apps: listeners,
          note: listeners.length ? `${appNames(listeners)} can be allowed to read every notification, OTPs included. Check who actually has it, then tap.` : `Android wouldn't show me what ${appNames(unseen)} can do. Check Notification access, then tap.`, deep: `offer ${NLS}: ${listeners.map((a) => a.pkg).join(", ") || "-"}; unread: ${unseen.map((a) => a.pkg).join(", ") || "-"}` }
      : { id: "p-notif", name: "Who reads your notifications", ok: true, how: "p-notif", note: "No app you installed can be made to read notifications.", deep: `no installed app offers ${NLS}` });
  }
  return out;
}

function phonePast(s) {
  return [
    { id: "past-reviewed", name: "Takeover signs checked", manual: true,
      note: "Tap “Was I hacked before?” - I look for what phone thieves leave behind.", deep: "device admins, screen helpers, remote apps, Trojan pairs, texts app" },
    ...(s ? [folderRow()] : []),
    ...ACCOUNTS.map((a) => ({ id: a.id, name: a.name, manual: true, note: a.phone ? "In the app" : "One web page", acc: a })),
  ];
}

Object.assign(HOWTO, {
  "p-lock": { settings: "lock", open: "Set a screen lock", steps: ["Tap the button - it opens the screen-lock page", "Choose a PIN, pattern or password (a 6-digit PIN is a good start)", "Add a fingerprint or face too if you like", "Come back and press “Check again”"] },
  "p-update": { settings: "about", open: "Open About phone", steps: ["Settings", "Type “update” in the Settings search box", "System update (or Software update)", "Download and install, then restart", "Nothing offered? The maker may have stopped updating this phone - keep banking on a newer one if you can"] },
  "p-encrypt": { settings: "security", open: "Open Security settings", steps: ["Set a screen lock first - on most phones that switches encryption on by itself", "Settings → Security → Encryption", "Follow the steps (keep the phone charging)"] },
  "p-wifi": { settings: "wifi", open: "Open Wi-Fi settings", steps: ["For banking or payments, switch Wi-Fi off and use mobile data", "At home: log in to your router and set WPA2 or WPA3 with a long password", "Tap this Wi-Fi → Forget, if you don't need it"] },
  "p-play": { settings: "security", open: "Open Security settings", steps: ["Open the Play Store app", "Tap your profile picture (top right)", "Play Protect", "Tap the gear → switch on “Scan apps with Play Protect”", "Press Scan, then come back and tap the circle"] },
  "p-usb": { settings: "developer", open: "Open Developer options", steps: ["Tap the button - if Settings opens on its main page, Developer options is hidden and USB debugging is already off", "Otherwise find “USB debugging” and switch it off", "You can switch Developer options off entirely at the top of that page", "Come back and tap the circle"] },
  "p-access": { settings: "accessibility", open: "Open Accessibility", steps: ["Tap the button - it opens Accessibility", "Look under “Downloaded apps” or “Installed services”", "Switch off each app named here that you didn't turn on for a real need", "Then uninstall it from its app page (buttons below)"] },
  "p-admin": { settings: "security", open: "Open Security settings", steps: ["Settings → Security (or Security & privacy) → More → Device admin apps", "Type “device admin” in the Settings search box if you can't find it", "Switch off each app named here", "Then uninstall it from its app page (buttons below)"] },
  "p-spy": { steps: ["If you are afraid of the person who may have put it there, get help BEFORE removing it - removing it can warn them. Call 181 (women helpline) or 112 from a phone they cannot see", "Otherwise: if it has device-admin power, take that away first (the card's device-admin row)", "Open its app page (button below) → Uninstall", "Then set a new screen-lock PIN and change your Google, WhatsApp and bank passwords - whoever installed it knew your old PIN"] },
  "p-folders": { steps: ["Don't open the file. If it is an app file (.apk), don't install it", "Open the Files app (Files by Google, or your phone's File Manager)", "Find the file - its full path is in the note (Download is the usual place, or WhatsApp → Media → WhatsApp Documents)", "Press and hold it → Delete, and empty the Files app's bin if it has one", "If you ever installed or opened it: change your Google, WhatsApp and bank passwords from another device", "Come back and press “Check my phone”"] },
  "p-known": { steps: ["Open its app page (button below) → Uninstall. If Uninstall is greyed out, it has device-admin power: take that away first (the card's device-admin row), then uninstall", "If it still won't go: restart in Safe mode (hold the power-off button on screen), then uninstall it there", "From ANOTHER device, change your Google, WhatsApp and bank passwords - it may have read them", "If it could read your texts or notifications, call your bank on the number on your card and ask them to watch your account; report fraud at 1930", "Run this check again to see the row go green"] },
  "p-remote": { steps: ["If anyone on a call asked you to install it - “bank support”, “refund team”, “KYC” - that is the scam", "Open its app page (button below) → Uninstall", "If you sent money or shared a code: call your bank on the number on your card, and 1930"] },
  "p-sms": { settings: "defaultApps", open: "Open Default apps", steps: ["Tap the button - it opens Default apps", "SMS app", "Choose Messages (or your phone maker's texts app)", "Then uninstall the other one if you don't know why it's there"] },
  "p-trojan": { steps: ["Do you know exactly why you installed it, and who made it? If not:", "Open its app page (button below) → Uninstall", "Uninstall greyed out? Take its device-admin power away first (the card's device-admin row)", "Then change your bank and email passwords from this phone, and call your bank"] },
  "p-outside": { steps: ["Apps from outside a store skip the store's checks", "Open each app page (buttons below) → Permissions", "Take away any power it doesn't need, or uninstall it", "Get apps from the Play Store or your phone maker's store from now on"] },
  "p-notif": { settings: "notificationAccess", open: "Open notification access", steps: ["Tap the button - it opens Notification access (or Device & app notifications)", "Each app switched on there reads every notification, OTPs included", "Keep only ones you know (a smartwatch, a music app)", "Switch off the rest, then come back here"] },
});

function trustApps(d) {
  const now = new Date().toISOString();
  for (const a of d.apps || []) ticks[trustKey(d.id, a.pkg)] = now;
  store.set("vv.ticks", ticks);
  renderCard(d.id);
  say(`<p>Noted - I won't flag ${d.apps.length === 1 ? "it" : "them"} again for this. A new app with the same power will still be flagged.</p>`);
}

async function freshPhoneScan() {
  if (state.scan && Date.now() - new Date(state.scan.time).getTime() < 10 * 60 * 1000) return state.scan;
  const s = await phone("scan");
  s.time = new Date().toISOString();
  state.scan = s;
  await refreshKnown();
  renderCard();
  return s;
}

async function phoneCheckup() {
  const t0 = performance.now();
  const done = thinking("Checking this phone - a few seconds...");
  let s;
  try { s = await phone("scan"); }
  finally { done(); }
  s.time = new Date().toISOString();
  state.scan = s;
  renderCard();
  // AWAITED (29 Sep, his "It took 2 seconds to scan my phone how???"): the summary used to come
  // after the settings read alone (~2 s) with the file reading left running unseen, so "What I
  // checked ... in 2.0 seconds" read as the whole scan. Now it waits, counting live in the bubble.
  const live = thinkingLive("Fingerprinting every app on this phone...");
  try {
    await refreshKnown(live.set);
    live.set("Reading every file in phone storage...");
    await refreshFolders(live.set);
    while (state.foldersRunning) await new Promise((r) => setTimeout(r, 700));
  } finally { live.done(); }
  state.checkMs = performance.now() - t0;
  renderCard();
  summarize();
  takeShareSoon();
}

// "Scan everything" on a phone: Android keeps each app's files sealed, so no app can open them all.
// The check of this phone, then Play Protect (Google's scanner, which can) run once by hand.
async function phoneSweep() {
  await phoneCheckup();
  const live = thinkingLive("Fingerprinting every app on this phone...");
  let k;
  try { k = await refreshKnown(live.set); }
  finally { live.done(); }
  k = state.known || k;
  let f = state.folders;
  if (state.foldersRunning || !f?.needsAccess) {
    const live2 = thinkingLive("Reading every file in phone storage...");
    try {
      // The checkup already started it: wait for that run instead of starting a second one.
      while (state.foldersRunning) { live2.set((progressWords((await invoke("sweep_progress")).files, "phone storage")) || "Reading every file in phone storage..."); await new Promise((r) => setTimeout(r, 700)); }
      f = state.folders?.checked || state.folders?.needsAccess ? state.folders : await refreshFolders(live2.set);
    } finally { live2.done(); }
    f = state.folders || f;
  }
  // The receipt: what was actually read, counted by the code that read it.
  const n = (x) => Number(x || 0).toLocaleString("en-IN");
  const appsLine = k?.checked
    ? `<b>Apps:</b> ${n(k.files)} app files of ${n(k.apps)} apps (${n(k.mine)} you installed, ${n(k.maker)} that came with the phone), each fingerprint compared with ${listSize(k)}. ${n(k.fresh)} read fresh this time, the rest remembered. `
      + (k.patterns?.ran ? `The code inside every app file read with the malware rules and my deep look: ${n(k.patterns.read)} read now, ${n(k.patterns.remembered)} remembered${k.patterns.failed ? `, ${n(k.patterns.failed)} could not be read` : ""}. `
        : `Their code was NOT read (${esc(k.patterns?.reason || "no answer")}). `)
      + `${secsWords(k.ms || 0)}.`
    : `<b>Apps:</b> not compared - ${esc(k?.error || "the known-malware list isn't downloaded yet (it needs internet once)")}.`;
  const filesLine = f?.needsAccess
    ? `<b>Phone storage:</b> not read - Android needs you to switch on “All files access” for Virus Vigil first.`
    : f?.checked ? `<b>Phone storage:</b> ${esc(folderRow().note)} ${secsWords(f.ms || 0)}, ${n(f.fresh)} files read fresh.${folderLookFold(f)}`
    : `<b>Phone storage:</b> not read - ${esc(f?.error || f?.list?.error || "unknown")}.`;
  say(`<p><b>Here is exactly what I read:</b></p><ul><li>${appsLine}</li><li>${filesLine}</li></ul>`
    + `<p>A file I read before is remembered by its name, size and date, so a second check only reads what is new - that is why it's quick. “Read everything again from scratch” reads every byte again.</p>`
    + `<p><b>What no phone app can open is each app's own private data</b> - Android keeps it sealed. The scanner that looks there is <b>Google Play Protect</b>, built into your phone.</p>`,
    { choices: [
      ...(f?.needsAccess ? [{ label: "Allow and sweep", kind: "main", run: allowFiles }] : []),
      { label: "Run Play Protect", kind: f?.needsAccess ? undefined : "main", run: () => { const d = Object.values(allDoses()).flat().find((x) => x.id === "p-play"); if (d) showHow([d], 0); } },
      { label: "Read everything again from scratch", run: () => guarded(rereadAll) },
      { label: "Not now", kind: "quiet", run: bye },
    ] });
}

// ---------- phone "Do it all for me" (his words 8 Oct 2026) ----------
// "do whatevr can be done for phone app and leave the rest, and mention that because android doesnt
// let us we cant so u have to but all these are automated for pc". Vigil itself re-reads every app and
// every file; each step Android keeps for the person is opened for them, one at a time, saying why.
const ANDROID_NO = "Android doesn't let any app - not even a security app - change this for you, so this step is your tap. On a laptop, Virus Vigil does steps like this by itself.";
const FILES_STEP = { id: "p-files-access", care: "Let Virus Vigil read your files", how: "p-files-access",
  note: "Android makes you allow this yourself, once, before any app may open other apps' downloads. I only read files to fingerprint them - nothing is changed, moved or sent.",
  why: "Android lets only you switch this on - no app can switch it on for itself." };
HOWTO["p-files-access"] = { settings: "allFiles", open: "Open the switch", steps: ["Tap “Open the switch”", "Turn on “Allow access to manage all files” for Virus Vigil", "Come back and press “Done” - I sweep your files by myself"] };
// Rows whose fix is removing an app: one tap opens Android's own uninstall box for it.
const UNINSTALL_ROWS = new Set(["p-known", "p-remote", "p-trojan"]);
const uninstallButtons = (apps) => apps.slice(0, 6).map((a) => ({ label: `Uninstall ${a.label || a.pkg}`, keep: true, run: () => openPhoneSettings("uninstall", a.pkg) }));

// What still needs the person's own tap: red rows and the hand-checked ones not yet stamped.
function phoneHandRows() {
  if (!PHONE || !state.scan) return [];
  const g = allDoses();
  return [...g.laptop, ...g.deeper, ...g.past.filter((d) => !d.manual)].filter((d) => {
    const st = doseState(d);
    return st === "open" || (st === "due" && d.manual);
  });
}

function phoneAllFlow() {
  const rows = phoneHandRows();
  say(`<p><b>On a phone, “do it all” works in two parts.</b></p>`
    + `<p><b>What I do myself:</b> check every app against the known-malware list, read the code inside each one, and sweep every file in phone storage.</p>`
    + (rows.length ? `<p><b>What needs your tap:</b> ${esc(rows.map((d) => d.care || d.name).join(" · "))}.</p><p>${esc(ANDROID_NO)} I'll open each page for you, one at a time, and say exactly what to press.</p>`
      : `<p>Nothing else needs your tap right now.</p>`)
    + (state.folders?.needsAccess ? `<p>First, Android asks you once to let me read your files.</p>` : ""),
  { choices: [{ label: "Start", kind: "main", run: () => guarded(phoneAllRun) }, { label: "Not now", kind: "quiet", run: bye }] });
}

async function phoneAllRun() {
  await phoneCheckup();
  phoneStep(new Set());
}

// One step at a time, worked out fresh each time (a sweep can turn a new row red on the way).
function phoneStep(done) {
  const left = [...(state.folders?.needsAccess ? [FILES_STEP] : []), ...phoneHandRows()].filter((d) => !done.has(d.id));
  if (!left.length) {
    return say(`<p><b>That's every step.</b> Let me check the phone again to see what changed.</p>`,
      { choices: [{ label: "Check again", kind: "main", run: () => guarded(checkup) }, { label: "Later", kind: "quiet", run: bye }] });
  }
  const d = left[0];
  const n = done.size + 1, total = done.size + left.length;
  const on = () => { done.add(d.id); phoneStep(done); };
  const next = d === FILES_STEP
    ? { label: "Done - sweep my files", kind: "main", run: () => guarded(async () => { await sweepFoldersNow(); on(); }) }
    : { label: n < total ? "Done - next step" : "Done - finish", kind: "main", run: () => { if (d.manual) setTick(d.id, true); on(); } };
  const c = [...howButtons(d), ...(UNINSTALL_ROWS.has(d.id) && d.apps?.length ? uninstallButtons(d.apps) : []), next,
    { label: "Skip this one", kind: "quiet", run: on }];
  say(`<p><b>Step ${n} of ${total}: ${esc(d.care || d.name)}</b></p><p>${esc(d.note || "")}</p><p>${esc(d.why || ANDROID_NO)}</p>${pathHtml(HOWTO[d.how]?.steps || [])}`,
    { choices: c });
}

function phoneMoreChecks() {
  say(`<p>Which one?</p>`, { choices: [
    { label: "Before a big payment", run: () => guarded(phonePaymentFlow) },
    { label: "Check my apps", run: () => guarded(phoneAppsFlow) },
    { label: "Who used my camera or mic?", run: phoneCameraFlow },
    { label: "Has my password leaked?", run: passwordFlow },
    { label: "Check a message someone sent me", run: phoneSafeIntro },
    { label: "Not now", kind: "quiet", run: bye },
  ] });
}

const phoneSlip = (sev, title, apps, what, treat) =>
  `<article class="slip sev-${sev}"><div class="slip-head"><span class="slip-label">DIAGNOSIS</span><b>${esc(title)}</b><span class="slip-count">${esc(appNames(apps))}</span></div>`
  + `<p><b>What it is:</b> ${esc(what)}</p><p><b>Treatment:</b> ${esc(treat)}</p></article>`;
const appButtons = (apps) => apps.slice(0, 6).map((a) => ({ label: `Open ${a.label || a.pkg}`, keep: true, run: () => openPhoneSettings("app", a.pkg) }));

// The phone's app checks. Each row exists only when Android gave the data, so a missing row means
// NOT CHECKED - never "nothing found" (31 Oct 2026).
const PHONE_ROWS = { "p-known": "the known-malware list", "p-spy": "the spy-app list", "p-trojan": "banking-Trojan powers",
  "p-admin": "device-admin power", "p-access": "screen control", "p-notif": "who reads notifications", "p-remote": "screen-sharing apps", "p-sms": "your texts app" };
const phoneUnchecked = (ids) => Object.keys(PHONE_ROWS).filter((id) => !ids.includes(id));
async function phoneHacked() {
  const done = thinking("Looking for what phone thieves leave behind...");
  let s;
  try { s = await freshPhoneScan(); }
  finally { done(); }
  const rows = Object.fromEntries(appDoses(s).map((r) => [r.id, r]));
  const hit = (id) => rows[id]?.apps?.length && !rows[id].manual ? rows[id].apps : null;
  const signs = [
    ["p-known", "severe", "Known malware app", KNOWN_WHAT, KNOWN_TREAT],
    ["p-spy", "severe", "Known spy app (stalkerware)", "It is on the public list of spy apps: it secretly sends your messages, calls, photos and location to whoever installed it - usually someone who had your phone in their hands.", "If you are afraid of that person, get help first (181 or 112) - removing it can warn them. Otherwise uninstall it, set a new screen-lock PIN and change your passwords."],
    ["p-trojan", "severe", "Banking-Trojan powers", "An app from outside a store that can control the screen or read your texts and notifications - how banking Trojans take OTPs and money.", "Unless you know exactly why it's there, uninstall it. Then change your bank and email passwords and call your bank."],
    ["p-admin", "severe", "Device-admin power", "It can lock or wipe the phone and blocks its own uninstall.", "Unless it's your work or school's app: switch its device-admin power off in Security settings, then uninstall it."],
    ["p-access", "high", "Screen control (accessibility)", "It sees everything on your screen and can tap for you - the power banking Trojans ask for first.", "If you didn't turn it on for a real need, switch it off in Accessibility and uninstall it."],
    ["p-notif", "high", "Reads your notifications", "It sees every notification as it arrives - OTP codes, bank alerts and chat messages.", "If you didn't turn it on for a real need (a smartwatch, say), switch it off in Notification access and uninstall it."],
    ["p-remote", "high", "Screen-sharing app", "It lets someone else watch and control this phone.", "If someone on a call asked you to install it, that was the scam: uninstall it, call your bank, and report at 1930."],
    ["p-sms", "moderate", "An unusual texts app", "Your texts app reads every SMS, including OTPs.", "Unless you chose it, set Messages back as the SMS app (Default apps) and uninstall this one."],
  ].filter(([id]) => hit(id));
  const flagged = [...new Map(signs.flatMap(([id]) => hit(id)).map((a) => [a.pkg, a])).values()];
  const after = [{ label: "Check my accounts", kind: "main", run: () => sweep(0) }, ...appButtons(flagged), { label: "Not now", kind: "quiet", run: bye }];
  const blind = `<p>What a phone app can't see: other apps' own files, whether someone knows your PIN, and your accounts on other devices - the account check covers that last one.</p>`;
  const unchecked = phoneUnchecked(Object.keys(rows));
  const gap = unchecked.length ? `<p><b>I couldn't check ${unchecked.map((id) => PHONE_ROWS[id]).join(", ")}</b> - Android didn't give me that${unchecked.includes("p-known") ? ", or the known-malware list isn't on the phone yet" : ""}. So this is not a full all-clear.</p>` : "";
  if (!signs.length && unchecked.length) {
    say(`<p><b>In what I could check, I found none of the usual signs of a taken-over phone.</b></p>${gap}${blind}`
      + deep(Object.values(rows).map((r) => `<b>${esc(r.id)}</b> ${esc(r.deep)}`).join("<br>") + `<br>not checked: ${esc(unchecked.join(", "))}`), { choices: after });
  } else if (!signs.length) {
    say(`<p><b>Good news: I found none of the usual signs of a taken-over phone.</b> No known spy app, and no stranger has device-admin power, screen control, your notifications, a screen-sharing app or your texts.</p>${blind}`
      + deep(Object.values(rows).map((r) => `<b>${esc(r.id)}</b> ${esc(r.deep)}`).join("<br>")), { choices: after });
  } else {
    say(`<p>I found <b>${plural(signs.length, "sign", "signs")}</b> worth a look. Each one is fine if you set it up yourself on purpose - otherwise treat it now.</p>`
      + signs.map(([id, sev, title, what, treat]) => phoneSlip(sev, title, hit(id), what, treat)).join("") + gap + blind
      + deep(signs.map(([id]) => `<b>${esc(id)}</b> ${esc(rows[id].deep)}`).join("<br>")), { choices: after });
  }
  // Reviewed only when every check ran - a partial look is not a review.
  if (!unchecked.length) setTick("past-reviewed", true);
}

// The phone's own check before a big payment (his rule: optional, only on request).
async function phonePaymentFlow() {
  const done = thinking("Checking this phone before you pay - a few seconds...");
  let s;
  try { s = await freshPhoneScan(); }
  finally { done(); }
  const rows = Object.fromEntries([...phoneDoses(s), ...appDoses(s)].map((r) => [r.id, r]));
  const levels = [];
  let body = "";
  // A screen-sharing app counts even if the person vouched for it: close it before paying anyway.
  const apps = Array.isArray(s.apps) ? s.apps : [];
  const remote = apps.filter(isRemote);
  if (!Array.isArray(s.apps)) { levels.push("careful"); body += `<div class="flag careful">Android wouldn't give me the app list, so I can't tell you whether a screen-sharing app is installed.</div>`; }
  else if (remote.length) {
    levels.push("danger");
    body += `<div class="flag danger"><b>${esc(appNames(remote))} ${remote.length === 1 ? "is" : "are"} installed.</b> ${remote.length === 1 ? "It lets" : "These let"} someone else watch and control this phone. `
      + `If anyone on a call asked you to install ${remote.length === 1 ? "it" : "them"}, <b>that is the scam: hang up, uninstall, and don't pay.</b> If it's yours for your own reasons, make sure it isn't connected before you pay.</div>`;
  } else body += `<div class="flag good">No screen-sharing app is installed.</div>`;
  const careful = [
    ["p-access", (r) => `${appNames(r.apps)} - close it, or switch it off in Accessibility, before you pay.`],
    ["p-notif", (r) => `${appNames(r.apps)} - it can read the OTP your bank sends. Switch it off in Notification access before you pay.`],
    ["p-spy", (r) => `${appNames(r.apps)} - a spy app can see what you type. Don't pay from this phone until it's dealt with.`],
    ["p-trojan", (r) => `${appNames(r.apps)} - don't pay from this phone until it's uninstalled.`],
    ["p-lock", () => "Set one soon - anyone holding this phone can read your texts and OTPs."],
    ["p-wifi", (r) => r.note],
  ];
  for (const [id, text] of careful) {
    const r = rows[id];
    if (r && r.ok === false) { const bad = id === "p-trojan" || id === "p-spy"; levels.push(bad ? "danger" : "careful"); body += `<div class="flag ${bad ? "danger" : "careful"}"><b>${esc(r.care)}:</b> ${esc(text(r))}</div>`; }
  }
  const overlay = apps.filter((a) => !fromStore(a) && powersOf(a).includes(SAW));
  if (overlay.length) { levels.push("careful"); body += `<div class="flag careful"><b>${esc(appNames(overlay))} can draw over other apps</b> and came from outside a store - the way fake bank screens are shown. Close ${overlay.length === 1 ? "it" : "them"} first.</div>`; }
  body += `<p><b>Then, for the payment itself:</b></p>` + pathHtml([
    "Open the bank's or UPI app yourself - never from a link in a message.",
    "If someone is on the phone telling you what to press, stop. Real banks never guide you through a payment.",
    "Your UPI PIN only ever SENDS money. Nobody needs it for you to receive money or a refund.",
    "Look at the name the UPI app shows before you enter the PIN - it's who really gets the money.",
  ]);
  body += deep(`remote apps: ${esc(remote.map((a) => a.pkg).join(", ") || "none")}; overlay outside store: ${esc(overlay.map((a) => a.pkg).join(", ") || "none")}. Rows: ${esc(["p-access", "p-trojan", "p-lock", "p-wifi"].map((id) => `${id}=${rows[id]?.ok}`).join(" "))}.`);
  say(verdictHtml(worst(levels)) + body, { choices: [
    ...appButtons([...remote, ...overlay]),
    { label: "Check again", run: () => { state.scan = null; guarded(phonePaymentFlow); } },
    { label: "That's all, thanks", kind: "quiet", run: bye },
  ] });
}

// Every app from outside a store, with what it can do - the phone version of the APK report.
async function phoneAppsFlow() {
  const done = thinking("Reading what each app can do...");
  let s;
  try { s = await freshPhoneScan(); }
  finally { done(); }
  if (!Array.isArray(s.apps)) { say(`<p>Android wouldn't give me the list of apps on this phone, so I can't check them.</p>`); return; }
  const outside = s.apps.filter((a) => !fromStore(a));
  const rank = (a) => (combosOf(a).length ? 0 : strongOf(a).length ? 1 : 2);
  outside.sort((a, b) => rank(a) - rank(b) || (a.label || "").localeCompare(b.label || ""));
  const storeCount = s.apps.length - outside.length;
  let html = `<p>You installed <b>${plural(s.apps.length, "app", "apps")}</b>: ${storeCount} from a store, <b>${outside.length} from outside a store</b>.</p>`;
  if (!outside.length) html += `<p><b>Every app came from a store.</b> Stores check apps (not perfectly) and Play Protect keeps scanning them - your card has a row for it.</p>`;
  const permLine = (x) => `<div class="perm ${PERMISSIONS[x].risk}"><span class="dot"></span><span>${esc(PERMISSIONS[x].plain)}</span></div>`;
  for (const a of outside.slice(0, 20)) {
    const known = powersOf(a).filter((x) => PERMISSIONS[x] && PERMISSIONS[x].risk !== "normal").sort((x, y) => RISK_ORDER.indexOf(PERMISSIONS[x].risk) - RISK_ORDER.indexOf(PERMISSIONS[y].risk));
    html += `<div class="app-block"><p><b>${esc(a.label || a.pkg)}</b> <small>${esc(whereFrom(a))}${a.installed ? ` · ${fmtDate(new Date(a.installed).toISOString())}` : ""}</small></p>`
      + combosOf(a).map((c) => `<div class="flag danger">${esc(c.says)}</div>`).join("")
      + (known.length ? known.map(permLine).join("") : `<p><small>Nothing unusual it can do.</small></p>`) + `</div>`;
  }
  if (outside.length > 20) html += `<p>… and ${outside.length - 20} more.</p>`;
  if (outside.length) html += `<p>An app from outside a store isn't bad by itself - but it skipped every check. Keep only the ones you know.</p>`;
  html += deep(s.apps.map((a) => `${esc(a.pkg)} installer=${esc(a.installer)} powers=${esc(powersOf(a).map((x) => x.replace("android.permission.", "")).join(","))}`).join("<br>"));
  say(html, { choices: [...appButtons(outside.filter((a) => rank(a) < 2)), { label: "Check again", run: () => { state.scan = null; guarded(phoneAppsFlow); } }, { label: "That's all, thanks", kind: "quiet", run: bye }] });
}

// Android keeps each app's camera and microphone use private; the phone's own Privacy page shows it.
function phoneCameraFlow() {
  say(`<p>Android doesn't let one app see another app's camera or microphone use, so I can't list it - but the phone keeps its own record:</p>`
    + pathHtml(["Tap the button - it opens Privacy", "Privacy dashboard (Android 12 or newer)", "Camera, then Microphone: which apps used it recently", "An app you don't expect? Tap it and take the permission away"])
    + `<p>A <b>green dot</b> at the top right of the screen means the camera or microphone is on right now.</p>`, {
    choices: [{ label: "Open Privacy settings", keep: true, run: () => openPhoneSettings("privacy") }, { label: "OK", kind: "quiet", run: bye }],
  });
}

function phoneSafeIntro() {
  say(`<p>Paste a <b>link</b> or a <b>message</b> in the box below, or <b>choose a file</b> (an app, a download, an attachment).</p>`
    + `<p>Easiest of all: <b>share it to me from any app</b> - in WhatsApp, Messages or Files press <b>Share → Virus Vigil</b>.</p><p>I look at it here on this phone. <b>The file is never uploaded</b> - only its fingerprint (a code worked out from it) is asked about online.</p>`,
    { choices: [{ label: "Choose a file", run: chooseFile }] });
}

function phoneNotHere(what) {
  const text = {
    startup: "Phones don't have a list of programs that start by themselves the way Windows does. What matters on a phone is which apps hold strong powers - I can check that.",
    addons: "Browser add-ons are a laptop thing - Chrome on Android doesn't take them. On a phone the same danger comes from apps with strong powers.",
    ransomware: "Android keeps every app in its own box, so ransomware that scrambles all your files is rare on phones. A backup is still the real cure: Settings → Google → Backup keeps your photos and data safe.",
  }[what];
  say(`<p>${esc(text)}</p>`, { choices: [{ label: "Check my apps", run: () => guarded(phoneAppsFlow) }, { label: "OK", kind: "quiet", run: bye }] });
}

// Anything shared into Vigil ("Share -> Virus Vigil"). Waits while a check is running, so a share
// that opened the app is handled right after the first checkup.
let shareTimer = null;
function takeShareSoon() {
  if (!PHONE || shareTimer) return;
  const tick = async () => {
    if (state.busy) { shareTimer = setTimeout(tick, 1000); return; }
    shareTimer = null;
    let r;
    try { r = await phone("takeShare"); } catch { return; }
    if (r.file) await guarded(() => checkFile(r.file));
    if (r.text) { you(r.text); await analyze(r.text).catch((e) => say(`<p>Something went wrong on my side: ${esc(e)}</p>`)); }
  };
  shareTimer = setTimeout(tick, 300);
}

function phoneStart() {
  document.body.classList.add("phone");
  const set = (sel, text) => { const el = $(sel); if (el) el.textContent = text; };
  set(".pin[data-go=checkup] b", "Check my phone");
  const live = $(".who p");
  if (live?.lastChild) live.lastChild.textContent = "watching this phone";
  set(".pass-id h2", "This phone");
  set(".card-foot .honest", "This closes the common doors. Nothing makes a phone 100% safe.");
  $("#ask-input")?.setAttribute("placeholder", "Paste a link or message, or ask “what is phishing?”");
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") takeShareSoon(); });
}

// Licences and credits, Privacy, Terms (29 Sep 2026, LEGAL-CHECK.md; his words "put some legal
// notices ... we credit these people"). Shown in a frame over the app so the chat and card stay.
function showLegal(page) {
  const d = $("#legal");
  if (!d) return;
  d.querySelector("iframe").src = page;
  d.showModal();
}
document.querySelectorAll("[data-legal]").forEach((b) => b.addEventListener("click", () => showLegal(b.dataset.legal)));
$("#legal .legal-close")?.addEventListener("click", () => $("#legal").close());

// ---------- wiring ----------
const DOORS = { checkup: () => guarded(checkup), hacked: () => guarded(hacked), safe: safeIntro };
document.querySelectorAll(".pin").forEach((b) => b.addEventListener("click", () => {
  if (state.busy) return;
  you(b.querySelector("b").textContent);
  document.body.classList.remove("card-open");
  DOORS[b.dataset.go]();
}));

$("#ask").addEventListener("submit", (e) => {
  e.preventDefault();
  const inp = $("#ask-input");
  const t = inp.value.trim();
  if (!t) return;
  inp.value = "";
  you(t);
  analyze(t).catch((e) => say(`<p>Something went wrong on my side: ${esc(e)}</p>`));
});
$("#pick-file").addEventListener("click", chooseFile);

const deepBtn = $("#deep-toggle");
function setDeep(on) {
  document.body.classList.toggle("deep-on", on);
  deepBtn.setAttribute("aria-pressed", String(on));
  store.set("vv.deep", on);
}
deepBtn.addEventListener("click", () => setDeep(!document.body.classList.contains("deep-on")));
setDeep(store.get("vv.deep", false));

// Dropping a file anywhere on the window checks it.
try {
  const wv = T.webview?.getCurrentWebview?.();
  if (wv?.onDragDropEvent) {
    wv.onDragDropEvent((ev) => {
      const p = ev.payload;
      if (p.type === "over" || p.type === "enter") document.body.classList.add("dropping");
      else if (p.type === "drop") {
        document.body.classList.remove("dropping");
        if (p.paths?.length) guarded(() => checkFile(p.paths[0]));
      } else document.body.classList.remove("dropping");
    });
  }
} catch { /* dragging just won't work; the file button still does */ }

// ---------- start ----------
if (PHONE) phoneStart();
renderCard();
say(`<p>Hi, I'm <b>Vigil</b>. I look after this ${DEVICE} and explain everything in plain words.</p><p>Let me take a quick look first.</p>`);
// After the checkup: pick up a full scan that was running when Vigil was last closed.
guarded(checkup).then(() => sweepWatch());
// Refresh the public phishing list in the background (at most daily; never blocks the page).
invoke("update_phish_list").catch(() => {});
// ...and MalwareBazaar's known-malware fingerprints (full weekly, last 48 hours daily; on the
// phone the 43 MB full list waits for Wi-Fi).
invoke("update_hash_list").catch(() => {}).then(() => { if (PHONE && state.scan && !state.known?.checked) refreshKnown(); });
// Is a vetted local AI available? (An empty question only probes; nothing is generated.)
if (PHONE) state.ai = false; // no local AI on a phone
else invoke("ask_local_ai", { question: "" }).then((r) => { state.ai = !!r.ok; }).catch(() => { state.ai = false; });
