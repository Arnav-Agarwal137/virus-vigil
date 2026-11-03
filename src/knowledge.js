// Virus Vigil - everything Vigil "knows", kept offline in this one file.
// Plain words first; `deep` holds the technical version for the Details view.
// Nothing here is fetched from the internet.

// ---------- Threat names ----------
// Microsoft Defender names follow  Type:Platform/Family.Variant!Suffix
// e.g. Trojan:Win32/Wacatac.H!ml  ->  Trojan / Win32 / Wacatac / H / ml

export const THREAT_TYPES = {
  Trojan: {
    plain: "A Trojan is a program that pretends to be something nice - a free game, a crack, a helpful tool - so you let it in yourself. Once inside, it does something else: steals, spies, or opens the door for more bad programs.",
    like: "Like the wooden horse in the old story: a gift that has soldiers hidden inside.",
    danger: "high",
  },
  TrojanDownloader: {
    plain: "A downloader is a small program whose only job is to fetch the real bad program from the internet and install it.",
    like: "Like a delivery boy who lets a burglar in through the back door.",
    danger: "high",
  },
  TrojanDropper: {
    plain: "A dropper carries another bad program hidden inside itself and quietly unpacks it onto your computer.",
    like: "Like a suitcase with a false bottom.",
    danger: "high",
  },
  TrojanSpy: {
    plain: "A spy program watches what you do - what you type, what is on your screen - and sends it to someone else.",
    like: "Like someone reading over your shoulder all day.",
    danger: "high",
  },
  PWS: {
    plain: "A password stealer copies the passwords, saved cards and 'already logged in' tokens that your browsers and apps keep, and sends them to a thief.",
    like: "Like a pickpocket who copies your keys instead of taking them, so you don't notice.",
    danger: "severe",
  },
  Backdoor: {
    plain: "A backdoor lets a stranger control your computer from far away, whenever they like.",
    like: "Like a secret extra key to your house that someone else holds.",
    danger: "severe",
  },
  Ransom: {
    plain: "Ransomware locks your files (photos, documents) and demands money to unlock them.",
    like: "Like a kidnapper, but for your files.",
    danger: "severe",
  },
  Worm: {
    plain: "A worm copies itself from one computer to others by itself - through a network, a USB stick or messages.",
    like: "Like a cold that spreads to everyone nearby without anyone passing it on on purpose.",
    danger: "high",
  },
  Virus: {
    plain: "A virus attaches itself to other files and spreads when those files are opened or shared.",
    like: "Like a real virus: it needs a host to live in and spread from.",
    danger: "high",
  },
  Exploit: {
    plain: "An exploit uses a mistake (a bug) in a program to sneak past its safety locks. Keeping Windows and apps updated closes these mistakes.",
    like: "Like a burglar who knows one window in your house doesn't lock properly.",
    danger: "high",
  },
  HackTool: {
    plain: "A hack tool is a program made for breaking into systems or pulling out passwords. Some experts use them for testing; on a normal person's computer they are a warning sign.",
    like: "Like finding lock-picking tools in your drawer that you never bought.",
    danger: "moderate",
  },
  VirTool: {
    plain: "A tool used to build or hide bad programs. On a normal computer it is a warning sign.",
    like: "Like finding a forger's kit.",
    danger: "moderate",
  },
  PUA: {
    plain: "A 'potentially unwanted app' is not exactly malware, but it is sneaky: it comes bundled with something else, shows ads, changes your browser, or is hard to remove.",
    like: "Like a salesman who follows you home after you bought one thing.",
    danger: "low",
  },
  Adware: {
    plain: "Adware floods you with ads, pop-ups and redirects so someone earns money from your clicks.",
    like: "Like someone sticking posters on your walls while you sleep.",
    danger: "low",
  },
  BrowserModifier: {
    plain: "A browser modifier changes your browser without asking - your home page, your search engine - often to push ads or track you.",
    like: "Like someone re-arranging your room and hiding cameras.",
    danger: "moderate",
  },
  SoftwareBundler: {
    plain: "An installer that sneaks extra programs in alongside the one you wanted.",
    like: "Like ordering one thing and getting three you never asked for.",
    danger: "low",
  },
  Spyware: {
    plain: "Spyware secretly collects information about you - what you browse, type or say.",
    like: "Like a hidden microphone.",
    danger: "high",
  },
  Behavior: {
    plain: "This name means Defender didn't recognise the program itself - it caught it by what it was DOING, which looked like what bad programs do.",
    like: "Like a guard stopping someone for acting suspicious, even without a wanted poster.",
    danger: "moderate",
  },
  Program: {
    plain: "A program Defender flags because it can be misused, even if it may be legitimate.",
    like: "Like a knife: useful, but worth knowing why it is there.",
    danger: "low",
  },
  Phish: {
    plain: "Phishing is a fake page or message that copies a real one (a bank, Google, Instagram) to trick you into typing your password, OTP or card number.",
    like: "Like a fake bank counter set up on the street.",
    danger: "high",
  },
  Misleading: {
    plain: "A program that lies about your computer - fake 'you have 200 viruses!' warnings - to scare you into paying.",
    like: "Like a fake doctor who invents a disease to sell you medicine.",
    danger: "moderate",
  },
};

export const PLATFORMS = {
  Win32: "a Windows program",
  Win64: "a 64-bit Windows program",
  MSIL: "a Windows program built with .NET (a Microsoft programming kit)",
  DOS: "an old-style program - often just a test file",
  JS: "a JavaScript script (code that runs in web pages)",
  HTML: "a web page",
  Script: "a script (a small text program)",
  PowerShell: "a PowerShell script (Windows' built-in command language)",
  VBS: "a VBScript (an old Windows script language)",
  O97M: "an Office macro (code hidden inside a Word or Excel file)",
  AndroidOS: "an Android app",
  Python: "a Python program",
  Linux: "a Linux program",
  MacOS: "a Mac program",
};

// How the thing was caught (the part after "!"). Worded carefully: Microsoft does
// not publish a full list, so these say "usually".
export const SUFFIXES = {
  ml: "caught by Microsoft's machine-learning check (a pattern-spotting model). It looked like malware, rather than matching a known file exactly - so false alarms are a bit more likely.",
  cl: "caught by Microsoft's cloud check, which compares the file with what Microsoft has seen on other computers.",
  MTB: "usually means it was caught by a behaviour-based or automated detection.",
  pz: "usually means it was caught while being unpacked (opened up) for inspection.",
};

// Families worth a sentence of their own. Kept to names whose meaning is well known.
export const FAMILIES = {
  EICAR: { plain: "Good news: EICAR is a harmless TEST file. Security people use it on purpose to check that antivirus is awake. If you or someone helping you ran a test, this is it.", harmless: true },
  EICAR_Test_File: { plain: "Good news: EICAR is a harmless TEST file. Security people use it on purpose to check that antivirus is awake.", harmless: true },
  Wacatac: { plain: "'Wacatac' is not one specific virus - it is the name Defender gives to many different Trojans it catches by their look (often fake game downloads, cracks and 'free' software)." },
  Wacapew: { plain: "'Wacapew' is a general name Defender gives to suspicious programs caught by pattern-spotting, not one specific virus." },
  Sabsik: { plain: "'Sabsik' is a general name Defender uses for suspicious programs it catches by pattern-spotting. Occasionally these are false alarms." },
  Posilod: { plain: "'Posilod' is a general name Defender uses for suspicious programs caught by its cloud and pattern checks. These are sometimes false alarms on normal software - worth a second look, not panic." },
  Kryptik: { plain: "'Kryptik' means the file was scrambled (packed) in a way bad programs use to hide from antivirus." },
  PShellMal: { plain: "Defender saw a PowerShell script (Windows' built-in command language) behaving like malware - for example downloading and running something hidden." },
  Lumma: { plain: "Lumma is a well-known password stealer: it takes browser passwords, saved cards, 'logged in' tokens and crypto wallets.", stealer: true },
  LummaStealer: { plain: "Lumma is a well-known password stealer: it takes browser passwords, saved cards, 'logged in' tokens and crypto wallets.", stealer: true },
  RedLine: { plain: "RedLine is a well-known password stealer sold to criminals.", stealer: true },
  Vidar: { plain: "Vidar is a well-known password stealer.", stealer: true },
  AgentTesla: { plain: "Agent Tesla is a well-known spy program that records typing and steals passwords.", stealer: true },
  Emotet: { plain: "Emotet started as a banking Trojan and became a delivery service for other malware, spread mostly through email attachments." },
  CoinMiner: { plain: "A coin miner secretly uses your computer's power to make cryptocurrency for someone else - your laptop gets hot and slow." },
  Mimikatz: { plain: "Mimikatz is a famous tool for pulling passwords out of Windows' memory.", stealer: true },
};

export const SEVERITY = { 0: "unknown", 1: "low", 2: "moderate", 4: "high", 5: "severe" };

export function parseThreatName(name) {
  const m = /^([^:]+):([^/]+)\/([^.!]+)(?:\.([^!]+))?(?:!(.+))?$/.exec(name || "");
  if (!m) return { raw: name, type: null, platform: null, family: null, variant: null, suffix: null };
  return { raw: name, type: m[1], platform: m[2], family: m[3], variant: m[4] || null, suffix: m[5] || null };
}

// ---------- Android permissions ----------
// risk: "watch" = normal but worth knowing, "high" = powerful, "severe" = the tools thieves use.
export const PERMISSIONS = {
  "android.permission.BIND_ACCESSIBILITY_SERVICE": { plain: "can see everything on your screen and tap buttons for you", risk: "severe" },
  "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": { plain: "can read every notification - including OTP codes from your bank (smartwatch and music apps honestly need this; a random app does not)", risk: "high" },
  "android.permission.BIND_DEVICE_ADMIN": { plain: "can make itself very hard to uninstall and can lock or wipe the phone", risk: "severe" },
  "android.permission.READ_SMS": { plain: "can read your text messages - including OTP codes", risk: "high" },
  "android.permission.RECEIVE_SMS": { plain: "sees text messages the moment they arrive - including OTP codes", risk: "high" },
  "android.permission.SEND_SMS": { plain: "can send text messages from your number (which can cost money or spread scams)", risk: "high" },
  "android.permission.SYSTEM_ALERT_WINDOW": { plain: "can draw on top of other apps - used to put fake login screens over your banking app", risk: "high" },
  "android.permission.REQUEST_INSTALL_PACKAGES": { plain: "can install other apps", risk: "high" },
  "android.permission.READ_CALL_LOG": { plain: "can read who you called and who called you", risk: "high" },
  "android.permission.CALL_PHONE": { plain: "can make phone calls", risk: "high" },
  "android.permission.READ_CONTACTS": { plain: "can read all your contacts", risk: "watch" },
  "android.permission.RECORD_AUDIO": { plain: "can use the microphone", risk: "watch" },
  "android.permission.CAMERA": { plain: "can use the camera", risk: "watch" },
  "android.permission.ACCESS_FINE_LOCATION": { plain: "can know exactly where you are", risk: "watch" },
  "android.permission.ACCESS_BACKGROUND_LOCATION": { plain: "can track where you are even when you're not using it", risk: "high" },
  "android.permission.QUERY_ALL_PACKAGES": { plain: "can see every app on your phone (including your bank apps)", risk: "watch" },
  "android.permission.READ_PHONE_STATE": { plain: "can read your phone number and phone ID", risk: "watch" },
  "android.permission.MANAGE_EXTERNAL_STORAGE": { plain: "can read and change all files on your phone", risk: "high" },
  "android.permission.READ_EXTERNAL_STORAGE": { plain: "can read your photos and files", risk: "watch" },
  "android.permission.WRITE_EXTERNAL_STORAGE": { plain: "can change your files", risk: "watch" },
  "android.permission.GET_ACCOUNTS": { plain: "can see which accounts are on the phone", risk: "watch" },
  "android.permission.RECEIVE_BOOT_COMPLETED": { plain: "starts itself every time the phone turns on", risk: "watch" },
  "android.permission.FOREGROUND_SERVICE": { plain: "can keep running in the background", risk: "watch" },
  "android.permission.WAKE_LOCK": { plain: "can keep the phone awake", risk: "watch" },
  "android.permission.INTERNET": { plain: "can use the internet", risk: "normal" },
  "android.permission.ACCESS_NETWORK_STATE": { plain: "can see if you are online", risk: "normal" },
  "android.permission.VIBRATE": { plain: "can vibrate the phone", risk: "normal" },
  "android.permission.POST_NOTIFICATIONS": { plain: "can show you notifications", risk: "normal" },
};

// Combinations that together look like a banking Trojan. Each is a set that must all be present.
export const DANGER_COMBOS = [
  { needs: ["android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.RECEIVE_SMS"], says: "It asks to control your screen AND read incoming texts. That pair is exactly how banking Trojans steal money: they read your OTP and tap 'confirm' for you." },
  { needs: ["android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.READ_SMS"], says: "It asks to control your screen AND read your texts - the classic banking-Trojan pair." },
  { needs: ["android.permission.SYSTEM_ALERT_WINDOW", "android.permission.READ_SMS"], says: "It can draw fake screens over other apps AND read your texts - a known way to steal bank logins and OTPs." },
  { needs: ["android.permission.BIND_NOTIFICATION_LISTENER_SERVICE", "android.permission.INTERNET"], says: "It can read every notification (including OTPs) and send data over the internet." },
  { needs: ["android.permission.RECEIVE_SMS", "android.permission.SEND_SMS"], says: "It can read incoming texts AND send texts from your number - common in apps that spread scams to your contacts." },
];

// ---------- Scam patterns (India first) ----------
export const SCAMS = [
  { id: "remote", test: /\b(?:anydesk|any desk|teamviewer|team viewer|quick ?support|rustdesk|airdroid|screen ?shar(?:e|ing)|remote (?:access|app|support|control))\b/i, title: "A request to share your screen", why: "Screen-sharing apps (AnyDesk, TeamViewer, QuickSupport) let the caller watch everything - including OTPs as they arrive - while they 'help you get a refund'. No bank ever needs this.", do: "Don't install it. Hang up. If you already did: turn the internet off, uninstall it, and call your bank on the number on your card." },
  { id: "family", test: /\b(?:new number|my number (?:has )?changed|changed my number|phone (?:is )?(?:broken|lost|not working))\b|\b(?:hi|hello|dear)\s+(?:mum|mom|mummy|dad|papa|beta|beti|bhai|didi|son|daughter)\b.{0,120}\b(?:send|transfer|pay|need)\b|\b(?:in trouble|hospital|accident|stuck)\b.{0,60}\b(?:send|transfer|pay)\b.{0,30}\b(?:money|rs|₹|\d{3,})/i, title: "A 'family member' asking for money", why: "Scammers pose as a relative with a 'new number' or an emergency, and push you to send money fast before you can check.", do: "Call the person on the number you already have (or ask something only they would know) before sending anything." },
  { id: "apk", test: /\.apk\b|\bapk\b/i, title: "An app file sent as a message", why: "Real banks, RTO, electricity boards and courier companies never send you an app file (.apk) on WhatsApp or SMS. Fake ones read your texts and steal OTPs.", do: "Don't open it. Delete the message. If you already installed it, uninstall it and call your bank." },
  { id: "challan", test: /challan|traffic (fine|violation)|\bRTO\b|parivahan/i, title: "A traffic-fine (challan) message", why: "Fake e-challan messages are a well-known trap: the link or app steals your card details.", do: "Check fines only on the official Parivahan site you type yourself: echallan.parivahan.gov.in." },
  { id: "kyc", test: /\bKYC\b|account (will be )?(blocked|suspended|freeze|frozen)|update (your )?PAN/i, title: "'Update your KYC or your account will be blocked'", why: "Banks don't block accounts through a link in an SMS. This pressure is the trick.", do: "Don't click. Call the number on the back of your card or open the bank's own app." },
  { id: "power", test: /electricity|power (will be )?(cut|disconnect)|bijli|light bill/i, title: "'Your electricity will be cut tonight'", why: "A classic fright message to make you call a fake officer or install a 'payment app'.", do: "Ignore it. Check your bill on your electricity board's own website or app." },
  { id: "parcel", test: /parcel|courier|customs|fedex|dhl|india ?post/i, title: "A parcel / customs message", why: "Fake courier and customs messages ask for a 'fee' or say drugs were found in your name.", do: "Don't pay or share details. Track parcels only on the courier's own site." },
  { id: "arrest", test: /digital arrest|\bCBI\b|narcotics|police (case|complaint)|money laundering|video call.*(police|officer)/i, title: "A 'police / CBI' threat", why: "'Digital arrest' is a scam. Real police never arrest anyone on a video call or ask for money to close a case.", do: "Hang up. Report at cybercrime.gov.in or call 1930." },
  { id: "prize", test: /lottery|you (have )?won|\bKBC\b|lucky draw|prize|reward points/i, title: "'You won a prize'", why: "If you didn't enter, you didn't win. The 'fee to release your prize' is the scam.", do: "Ignore and delete." },
  { id: "job", test: /part[- ]?time|work from home|like (youtube )?videos|rate (hotels|products)|daily (income|earning)|task.*(earn|commission)/i, title: "An easy online job", why: "'Like videos and earn' jobs pay a little at first, then ask you to 'invest' - and the money is gone.", do: "No real job asks you to pay to work. Block the sender." },
  { id: "otp", test: /\bOTP\b|one[- ]time password|verification code/i, title: "Someone wants a code", why: "An OTP is like the key to your locker. Nobody genuine - not your bank, not Amazon, not the police - ever needs you to tell it to them.", do: "Never share an OTP, even with someone who says they are from your bank." },
  { id: "upi", test: /\bUPI\b|collect request|scan (this )?(the )?QR|receive (the )?money|refund/i, title: "A UPI / QR request", why: "To RECEIVE money you never scan a QR or enter your UPI PIN. Entering the PIN always SENDS money.", do: "If someone asks you to enter your PIN to 'receive', it's a scam." },
  { id: "loan", test: /instant loan|loan approved|pre-?approved loan/i, title: "An instant loan offer", why: "Fake loan apps take your contacts and photos, then harass and blackmail you.", do: "Borrow only from banks and apps listed on the RBI's site." },
  { id: "invest", test: /crypto|double (your )?money|guaranteed return|trading (tips|group)|stock tips/i, title: "A 'guaranteed returns' investment", why: "Nobody can guarantee big returns. Fake trading groups show fake profits, then disappear with your money.", do: "Invest only through SEBI-registered brokers." },
];

export const SHORTENERS = ["bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "t.ly", "rb.gy", "shorturl.at", "rebrand.ly", "t.co", "ow.ly", "tiny.cc", "s.id"];
export const RISKY_TLDS = ["zip", "mov", "xyz", "top", "click", "icu", "buzz", "cfd", "sbs", "rest", "quest", "cam", "monster", "live", "support", "loan", "work"];
// Brands scammers copy, and the domains that are really theirs.
export const BRANDS = {
  sbi: ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"], hdfc: ["hdfcbank.com", "hdfc.bank.in"], icici: ["icicibank.com", "icici.bank.in"], axis: ["axisbank.com", "axis.bank.in"],
  paytm: ["paytm.com"], phonepe: ["phonepe.com"], gpay: ["pay.google.com"], amazon: ["amazon.in", "amazon.com"], flipkart: ["flipkart.com"],
  google: ["google.com", "google.co.in", "youtube.com", "gmail.com"], whatsapp: ["whatsapp.com"], instagram: ["instagram.com"], facebook: ["facebook.com"],
  incometax: ["incometax.gov.in"], uidai: ["uidai.gov.in"], aadhaar: ["uidai.gov.in"], epfo: ["epfindia.gov.in"], parivahan: ["parivahan.gov.in"], indiapost: ["indiapost.gov.in"],
  microsoft: ["microsoft.com", "live.com", "office.com"], netflix: ["netflix.com"],
};

// ---------- Plain answers to "what is ...?" ----------
export const GLOSSARY = {
  "trojan": THREAT_TYPES.Trojan.plain + " " + THREAT_TYPES.Trojan.like,
  "virus": THREAT_TYPES.Virus.plain,
  "worm": THREAT_TYPES.Worm.plain,
  "ransomware": THREAT_TYPES.Ransom.plain,
  "spyware": THREAT_TYPES.Spyware.plain,
  "adware": THREAT_TYPES.Adware.plain,
  "phishing": THREAT_TYPES.Phish.plain,
  "malware": "Malware means any bad program - viruses, Trojans, spyware, all of them. 'Mal' means bad.",
  "stealer": THREAT_TYPES.PWS.plain,
  "otp": "An OTP (one-time password) is a short code sent to your phone to prove it's really you. It's the last lock on your money - never tell it to anyone.",
  "2fa": "Two-step verification (2FA) means logging in needs two things: your password AND something only you have, like a code on your phone. A thief with just your password still can't get in.",
  "two-step": "Two-step verification means logging in needs two things: your password AND something only you have, like a code on your phone.",
  "apk": "An APK is an Android app file. Apps from the Play Store are checked by Google; an APK sent to you on WhatsApp or downloaded from a website has not been checked by anyone.",
  "sideload": "Sideloading means installing an app from outside the Play Store (an APK file). Sometimes needed - but those apps haven't been checked, so check them yourself first.",
  "cookie": "A cookie is a small file a website leaves in your browser so it remembers you are logged in. If a thief steals it, they can be 'you' on that site without your password.",
  "firewall": "A firewall is a gatekeeper for your internet connection: it decides which programs may talk to the outside world.",
  "dns": "DNS is the internet's phone book: it turns a name like google.com into an address. A safe DNS refuses to look up known bad sites, so they never even load.",
  "vpn": "A VPN hides your internet traffic inside a tunnel. It helps on public Wi-Fi, but it does NOT stop viruses or scams.",
  "root": "Rooting unlocks the deepest control of an Android phone. It lets apps do anything - including bad apps - and banking apps often refuse to work on rooted phones.",
  "password manager": "A password manager is an app that remembers a different strong password for every site, locked behind one master password.",
};

// Browser add-on (extension) powers, in plain words. Only the ones worth saying out loud;
// harmless ones (storage, alarms, contextMenus...) are not listed. Source: Chrome extension
// permission docs (developer.chrome.com/docs/extensions/reference/permissions-list).
export const EXT_POWERS = {
  debugger: "can take full control of any tab, like a remote control",
  cookies: "can read the sign-in cookies that keep you logged in",
  webRequest: "can watch every web request the browser makes",
  webRequestBlocking: "can change web requests before they are sent",
  proxy: "can reroute all your browsing through another computer",
  nativeMessaging: "can talk to a program installed on this laptop",
  management: "can switch your other add-ons on and off",
  history: "can read your browsing history",
  clipboardRead: "can read what you copy",
  privacy: "can change the browser's privacy settings",
  desktopCapture: "can record your screen",
  downloads: "can start and open downloads",
  scripting: "can run its own code inside web pages",
  tabs: "can see the address of every tab",
  bookmarks: "can read your bookmarks",
};
// Access patterns that mean "every website".
export const ALL_SITES = /^(<all_urls>|\*:\/\/\*\/\*|https?:\/\/\*\/\*|\*:\/\/\*\/|file:\/\/\/?\*)$/;

// Shared sites: anyone can publish a page under these exact names, so a host-level list
// cannot judge a link on them either way (the public phishing list DOES contain some of
// them whole, e.g. sites.google.com - matching those would call every page on them phishing).
export const SHARED_HOSTS = [
  "sites.google.com", "docs.google.com", "drive.google.com", "forms.gle", "storage.googleapis.com",
  "firebasestorage.googleapis.com", "cloudflare-ipfs.com", "ipfs.io", "dweb.link", "telegra.ph",
  "dropbox.com", "dl.dropboxusercontent.com", "onedrive.live.com", "1drv.ms", "forms.office.com",
  "linktr.ee", "notion.site", "github.com", "raw.githubusercontent.com", "gitlab.com", "medium.com",
  "t.me", "wa.me", "s3.amazonaws.com", "blob.core.windows.net",
];
// Bases under which strangers get their own sub-site (x.web.app). A listed sub-site is judged
// by its own full name; the base itself is never looked up as a parent of someone's link.
export const PLATFORM_BASES = [
  "web.app", "firebaseapp.com", "github.io", "gitlab.io", "vercel.app", "netlify.app", "pages.dev",
  "workers.dev", "r2.dev", "000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com", "appspot.com",
  "herokuapp.com", "azurewebsites.net", "glitch.me", "replit.app", "ngrok-free.app", "trycloudflare.com",
  "wordpress.com", "square.site", "godaddysites.com", "mystrikingly.com", "jimdosite.com",
  "co.in", "org.in", "net.in", "gov.in", "ac.in", "co.uk", "com.au",
];

// ---------- Vigil's own look inside a file (src-tauri/src/sniff.rs) ----------
// One entry per code sniff.rs can report. `t` = the headline, `why` = why it matters,
// `do` = what to do. "{d}" is replaced with the detail sniff.rs found (escaped by the page).
// `act` = a script behaviour: shown together in one list instead of a row each.
// Never says "safe": these catch the SHAPES malware arrives in, not malware by name.
export const LOOK = {
  "program-odd-name": { t: "This is a program with an unusual ending ({d})", why: "Inside, it is a Windows program, but its name ends in something else. Installers do this all the time with their own temporary files, so on its own it is not a sign of harm.", do: "If you didn't just install something and don't know where it came from, check it with Defender." },
  "disguised-program": { t: "This is a program pretending to be a {d} file", why: "Inside, it is a Windows program, but its name says it is something harmless. Honest files never do this - it is how harmful programs get double-clicked.", do: "Don't open it. Delete it." },
  "disguised-shortcut": { t: "This is a shortcut pretending to be a {d} file", why: "Inside, it is a Windows shortcut that can start a program, but its name says it is something harmless.", do: "Don't open it. Delete it." },
  "disguised-script": { t: "This {d} file is really a web page or script", why: "Its name says it is harmless, but inside it holds code that runs when opened.", do: "Don't open it. Delete it." },
  "disguised-archive": { t: "This {d} file is really a zipped folder", why: "Its name says it is a normal file, but it is a packed archive. Sometimes a program ends up renamed by mistake, but it is also a trick to slip files past checks.", do: "Don't unpack it unless you know exactly who sent it and why." },
  "name-reversed": { t: "The file name is written backwards to hide its real ending", why: "It holds an invisible 'reverse text' character, so a name like 'photo_gpj.exe' shows as 'photo_exe.jpg'. This trick is used almost only by harmful files.", do: "Don't open it. Delete it." },
  "double-ending": { t: "A double ending: {d}", why: "The name ends in a harmless-looking type and then a program type. Windows often hides the last one, so you see only the harmless part.", do: "Don't open it. Delete it." },
  "hidden-ending": { t: "Spaces hide this file's real ending ({d})", why: "A long run of spaces pushes the real ending out of sight, so the name looks like a harmless file.", do: "Don't open it. Delete it." },
  "can-run": { t: "This file type ({d}) can run by itself when double-clicked", why: "Opening it lets it do things on a Windows computer.", do: "Only run it if it came from a maker you trust, from their own website." },
  "disk-image": { t: "This is a disk image ({d})", why: "It opens like a folder. Disk images have been used to carry harmful programs past Windows' download warnings.", do: "Only open it if it came from a maker you trust. Don't run what's inside unless you expected it." },
  "zip-unreadable": { t: "I couldn't open this zipped folder to look inside", why: "It may be damaged - or built oddly on purpose so checkers can't read it.", do: "Treat what's inside with care." },
  "locked-archive": { t: "This zipped folder is locked with a password", why: "A password stops every virus scanner from looking inside. Harmful files are often sent this way, with the password in the message.", do: "Only unpack it if you know who sent it and expected it." },
  "archive-has-program": { t: "Inside this zipped folder are files that can run: {d}", why: "Programs and scripts inside a zip are how many harmful downloads arrive.", do: "Only run them if you expected a program from this sender." },
  "archive-name-trick": { t: "A file inside uses a name trick: {d}", why: "It is named to look harmless while it is really a program.", do: "Don't unpack or open it. Delete the zipped folder." },
  "archive-single-program": { t: "The only thing inside is one program: {d}", why: "A zip holding just one program is a common way to deliver harmful files, often named like an invoice or a photo.", do: "Don't run it unless you expected exactly this program." },
  "macros": { t: "This Office file holds macros (small programs)", why: "Macros can run code when you press 'Enable content'. Real documents rarely need them.", do: "If Word or Excel asks you to 'Enable content' or 'Enable editing' for this file, don't." },
  "remote-template": { t: "This Office file fetches something from the internet when opened", why: "It points to an outside address ({d}) and loads it on opening - a known way to pull in harmful code without any macro inside the file itself.", do: "Don't open it. Delete it." },
  "embedded-object": { t: "Another file is packed inside this Office document", why: "Documents can carry hidden files or programs that run when you double-click an icon in the page.", do: "Don't double-click icons or pictures inside the document." },
  "pdf-code": { t: "This PDF contains code", why: "PDFs can carry JavaScript, and most real PDFs don't need it.", do: "Open it only in your browser (which blocks most PDF code), not in a full PDF program." },
  "pdf-launch": { t: "This PDF tries to start a program", why: "It carries a 'launch' command - a trick to run something on your computer from a document.", do: "Don't open it. Delete it." },
  "pdf-opens-file": { t: "This PDF opens another file or address", why: "Its links use a 'launch' command, but what they open is a document or an e-mail address, not a program. Government and office reports made with older tools often do this.", do: "Fine to read. If a link inside asks to run something, say no." },
  "pdf-attachment": { t: "Another file is attached inside this PDF", why: "PDFs can carry files. Harmful ones hide a program or script this way.", do: "If a PDF asks you to open or save an attachment, don't." },
  "pdf-form-code": { t: "This PDF has a form that runs code", why: "Forms with code are rare in ordinary PDFs and have been used to attack PDF programs.", do: "Open it only in your browser." },
  "shortcut-runs-command": { t: "This shortcut secretly runs a command ({d})", why: "It looks like a link to a file, but it starts a Windows tool that can download and run anything.", do: "Don't open it. Delete it." },
  "shortcut-web": { t: "This shortcut points to a web address", why: "Opening it takes you to a website - check you know where.", do: "Only open it if you trust who sent it." },
  "turns-off-defender": { t: "This script tries to switch off Windows Defender", why: "Turning off the virus shield, or telling it to skip folders, is what harmful scripts do first.", do: "Don't run it. Delete it." },
  "deletes-backups": { t: "This script deletes Windows' backups", why: "Wiping the saved copies of your files is what ransomware does just before it locks everything.", do: "Don't run it. Delete it." },
  "web-runner": { t: "This script runs code straight from the internet", why: "It uses a built-in Windows tool to fetch and run code from a website - a classic attack trick.", do: "Don't run it. Delete it." },
  "download-and-run": { t: "This script downloads something and runs it", why: "Fetching a program from the internet and starting it at once is how most harmful scripts install the real virus.", do: "Don't run it. Delete it." },
  "hidden-and-run": { t: "This script hides its code and then runs it", why: "Scrambling code so nobody can read it, then running it, is a strong sign of a harmful script.", do: "Don't run it. Delete it." },
  "hidden-code": { t: "hides part of its code in scrambled text", act: true },
  "downloads": { t: "downloads things from the internet", act: true },
  "runs-text-as-code": { t: "turns text into code and runs it", act: true },
  "starts-programs": { t: "starts other programs", act: true },
  "hidden-window": { t: "runs in a hidden window", act: true },
  "starts-itself": { t: "sets itself to start every time the computer starts", act: true },
  "clears-tracks": { t: "wipes Windows' records of what happened", act: true },
};
