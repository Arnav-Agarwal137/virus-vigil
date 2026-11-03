// Virus Vigil - the built-in answer library. Everything here works offline, on the phone and
// the laptop, and answers instantly. Two kinds:
//   FIRST_AID - "it happened to me": the person is the victim, speaking in the first person.
//               Answer = what to do NOW, then what to do next. Checked before the scam patterns,
//               because "I shared my OTP" is a confession, not a scam message.
//   ANSWERS   - how-to and "is X safe?" questions.
// Entry: { id, test, title, say, steps?, phone?: {say?, steps?}, laptop?: {say?, steps?},
//          links?: [{label, url}], go?: [keys main.js turns into buttons] }
// Official numbers and addresses: checked against the source pages on 24 Sep 2026 (reader agent,
// quotes in ../../RESUME-HERE.md "answer library facts"): 1930, cybercrime.gov.in (+ Report Suspect),
// RBI 3 / 4-7 working days, Sanchar Saathi Chakshu/CEIR/TAFCOP, 1909 + TRAI DND app, recovery URLs
// for Instagram/Facebook/Google/Microsoft. NOT YET VERIFIED (JS-only or sign-in pages): WhatsApp
// menu paths, Aadhaar biometric-lock path, Play Protect path. Never add a fact from memory.

const I = String.raw`(?:^|\b)(?:i|i've|ive|i have|i had|i just|i accidentally|i mistakenly|by mistake i|i by mistake|my (?:mom|mother|dad|father|son|daughter|wife|husband|friend|grandma|grandpa))\b`;

export const HELPLINE = { number: "1930", portal: "https://cybercrime.gov.in" };

const REPORT = { label: "Open cybercrime.gov.in", url: "https://cybercrime.gov.in" };

export const FIRST_AID = [
  {
    id: "money-lost",
    test: new RegExp(String.raw`(?:money|amount|rs\.?|₹|rupees|payment)\b.{0,40}\b(?:deducted|debited|stolen|gone|lost|cut|withdrawn|transferred)|\b(?:unauthori[sz]ed|fraud(?:ulent)?)\s+(?:transaction|payment|debit)|${I}.{0,30}\b(?:got |been )?(?:scammed|cheated|duped|defrauded|looted)|${I}.{0,20}\b(?:sent|paid|transferred)\b.{0,40}\b(?:scam|fraud|fake|cheat)`, "i"),
    title: "Money left your account without you",
    say: "Speed matters most: the sooner the bank and the police cyber cell know, the better the chance of stopping the money.",
    steps: [
      "Call 1930 now (India's cyber fraud helpline) - they can ask banks to freeze the money while it is still moving.",
      "Call your bank on the number printed on your card or passbook and block the card / UPI. Ask for a complaint number.",
      "Report it at cybercrime.gov.in - keep screenshots of the messages, the transaction ID and the scammer's number.",
      "Tell your bank in writing within 3 working days: under RBI rules, if neither you nor the bank caused it, reporting within 3 working days means you lose nothing (4-7 days: a capped amount). Sharing an OTP counts as your side, sadly - which is one more reason to call 1930 fast.",
    ],
    links: [REPORT],
    go: ["hacked"],
  },
  {
    id: "otp-shared",
    test: new RegExp(String.raw`${I}.{0,30}\b(?:shared|gave|told|sent|typed|entered|said|read out|forwarded)\b.{0,30}\b(?:otp|one[- ]time|verification code|code|upi pin|atm pin|pin|cvv)\b`, "i"),
    title: "You shared a code (OTP or PIN)",
    say: "An OTP or PIN is the last lock on your money or account. Act now, before it is used.",
    steps: [
      "If it was a bank or UPI code: call your bank on the number on your card and block the card / UPI straight away.",
      "If it was a WhatsApp, Telegram or other app code: open that app now - if it logs you out, log back in with your number and turn on two-step verification.",
      "Change the PIN or password it protects, from the real app - never from a link someone sent.",
      "If any money has gone: call 1930 and report at cybercrime.gov.in.",
    ],
    links: [REPORT],
    go: ["accounts"],
  },
  {
    id: "clicked-link",
    test: new RegExp(String.raw`${I}.{0,25}\b(?:clicked|opened|tapped|pressed|visited)\b.{0,25}\b(?:link|url|website|site|page|message)`, "i"),
    title: "You opened a suspicious link",
    say: "Just opening a page rarely harms a phone or laptop by itself. The danger is what you typed there or installed from it.",
    steps: [
      "Did you type a password there? Change that password now, from the real app or website.",
      "Did you type card details, a UPI PIN or an OTP? Call your bank on the number on your card and block it.",
      "Did it download a file or an app? Don't open it - delete it. If you installed an app, remove it.",
      "Nothing typed, nothing installed? You're most likely fine. Close the page and delete the message.",
    ],
    go: ["checkup", "password"],
  },
  {
    id: "installed-app",
    test: new RegExp(String.raw`${I}.{0,25}\b(?:installed|downloaded|opened|ran|run)\b.{0,40}\b(?:apk|app|application|file|software|program|exe)\b`, "i"),
    title: "You installed something you now doubt",
    say: "An app from a message can read your texts (and OTPs) the moment you give it permission. Take it off first, then check.",
    phone: { steps: [
      "Turn on flight mode for a minute so it can't send anything while you work.",
      "Settings → Apps → find the app → Uninstall. If Uninstall is greyed out, it made itself a 'device admin': Settings → Security → Device admin apps → switch it off, then uninstall.",
      "Then let me check this phone for what such apps leave behind.",
      "If you entered bank details in it: call your bank and block the card / UPI.",
    ] },
    laptop: { steps: [
      "Disconnect from the internet (Wi-Fi off) so it can't send anything.",
      "Settings → Apps → Installed apps → find it → Uninstall.",
      "Run a full Windows Security scan, then let me check what starts by itself.",
      "Change the passwords you used on this laptop since - from another device if you can.",
    ] },
    go: ["hacked", "apps"],
  },
  {
    id: "remote-access",
    test: new RegExp(String.raw`${I}.{0,40}\b(?:anydesk|teamviewer|quick ?support|rustdesk|airdroid|remote (?:access|control|desktop|support)|screen ?shar(?:e|ing)|shared (?:my )?screen)|(?:gave|given|allowed)\b.{0,20}\b(?:remote|screen)\b`, "i"),
    title: "Someone had remote access to your screen",
    say: "Screen-sharing apps let the other person see everything, including OTPs as they arrive. Cut them off first.",
    steps: [
      "Turn off the internet (flight mode / Wi-Fi off) right now.",
      "Uninstall the screen-sharing app (AnyDesk, TeamViewer, QuickSupport, RustDesk...).",
      "Call your bank on the number on your card: block cards and UPI, and ask about any recent transactions.",
      "Change passwords of email, banking and social apps - start with email.",
      "If money is gone: 1930 and cybercrime.gov.in.",
    ],
    links: [REPORT],
    go: ["hacked", "payment"],
  },
  {
    id: "account-hacked",
    test: /\b(?:my|our)\s+(?:instagram|insta|facebook|fb|gmail|google|email|mail|whatsapp|telegram|twitter|x|snapchat|microsoft|outlook|hotmail|account|id)\b.{0,30}\b(?:hacked|stolen|compromised|taken over|not (?:opening|working)|locked|disabled)|\b(?:someone|somebody|stranger|hacker)\b.{0,20}\b(?:is using|using|logged into|has|took|changed)\b.{0,10}\bmy\b|\b(?:can't|cannot|cant|unable to)\s+(?:log ?in|login|sign ?in|open)\b.{0,30}\b(?:password|changed|hacked)|password (?:was|got|has been) changed/i,
    title: "An account was taken over",
    say: "Most accounts can be recovered if you act quickly, from the service's own recovery page - never through someone who messages you offering to 'recover' it.",
    steps: [
      "Use the official recovery page for that service (buttons below). WhatsApp: open WhatsApp and verify your own number again - the other person is logged out.",
      "Once back in: change the password, turn on two-step verification, and log out every other device.",
      "Tell your friends not to answer money requests 'from you' - hacked accounts are used to ask for money.",
      "Change the same password everywhere else you used it.",
    ],
    links: [
      { label: "Instagram recovery", url: "https://www.instagram.com/hacked/" },
      { label: "Facebook recovery", url: "https://www.facebook.com/hacked" },
      { label: "Google recovery", url: "https://accounts.google.com/signin/recovery" },
      { label: "Microsoft recovery", url: "https://account.live.com/acsr" },
    ],
    go: ["accounts", "password"],
  },
  {
    id: "device-hacked",
    test: /\b(?:my|this|our)\s+(?:phone|mobile|laptop|computer|pc|device|system)\b.{0,25}\b(?:is |got |has been |was |might be |may be )?(?:hacked|infected|compromised|has (?:a )?virus|virus)|\b(?:virus|malware|hacker)s?\b.{0,20}\b(?:in|on) my (?:phone|mobile|laptop|computer|pc)\b|\bi think\b.{0,20}\b(?:hacked|virus|spy|being watched|tracked)/i,
    title: "You think this device is hacked",
    say: "Let's look instead of guessing. I'll check the signs that attackers leave behind on this device.",
    steps: [
      "Tap 'Was I hacked before?' below - I look for the usual signs.",
      "Change your email password first (from a device you trust) - email is the key to all your other accounts.",
      "Common real signs: apps you didn't install, settings you didn't change, messages you didn't send, OTPs you didn't ask for.",
      "Slow, hot or battery-hungry on its own is usually NOT a hack - just age or a heavy app.",
    ],
    go: ["hacked", "accounts"],
  },
  {
    id: "lost-phone",
    test: /\b(?:my|our)\s+(?:phone|mobile|smartphone)\b.{0,20}\b(?:lost|stolen|missing|snatched|theft)|\b(?:lost|stole|snatched)\b.{0,12}\bmy\s+(?:phone|mobile)\b/i,
    title: "Your phone is lost or stolen",
    say: "Two jobs: stop the phone being used against you, and block it so it can't be reused.",
    steps: [
      "From another device, open Google's Find My Device (google.com/android/find) and lock or erase it.",
      "Call your mobile operator to block the SIM and get a new one on the same number.",
      "Call your bank to block UPI on that number.",
      "File a police complaint, then block the phone's IMEI on the government's CEIR service (Sanchar Saathi) with the complaint number.",
      "Change your Google / email password.",
    ],
    links: [{ label: "Find My Device", url: "https://www.google.com/android/find" }, { label: "Sanchar Saathi (CEIR)", url: "https://sancharsaathi.gov.in" }],
  },
  {
    id: "sim-dead",
    test: /\b(?:my\s+)?sim\b.{0,25}\b(?:stopped|not working|no network|no signal|deactivated|blocked)|\bno network\b.{0,30}\b(?:suddenly|since)/i,
    title: "Your SIM suddenly stopped working",
    say: "Sometimes it's just the network. But if it happens out of the blue, a criminal may have got a copy of your SIM (a 'SIM swap') to receive your OTPs.",
    steps: [
      "From another phone, call your operator's customer care and ask: 'Was a new SIM issued on my number?'",
      "If yes, or they aren't sure: ask them to block it, and call your bank to block UPI and netbanking.",
      "Watch your bank account for the next day.",
    ],
  },
  {
    id: "blackmail",
    test: /\b(?:blackmail(?:ing|ed)?|threaten(?:ing|ed)?|extort(?:ing|ion)?)\b.{0,40}\b(?:me|my)\b|\b(?:leak|share|post|send)\b.{0,15}\bmy\s+(?:photos?|pictures?|videos?|pics)\b|\bsextortion\b/i,
    title: "Someone is threatening or blackmailing you",
    say: "You are not in trouble - they are. Blackmailers want you scared and alone. Paying almost never makes them stop; it tells them you'll pay again.",
    steps: [
      "Don't pay and don't argue. Stop replying.",
      "Keep evidence: screenshots of the chats, their profile, numbers and payment IDs.",
      "Block and report the account on that app.",
      "Report at cybercrime.gov.in (there's a section for women and children) or call 1930. Tell someone you trust.",
    ],
    links: [REPORT],
  },
  {
    id: "loan-app",
    test: /\bloan app\b.{0,40}\b(?:harass|threat|calling|messag|contacts|morph|abus)|\b(?:harass|threat)\w*\b.{0,30}\bloan\b/i,
    title: "A loan app is harassing you or your contacts",
    say: "Illegal loan apps copy your contacts and photos, then use shame to squeeze money. It's a crime - report it.",
    steps: [
      "Don't pay extra 'fees'. Keep proof of what you actually borrowed and repaid.",
      "Uninstall the app, then revoke its permissions if it asks.",
      "Report at cybercrime.gov.in or call 1930. Warn your contacts that fake messages may arrive.",
      "Check whether the lender is registered with the RBI before paying anything.",
    ],
    links: [REPORT],
  },
  {
    id: "card-entered",
    test: new RegExp(String.raw`${I}.{0,30}\b(?:entered|typed|gave|shared|filled|put)\b.{0,30}\b(?:card|cvv|debit|credit|bank details|account details|net ?banking|password)\b`, "i"),
    title: "You typed card or bank details somewhere doubtful",
    say: "Block first, ask questions later - a blocked card costs a few days; a used one costs money.",
    steps: [
      "Call your bank on the number on your card and block it (most bank apps also have a 'block card' button).",
      "If you typed a netbanking or app password: change it from the real bank app.",
      "Check the last transactions. If any is not yours: 1930 and cybercrime.gov.in, and tell the bank in writing within 3 working days.",
    ],
    links: [REPORT],
  },
  {
    id: "ransom-files",
    test: /\b(?:my\s+)?files?\b.{0,30}\b(?:encrypted|locked|renamed|won't open|can't open)\b.{0,40}\b(?:ransom|pay|bitcoin|money)|\bransom (?:note|message|demand)/i,
    title: "Your files are locked and someone wants money",
    say: "That's ransomware. Don't pay - payment often doesn't bring files back.",
    steps: [
      "Unplug the internet cable / turn Wi-Fi off, and unplug any USB or backup drive right now so they aren't locked too.",
      "Don't restart repeatedly or delete the ransom note (it identifies the type).",
      "Check nomoreransom.org from another device - for some types there is a free unlock tool.",
      "Report at cybercrime.gov.in.",
    ],
    links: [{ label: "No More Ransom", url: "https://www.nomoreransom.org" }, REPORT],
  },
];

// ---------- how-to and "is it safe?" ----------
export const ANSWERS = [
  {
    id: "remove-virus",
    test: /\b(?:remove|delete|get rid of|clean|kill|fix)\b.{0,25}\b(?:virus|malware|trojan|spyware|adware)|\b(?:virus|malware)\b.{0,15}\b(?:remov|clean)/i,
    title: "Removing a virus",
    laptop: { say: "Windows Security (Defender) is a real antivirus and is already on this laptop.", steps: [
      "Windows Security → Virus & threat protection → Scan options → Full scan → Scan now.",
      "If something keeps coming back: same place → Microsoft Defender Offline scan (it restarts the laptop and cleans before Windows starts).",
      "Then let me check what starts by itself and your browser add-ons - leftovers often hide there.",
      "Change your important passwords afterwards.",
    ] },
    phone: { say: "On Android, a 'virus' is almost always a bad app. Removing the app removes the problem.", steps: [
      "Let me check your apps - I point out the ones with dangerous powers or from outside a store.",
      "Uninstall anything you don't recognise: Settings → Apps → the app → Uninstall.",
      "Can't uninstall? It's a device admin: Settings → Security → Device admin apps → switch it off first.",
      "Pop-ups everywhere even on the home screen: the last apps you installed before it started are the usual cause.",
    ] },
    go: ["apps", "hacked"],
  },
  {
    id: "virus-signs",
    test: /\b(?:how (?:do i|to|can i) (?:know|tell|check|find)|signs?|symptoms?|is there)\b.{0,40}\b(?:virus|malware|hacked|spy|infected)|\b(?:check|scan)\b.{0,15}\b(?:for|my\b.{0,20}for)\s+(?:virus|viruses|malware)/i,
    title: "How to tell if a device has a virus",
    say: "Real signs: apps or programs you didn't install, settings changing on their own, messages sent from your accounts, OTPs you didn't ask for, pop-ups outside the browser. Being slow or hot is usually just age.",
    steps: ["Tap 'Was I hacked before?' - I check the usual signs on this device.", "Then run the checkup - it shows which doors are still open."],
    go: ["hacked", "checkup"],
  },
  {
    id: "strong-password",
    test: /\b(?:strong|good|safe|secure|best)\b.{0,15}\bpasswords?\b|\bpasswords?\b.{0,20}\b(?:make|create|choose|tips|ideas)/i,
    title: "Making a strong password",
    say: "Length beats cleverness. A long phrase of random words is stronger than a short mix of symbols, and easier to remember.",
    steps: [
      "Use 4 or more unrelated words: 'mango ladder cloudy tiger 42' - not your name, birthday or phone number.",
      "A DIFFERENT password for each important account - when one site leaks, the rest stay safe.",
      "Let a password manager remember them (Google Password Manager or Bitwarden are free).",
      "Turn on two-step verification - then a stolen password alone isn't enough.",
    ],
    go: ["password"],
  },
  {
    id: "whatsapp-2fa",
    test: /\b(?:two[- ]?step|2fa|two[- ]?factor|pin|secure|protect|safe)\b.{0,30}\bwhats ?app\b|\bwhats ?app\b.{0,40}\b(?:two[- ]?step|2fa|secure|safe|protect|hack)/i,
    title: "Protecting WhatsApp",
    say: "Two-step verification adds a 6-digit PIN that WhatsApp asks for when your number is set up on a new phone - so a stolen SMS code alone can't take your account.",
    steps: [
      "WhatsApp → Settings → Account → Two-step verification → Turn on → choose a 6-digit PIN (add an email in case you forget it).",
      "Linked devices (Android: ⋮ → Linked devices; iPhone: Settings → Linked devices): tap any computer you don't recognise → Log out.",
      "Settings → Privacy → Groups: 'My contacts', so strangers can't add you to scam groups.",
      "Never tell anyone the 6-digit code WhatsApp texts you - not even 'WhatsApp support'.",
    ],
  },
  {
    id: "2fa-general",
    test: /\b(?:two[- ]?step|2fa|two[- ]?factor|mfa|authenticator)\b/i,
    title: "Two-step verification",
    say: "It means logging in needs your password AND something only you have (a code on your phone, or a tap on 'Yes it's me'). A thief with your password still can't get in. Turn it on for email first, then banking and social apps.",
    steps: ["Google: myaccount.google.com → Security → 2-Step Verification.", "Instagram / Facebook: Settings → Accounts Centre → Password and security → Two-factor authentication.", "WhatsApp: Settings → Account → Two-step verification."],
    go: ["accounts"],
  },
  {
    id: "report-fraud",
    test: /\b(?:report|complain|complaint|file (?:a )?(?:case|fir|complaint))\b.{0,40}\b(?:fraud|scam|cyber|hack|cheat|number|call|sms|message|crime)|\b(?:cyber ?(?:crime|cell|police)|helpline)\b/i,
    title: "Reporting cyber fraud in India",
    say: "Money lost: call 1930 first, then report online. A suspicious call or message (no money lost): report it so the number gets blocked.",
    steps: [
      "Money lost or at risk: call 1930 immediately.",
      "File the full complaint at cybercrime.gov.in - keep screenshots, numbers, transaction IDs.",
      "Suspicious call, SMS or WhatsApp with no loss: report it on Sanchar Saathi → Chakshu, or on cybercrime.gov.in → Report Suspect (numbers, links, email IDs).",
      "Tell your bank in writing too, if it involves your account.",
    ],
    links: [REPORT, { label: "Sanchar Saathi", url: "https://sancharsaathi.gov.in" }],
  },
  {
    id: "block-card",
    test: /\b(?:block|freeze|stop|cancel|hotlist)\b.{0,20}\b(?:card|debit|credit|atm|upi|account|netbanking)/i,
    title: "Blocking a card or UPI",
    say: "Fastest: your bank's own app (look for 'Block card' or 'Card controls'). Or call the number printed on the back of the card - it works 24 hours.",
    steps: ["Bank app → Cards → Block / Hotlist.", "Or call the number on the back of your card - not a number from Google search (fake 'customer care' numbers are a common scam).", "For UPI: in the UPI app, remove the bank account, or ask the bank to block UPI."],
  },
  {
    id: "app-safe",
    test: /\b(?:is|are|check if|know if|tell if)\b.{0,25}\b(?:app|apk|application)s?\b.{0,20}\b(?:safe|real|fake|legit|genuine)|\bbefore install/i,
    title: "Is an app safe to install?",
    say: "The safest apps come from the Play Store, from the real company's account, with many downloads and reviews. An app sent over WhatsApp or SMS is the most common way phones are taken over in India.",
    steps: [
      "Install only from the Play Store (or the real company's website for laptops).",
      "Check the developer name matches the company, and look at the reviews - many fakes have few.",
      "Watch what it asks for: a torch or game app asking for SMS, accessibility or 'display over other apps' is a red flag.",
      "Got the file already? Send it to me with the paper-clip - I read its permissions without running it.",
    ],
    go: ["file"],
  },
  {
    id: "need-antivirus",
    test: /\b(?:need|should i (?:get|buy|install|use)|best|which|recommend|good)\b.{0,20}\b(?:anti ?virus|antivirus|security app|mobile security)|\b(?:defender|windows security)\b.{0,15}\b(?:enough|good enough|sufficient)\b/i,
    title: "Do I need an antivirus?",
    laptop: { say: "On Windows 10/11, the built-in Windows Security (Defender) is a real antivirus and scores well in independent tests - you don't need to buy another. Two running at once can clash. What matters more: updates on, and not installing cracked software." },
    phone: { say: "On Android, Google Play Protect is built in and scans your apps. Extra 'antivirus' apps add little and many are adware. What protects a phone: apps only from the Play Store, security updates, a screen lock, and not giving apps powers like Accessibility." },
    go: ["checkup"],
  },
  {
    id: "public-wifi",
    test: /\b(?:public|free|open|cafe|café|airport|railway|station|hotel|mall)\b.{0,15}\bwi-?fi\b|\bwi-?fi\b.{0,20}\b(?:safe|secure|hack)/i,
    title: "Public Wi-Fi",
    say: "Most sites and bank apps encrypt their traffic, so public Wi-Fi is far safer than it used to be. The real risks are fake networks with a real-looking name and pages asking you to 'log in' with personal details.",
    steps: ["For banking and UPI, use mobile data instead.", "Don't enter card details on a 'Wi-Fi login' page.", "Turn off auto-join for open networks."],
  },
  {
    id: "browser-passwords",
    test: /\b(?:save|saving|store|remember)\b.{0,20}\bpasswords?\b.{0,20}\b(?:chrome|browser|edge|google|firefox)|\bpassword manager\b/i,
    title: "Saving passwords in the browser",
    say: "Yes, it's much safer than reusing one password everywhere or writing them in Notes. Google Password Manager and Edge encrypt them and warn you about leaks. Protect the account behind it with a strong password and two-step verification.",
    steps: ["Don't save bank card details in the browser if others use the device.", "Check: passwords.google.com → Password Checkup finds leaked and reused ones."],
    go: ["password"],
  },
  {
    id: "truecaller",
    test: /\btrue ?caller\b/i,
    title: "Truecaller",
    say: "It's a real, widely used app, not malware. The trade-off is privacy: its caller names come from people sharing their contact lists, and it asks for many permissions. Your phone's built-in spam protection (Phone app → Settings → Caller ID & spam) does part of the job without sharing your contacts.",
  },
  {
    id: "vpn",
    test: /\bvpn\b/i,
    title: "Should I use a VPN?",
    say: "A VPN hides your browsing from the Wi-Fi owner and your internet provider. It does NOT stop viruses, scams or phishing, and free VPN apps often sell your data. Most people don't need one; if you want one, pick a well-known paid one or your company's.",
  },
  {
    id: "hack-by-call",
    test: /\b(?:hack|access|control)\w*\b.{0,30}\b(?:by|just by|through|from)\b.{0,15}\b(?:call|calling|missed call|picking up|answering)|\b(?:missed|unknown|strange) call\b.{0,30}\b(?:hack|danger|safe)/i,
    title: "Can a phone be hacked by a call?",
    say: "No - picking up a call can't install anything on your phone. The danger is what the caller persuades you to do: share an OTP, install an app like AnyDesk, or send money. Hang up on anyone who asks for those.",
  },
  {
    id: "old-updates",
    test: /\b(?:security )?(?:update|patch)s?\b.{0,30}\b(?:old|not coming|stopped|no more|available|how)|\bupdate (?:my )?(?:phone|android|laptop|windows)/i,
    title: "Security updates",
    phone: { say: "Security updates close the holes attackers use. Check: Settings → About phone → Software update (on Vivo: Settings → System update). If your phone no longer gets any, it isn't broken - but be extra careful: apps only from the Play Store, keep Play Protect on, keep the Play Store and Chrome updated (those still get fixes), and consider a newer phone for banking." },
    laptop: { say: "Windows Update installs security fixes. Settings → Windows Update → Check for updates, and restart when it asks - many fixes only apply after a restart." },
    go: ["checkup"],
  },
  {
    id: "link-safe",
    test: /\b(?:is|how)\b.{0,20}\b(?:this |a |the )?(?:link|url|website|site)\b.{0,20}\b(?:safe|real|fake|genuine|check)/i,
    title: "Checking a link",
    say: "Paste the link itself into this box and I'll check it here - its real name, look-alike tricks, and the public list of phishing sites.",
    steps: ["Look at the part just before .com / .in: 'sbi.co.in' is SBI; 'sbi-kyc.xyz' or 'sbi.co.in.verify.top' is not.", "Never type a password or OTP on a page you reached from a message."],
  },
  {
    id: "fake-customer-care",
    test: /\bcustomer (?:care|support|service)\b.{0,30}\b(?:number|fake|real|google)|\bhelpline number\b/i,
    title: "Customer care numbers",
    say: "Criminals post fake 'customer care' numbers on Google search, maps and social media. Take the number only from the company's own app or official website, or the back of your card. Real support never asks for OTP, PIN, or to install AnyDesk.",
  },
  {
    id: "sim-in-my-name",
    test: /\b(?:sims?|numbers?|connections?)\b.{0,30}\b(?:in|on|under|with) my (?:name|aadhaar|id)/i,
    title: "SIMs registered in your name",
    say: "The government's Sanchar Saathi site shows every mobile connection registered with your ID, and lets you report the ones you don't recognise.",
    links: [{ label: "Sanchar Saathi", url: "https://sancharsaathi.gov.in" }],
  },
  {
    id: "spam-calls",
    test: /\b(?:stop|block|too many|lots of|getting)\b.{0,20}\b(?:spam|promotional|marketing|telemarketing|unknown) (?:calls?|sms|messages)/i,
    title: "Stopping spam calls",
    say: "Register on India's Do Not Disturb list: call 1909 or send an SMS to 1909 from your number, or use the TRAI DND app. Report scam calls and messages on Sanchar Saathi → Chakshu. Your Phone app's spam filter also helps.",
  },
  {
    id: "aadhaar",
    test: /\baadh?aa?r\b.{0,40}\b(?:safe|misuse|lock|biometric|protect|fraud|leak)/i,
    title: "Protecting your Aadhaar",
    say: "You can lock your Aadhaar biometrics, so fingerprints can't be used for payments or verification until you unlock them. Share a 'masked Aadhaar' (only the last 4 digits show) instead of the full copy.",
    steps: ["myAadhaar portal or the mAadhaar app → Lock/Unlock Biometrics.", "Never share an Aadhaar OTP with anyone."],
    links: [{ label: "myAadhaar", url: "https://myaadhaar.uidai.gov.in" }],
  },
  {
    id: "cracked-software",
    test: /\b(?:crack(?:ed)?|pirated?|mod(?:ded)? apk|free (?:version|download) of|free (?:full )?(?:pc )?(?:game|games)\b.{0,20}\b(?:download|setup|install|website|site)|(?:download\w*|install\w*)\b.{0,20}\bfree (?:full )?(?:pc )?games?|keygen|repack|activator|patch(?:ed)? (?:game|app))\b/i,
    title: "Never run a free or cracked game installer",
    say: "Cracked programs, 'free full version' games and 'mod APKs' are the most common way password stealers get onto personal laptops and phones. The site looks like a game site, the download is a zip, and the Setup.exe inside quietly installs a stealer under a harmless name (a 'hardware monitor', a 'driver') - while you watch a game installer that never finishes. A real case from this laptop's own history went exactly like that.",
    laptop: { steps: [
      "Don't run any Setup.exe, crack, keygen or 'activator' from a free-download site - not even to 'just see'. Running it once is enough.",
      "If a site asks you to turn Windows Security off first, that is the proof: a real installer never needs that.",
      "Want the game or program? Buy it on sale (Steam, Epic, the maker's site) or use a free official alternative.",
      "Already ran one? Treat it as a password stealer: tap 'After a password stealer' below and follow it from your phone, then run an offline scan and get a second opinion.",
    ] },
    phone: { steps: [
      "Don't install 'mod APKs' or 'premium unlocked' apps from websites or Telegram - they are the phone version of the same trap.",
      "Get apps only from the Play Store, and even there check the maker's name.",
      "Already installed one? Uninstall it, then tap 'After a password stealer' below.",
    ] },
    go: ["stealer", "second", "hacked"],
  },
  {
    // Facts checked on the makers' own pages, 24/25 Sep 2026 (reader agent): ESET Online Scanner
    // "Free", "No ... installations are required"; Malwarebytes Free "a cleanup tool for
    // cyberattacks that have already damaged a device"; Microsoft Safety Scanner "expires 10 days
    // after being downloaded", does not require uninstalling your antivirus. Malwarebytes' trial
    // turning on real-time protection = seen on this laptop (incidents/HARDENING-APPLIED.md), so it
    // is worded as a thing to CHECK, not as a vendor fact.
    id: "second-opinion",
    test: /\bsecond opinion\b|\b(?:another|second|other|extra|different)\s+(?:antivirus|anti-virus|scanner|scan)\b|\b(?:eset|malwarebytes|safety scanner)\b/i,
    title: "A second opinion scan",
    laptop: { say: "Windows Defender is good, but after a scare it's worth letting a second, different scanner look once. Use ONE of these, one time - they run next to Defender without replacing it.", steps: [
      "ESET Online Scanner (free, no install): download it from eset.com, choose 'Full scan', and turn on 'detect potentially unwanted applications'. Leave the laptop plugged in - it can take hours.",
      "Or Microsoft Safety Scanner (free, from Microsoft): it only scans when you start it, and stops working 10 days after download - download a fresh one each time.",
      "Or Malwarebytes Free: a clean-up scanner. After installing it, open Windows Security and check it still says Microsoft Defender is protecting you. If Malwarebytes' trial has taken over as the antivirus, Defender's extra blocking rules stop working - end the trial or uninstall Malwarebytes after the scan.",
      "If any of them finds something: let it quarantine it, then tap 'After a password stealer' below - whatever it found may already have copied your logins.",
      "Download only from the maker's own site (buttons below) - fake 'antivirus' downloads are a trap of their own.",
    ], links: [
      { label: "ESET Online Scanner", url: "https://www.eset.com/us/home/online-scanner/" },
      { label: "Microsoft Safety Scanner", url: "https://learn.microsoft.com/en-us/defender-endpoint/safety-scanner-download" },
      { label: "Malwarebytes Free", url: "https://www.malwarebytes.com/mwb-download" },
    ] },
    phone: { say: "On a phone, a second scanner rarely finds what an app check misses: a harmful app is the problem, and removing it is the cure.", steps: [
      "Let me check your apps - I point out the ones with dangerous powers or from outside a store.",
      "Uninstall anything you don't recognise.",
      "If you want a second look at your laptop, open Virus Vigil there and ask for a second opinion.",
    ], links: [] },
    go: ["checkup", "apps", "stealer"],
  },
  {
    // Paths checked on official help pages, 24/25 Sep 2026 (reader agent): Google "Security &
    // sign-in > Your devices > Manage all devices > Sign out" (answer 3067630); Microsoft "Sign out
    // everywhere", up to 24 hours, not Xbox; Telegram "Settings > Devices (or Privacy & Security >
    // Active Sessions)"; Steam "Account Details > Manage Steam Guard" deauthorizes all; Chrome
    // Password Checkup. Instagram/Facebook "Where you're logged in" exists; a one-tap "log out all"
    // was NOT confirmed, so the step says to log out each. Discord's official page could not be
    // opened, so Discord gets no menu path.
    id: "after-stealer",
    test: /\b(?:password|info|cookie|data|token)[- ]?stealers?\b|\bstealer\b|\b(?:stole|stolen|steal)\b.{0,20}\b(?:cookies?|sessions?|tokens?|saved passwords?)\b|\b(?:cookies?|sessions?|tokens?|saved passwords?)\b.{0,20}\b(?:stole|stolen|taken|hijack\w*)\b|\bafter (?:a |the )?(?:virus|malware|trojan|infection)\b.{0,40}\b(?:password|account|what)/i,
    title: "After a password stealer",
    say: "A password stealer copies what your browser remembers - saved passwords AND the 'stay signed in' tickets (cookies) - and sends them off in seconds. With a ticket, the thief is already inside your account without any password, so changing the password alone is not enough: you must also SIGN OUT EVERYWHERE. Do it in this order, and from your PHONE or another clean device - not from the laptop that was infected, until it has been cleaned.",
    steps: [
      "Email first - it can reset everything else. Google: Google Account → Security & sign-in → Your devices → Manage all devices → sign out every device you don't recognise, then change the password. Microsoft: account security → Advanced security options → 'Sign out everywhere' (it can take up to 24 hours), then change the password.",
      "Bank and UPI: call your bank on the number on your card, tell them your laptop had a password stealer, and ask them to watch or block your cards and net banking. Change the net-banking password from your phone. If any money has moved: 1930 and cybercrime.gov.in straight away.",
      "Chats: WhatsApp → Linked devices → log out every device listed. Telegram → Settings → Devices → terminate every other session. Discord and others: open the devices / sessions list in their settings and log out everything.",
      "Social and games: Instagram and Facebook → Accounts Center → 'Where you're logged in' → log out each one you don't recognise. Steam → Account Details → Manage Steam Guard → deauthorize all other devices.",
      "Change every password that was saved in the browser, then run Google's Password Checkup (passwords.google.com) to catch the ones you forgot. Turn on two-step verification everywhere it's offered.",
      "If you code or use crypto: delete and re-create GitHub tokens, SSH keys and cloud keys that were on the laptop; move any crypto to a NEW wallet (stealers take wallet files).",
      "Then clean the laptop: Defender offline scan, and a second opinion scan. Only after that, sign in on it again.",
    ],
    links: [
      { label: "Google: your devices", url: "https://myaccount.google.com/security" },
      { label: "Microsoft: sign out everywhere", url: "https://account.microsoft.com/security" },
      { label: "Google Password Checkup", url: "https://passwords.google.com" },
      REPORT,
    ],
    go: ["second", "password"],
  },
  {
    id: "factory-reset",
    test: /\b(?:factory reset|format|reset)\b.{0,30}\b(?:phone|laptop|virus|hack|remove|help|safe)/i,
    title: "Does a factory reset remove hackers?",
    say: "It removes apps and malware from the device - almost always enough. It does NOT fix hacked accounts: change your email and other passwords too, from a clean device. Don't restore the same suspicious app from backup afterwards.",
  },
  {
    id: "juice-jacking",
    test: /\b(?:public|free|airport|station|bus)\b.{0,20}\b(?:charg\w*|usb)\b|\bcharg\w*\b.{0,30}\b(?:railway|station|airport|public|bus|mall|cafe)\b/i,
    title: "Public charging points",
    say: "Real attacks through charging ports are very rare, but easy to avoid: use your own charger in a wall socket, or a power bank. If the phone asks 'Allow access to data?' when charging, tap Deny.",
  },
  {
    id: "camera-spy",
    test: /\b(?:is|are|can)\b.{0,20}\b(?:someone|anyone|hacker|app)s?\b.{0,20}\b(?:watch|see|spy|record|listen)/i,
    title: "Is someone watching through the camera?",
    say: "Both Android and Windows show a green dot or light when the camera or microphone is in use, and keep a record of which app used them.",
    go: ["camera"],
  },
  {
    id: "safe-upi",
    test: /\b(?:upi|gpay|google pay|phonepe|paytm|bhim)\b.{0,40}\b(?:safe|tips|secure|fraud|protect)/i,
    title: "Using UPI safely",
    say: "Rule one: you enter your UPI PIN only to SEND money. Anyone asking you to scan a QR or enter a PIN to 'receive' money is scamming you.",
    steps: ["Check the name shown before you pay.", "Don't accept 'collect requests' you didn't expect.", "Before a big payment, tap 'Before a big payment' - I check this device first."],
    go: ["payment"],
  },
  {
    id: "email-attachment",
    test: /\b(?:email|mail)\b.{0,30}\b(?:attachment|pdf|zip|file|invoice)|\b(?:attachment|pdf|zip)\b.{0,20}\b(?:safe|open|virus)/i,
    title: "Email attachments",
    say: "Be wary of unexpected invoices, 'payment receipts', ZIP files and anything asking you to 'enable editing' or 'enable content'. Send the file to me with the paper-clip before opening it.",
    go: ["file"],
  },
  {
    id: "deepfake-voice",
    test: /\b(?:deep ?fake|ai voice|cloned voice|voice clone|fake video call)\b|\bvoice\b.{0,20}\b(?:sounded like|same as) my\b/i,
    title: "Fake voice and video calls",
    say: "Scammers can now copy a relative's voice from a short clip. If a 'relative' calls in panic asking for money, hang up and call them back on the number you already have. A family code word helps.",
  },
  {
    id: "sell-phone",
    test: /\b(?:sell|selling|give away|exchange|old)\b.{0,20}\b(?:phone|laptop|mobile)\b.{0,30}\b(?:data|safe|wipe|erase|reset)?/i,
    title: "Before selling or giving away a device",
    phone: { say: "Back up, then Settings → System → Reset → Erase all data (factory reset). Remove your Google account first, take out the SIM and memory card, and un-link it from WhatsApp and banking apps." },
    laptop: { say: "Back up, sign out of browsers and Microsoft account, then Settings → System → Recovery → Reset this PC → Remove everything, with 'Clean data' switched on." },
  },
];

// More specific entries must win over the broad ones they overlap ("does factory reset remove
// a virus?" is about reset, not removal). Stable sort keeps the rest in written order.
const SPECIFIC_FIRST = ["after-stealer", "second-opinion", "factory-reset", "cracked-software", "browser-passwords", "whatsapp-2fa", "juice-jacking"];
ANSWERS.sort((a, b) => SPECIFIC_FIRST.includes(b.id) - SPECIFIC_FIRST.includes(a.id));

// Extra words to explain (added to GLOSSARY in main.js)
export const MORE_GLOSSARY = {
  "smishing": "Smishing is phishing by SMS: a text pretending to be your bank, courier or electricity board, with a link or number that leads to a scam.",
  "vishing": "Vishing is phishing by voice call: someone pretending to be the bank, police or customer care, talking you into sharing an OTP, installing an app or sending money.",
  "sim swap": "A SIM swap is when a criminal gets a new SIM issued on YOUR number (with fake papers or an inside helper). Your phone loses network, and your OTPs go to them. Sudden 'no network' for hours is the sign - call your operator.",
  "keylogger": "A keylogger is spying software that records every key you press - including passwords - and sends them to the attacker. It usually arrives inside a fake or cracked program.",
  "rootkit": "A rootkit is malware that hides deep inside the system so ordinary tools can't see it. Offline scans (which run before Windows starts) are how it's usually found.",
  "botnet": "A botnet is a crowd of hacked devices controlled together by one criminal - used to send spam or attack websites, often without the owners noticing.",
  "spoofing": "Spoofing is faking who a message or call comes from - a caller ID showing your bank's number, or an email that looks like it's from a friend. What the screen shows as the sender can be forged.",
  "deepfake": "A deepfake is a fake video or voice made with AI to look and sound like a real person. Scammers use them to pose as relatives or officials.",
  "zero-day": "A zero-day is a hole in software that attackers know about before the company has a fix. Updates close them once a fix exists - that's why updates matter.",
  "stalkerware": "Stalkerware is a spying app someone installs on another person's phone to read their messages, see their location and listen in - often a partner or someone close. It hides its icon.",
  "encryption": "Encryption scrambles data so only someone with the key can read it. An encrypted phone is unreadable to a thief without your lock screen PIN.",
  "remote access": "Remote access means someone else can see and control your screen from far away (apps like AnyDesk or TeamViewer). Useful for real IT help, and the favourite tool of 'bank refund' scammers.",
  "mule account": "A mule account is a bank account used to receive and pass on stolen money. Lending your account for 'commission' makes you part of the crime.",
  "security update": "A security update (or patch) is a fix for holes found in the software. Without them, known holes stay open for attackers.",
  "play protect": "Google Play Protect is Android's built-in scanner: it checks apps from the Play Store and elsewhere for harmful behaviour.",
  "adware": "Adware is an app or program whose job is to show you ads - pop-ups, full-screen ads, new tabs. Annoying, sometimes risky, usually removed by uninstalling the last apps you added.",
  "hacker": "A hacker (in the everyday sense) is someone who breaks into devices or accounts. Most 'hacks' of ordinary people are actually tricks - a stolen OTP or password - not movie-style break-ins.",
  "scam": "A scam is a trick to get your money or details, usually with pressure (hurry, fear, a prize). The pressure itself is the warning sign.",
};

// Shortest useful text for a platform-varying entry
export function forPlatform(entry, phone) {
  const v = (phone ? entry.phone : entry.laptop) || {};
  return { say: v.say || entry.say || "", steps: v.steps || entry.steps || [] };
}
