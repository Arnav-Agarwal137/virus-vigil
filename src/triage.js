// Virus Vigil - triage: when someone types a PROBLEM ("money got deducted", "my insta is hacked",
// "help"), Vigil does not answer with one general page. It asks two or three tap-questions to pin
// down what exactly happened, then gives the steps for THAT case. His rule, 24 Sep 2026 20:08
// (RULES.md): "when a problem is given make the bot ask questions to user to pin point and guide
// properly". Offline, same on phone and laptop.
//
// Pure data + pure functions (no page code), so tests/triage/walk.mjs can walk every path in Node.
//
//   detectProblem(text)       -> family id, or null (a question, a pasted message, not a problem)
//   FAMILIES[f]               -> { start: node id, urgent?: text shown before the first question }
//   NODES[id]                 -> { ask, options: [{ label, set?, to?, hint?, only? }] }
//                                 `to` = next node (may belong to another family: its leaf then
//                                 answers); no `to` = answer now. `hint` = if the typed message
//                                 already says it, that option is picked without asking.
//                                 `only` = "phone" | "laptop".
//   leafFor(family, ctx, phone) -> { title, say, steps, links, go, danger }
//
// Facts: only those already verified for answers.js (1930, cybercrime.gov.in, RBI 3 / 4-7 working
// days, Sanchar Saathi Chakshu / CEIR, recovery URLs, Find My Device). NOT verified and therefore
// worded without menu paths: WhatsApp two-step, Play Protect, Chrome notification settings.

import { FIRST_AID } from "./answers.js";
import { wordGuess, wordRank } from "./wordscore.js";

const REPORT = { label: "Open cybercrime.gov.in", url: "https://cybercrime.gov.in" };
const CHAKSHU = { label: "Sanchar Saathi (report a scam call)", url: "https://sancharsaathi.gov.in" };
const RECOVERY = {
  insta: { label: "Instagram recovery", url: "https://www.instagram.com/hacked/" },
  fb: { label: "Facebook recovery", url: "https://www.facebook.com/hacked" },
  google: { label: "Google recovery", url: "https://accounts.google.com/signin/recovery" },
  microsoft: { label: "Microsoft recovery", url: "https://account.live.com/acsr" },
};

// ---------- which problem is this? ----------
const FIRST_AID_FAMILY = {
  "money-lost": "money", "otp-shared": "code", "card-entered": "code", "clicked-link": "link",
  "installed-app": "app", "remote-access": "remote", "account-hacked": "account",
  "device-hacked": "device", "lost-phone": "lost", "sim-dead": "sim", "blackmail": "threat",
  "loan-app": "threat", "ransom-files": "ransom",
};

// Families in PRIORITY order: the first that matches wins. Why this order: money lost beats how it
// got lost ("clicked a link and 42000 is gone" is a money problem); a code given away beats the
// call that asked for it; a device acting up beats the link that started it; a call is the
// weakest signal (the person may have done nothing yet). Each family = its first-aid pattern from
// answers.js (English, first person) + the words those miss: Hinglish, no "I" at the start,
// "emergency calls only", laptops.
const SPY_PATTERN = /\b(?:spy|spying|stalker|tracking|tracker|monitoring|jasoosi)\s*(?:app|apps|software|program)\b|\b(?:spy|stalker)ware\b|\b(?:mspy|flexispy|thetruthspy|truthspy|spyzie|hoverwatch|cocospy|eyezy|spyic|xnspy)\b/i;
const PATTERNS = [
  ["remote", /\b(?:anydesk|any desk|teamviewer|team viewer|quick ?support|rustdesk|airdroid)\b|\bremote (?:control|access|desktop|support)\b|\btook (?:remote )?control\b|\bscreen ?shar\w*|\bshare (?:my |the |his |her |your )?screen\b|\b(?:controlling|moving|using)\b.{0,15}\bmy (?:laptop |pc |computer |phone )?(?:mouse|cursor|screen)\b|\b(?:mouse|cursor)\b.{0,20}\b(?:moving|moved|clicking)\b.{0,15}\b(?:on its own|by itself|khud se|apne aap)|\b(?:see|seeing|control|controlling)\s+(?:my|the)\s+screen\b|\bseeing everything i (?:typed|type|did|do)\b|\bshar\w*\s+(?:my |your |the |his |her )?screen\b|\b(?:mouse|cursor|pointer)\b(?!.{0,6}\b(?:not|nahi|isn'?t|doesn'?t)\b).{0,30}\b(?:apne aap|khud se|by itself|on its own|chal(?:ne)? (?:raha|rha|rahi|lag\w*)|moving|moves|moved)\b/i],
  ["money", /\b(?:transactions?|charges?|payments?|debits?)\b.{0,40}\b(?:i (?:never|didn'?t|did not) (?:make|made|do|did)|not (?:mine|by me)|dikh rahe)\b|\b(?:international|unknown|unauthori[sz]ed)\s+(?:transactions?|charges?|payments?)\b.{0,60}\b(?:card|account|wallet)\b|\b(?:paise?|paisa|rupaye|rupay)\b(?!.{0,25}\bnahi\s+(?:kat|kaat|cut|gaye|gaya|nikle|nikla))(?!\s*(?:abhi tak\s*)?nahi\b).{0,25}\b(?:kat|kaat|cut|gaye|gaya|chale|nikal|nikle|debit)|\baccount se\b.{0,25}\b(?:kat|kaat|nikal|gaye|gaya)|\b(?:lost|lose|losing)\b.{0,15}\b(?:money|rs\.?|rupees|\d{3,})|^(?=.*\b(?:paid|pay|sent|lost|money|rupees|rs|advance|fee|₹)).*\b(?:fake|fraud)\s+(?:seller|buyer|shop|website|job|company|investment|trading)\b|\b(?:i|we)\s+(?:got|were|was|have been)\s+(?:cheated|looted|duped)\b|\bpaid\b.{0,40}\b(?:but|and)\b.{0,30}\b(?:never|no|not)\b.{0,20}\b(?:came|received|arrived|deliver|reply|replying|respond|answer)|\b(?:took|taken|stole|stolen|gone|cut|deducted|debited|withdrew|withdrawn|missing|nikal)\b.{0,30}\b(?:from|out of|se)\s+(?:my|our|mere|mera|meri)\b.{0,20}\b(?:account|a\/c|bank|wallet|upi|card|paytm)|\b\d[\d,]{2,}\s*(?:rs|rupees|₹)?\b.{0,25}\b(?:gone|taken|missing|cut|deducted|debited|withdrawn|stolen)\b|\bupi fraud\b|\b(?:fee|fees|charges?|\d[\d,]{2,}\s*(?:rs|rupees?|rupye|rupaye|₹)?)\b.{0,40}\b(?:pay|payment|transfer|bhej)\w*\s+kar\s+(?:di|diya|diye|dia)\b|\b(?:pay|payment|transfer)\w*\s+kar\s+(?:di|diya|diye|dia)\b.{0,40}\b\d[\d,]{2,}|\bfraud\b.{0,15}\b(?:happened|hua|ho gaya|hogaya|with me)|\bturned out (?:to be )?(?:a )?(?:fake|fraud|scam)|\bwithdrawal\b.{0,20}\b(?:stuck|pending|blocked|not)|\binvest\w*\b.{0,60}\b(?:not opening|stuck|can'?t withdraw|scam|fraud|fake)|\bcharged\b.{0,40}\b(?:never|didn'?t|did not|without)|\b(?:advance|deposit)\b.{0,40}\b(?:fake|not responding|scam|fraud)|\b(?:she|he|they|i|mom|mum|dad|mother|father|papa|mummy)\s+(?:sent|paid|transferred)\s+(?:rs\.?\s*|₹\s*)?\d[\d,]{2,}/i],
  ["threat", /\bdigital(?:ly)?\s+arrest\w*|\b(?:cbi|ncb|ed officer|police|customs|narcotics|cyber ?cell|trai)\b.{0,80}\b(?:arrest\w*|warrant|case|fir)\b.{0,80}\b(?:video call|skype|don'?t tell|do not tell|kisi ko (?:batana|mat)|stay on (?:the )?call|call (?:pe|par) (?:hi )?(?:rehna|raho|baitha|baithi))|\b(?:webcam|camera)\b.{0,60}\b(?:record\w*|video)\b.{0,80}\b(?:pay|bitcoin|btc|crypto)\b|\b(?:dhamki|blackmail|threaten|threatening|extort)\w*|\b(?:nude|private|intimate)\s+(?:photos?|pics?|videos?)\b|\bvideo call\b.{0,40}\b(?:record|recorded|screenshot)|\b(?:recovery|loan) agents?\b.{0,40}\b(?:call|abus|threat|harass|messag)|\bsextortion\b|^(?=.*\b(?:cbi|ncb|enforcement directorate|ed officer|police|customs|narcotics|cyber ?cell|crime branch|trai)\b)(?=.*\b(?:arrest\w*|warrant|fir|money laundering|drugs?|jail|pakad\w*|pakd\w*)\b)(?=.*\b(?:video call|on video|skype|don'?t tell|do not tell|not tell anyone|kisi ko|stay on|paise bhej\w*|send money|transfer)\b)|\b(?:beta|beti|son|daughter|bhai|brother|husband|pati|nephew|bhatija)\b.{0,50}\b(?:pakda|pakdi|pakde|arrest\w*|caught|jail|custody|hirasat)\b.{0,80}\b(?:paise|paisa|money|bhej\w*|send|transfer|pay)\b|\bloan app\b(?=.{0,120}\b(?:threat\w*|abus\w*|harass\w*|morph\w*|edit\w*|send\w*|sent|bhej\w*|call\w*|messag\w*|shar\w*|viral|leak\w*|dhamki)\b).{0,60}\b(?:photo|pic|family|contacts|bhej|morph|edit)|\bphotos?\b.{0,20}\bedit kar|\b(?:will|going to)\s+(?:send|share|leak|post|show)\b.{0,30}\b(?:family|friends|contacts|everyone|parents)/i],
  ["ransom", /\b(?:can'?t|cannot|unable to|not able to)\s+open\b.{0,40}\b(?:files?|photos?|documents?)\b.{0,80}\b(?:money|pay|payment|ransom|key|bitcoin|crypto)\b|\b(?:files?|photos?|documents?)\b.{0,30}\b(?:encrypted|locked)\b|\bransom(?:ware)?\b|\bunlock\b.{0,40}\b(?:paise|money|pay|bitcoin|maang|mang)|\bbitcoin\b.{0,40}\b(?:mang|maang|demand|pay|unlock)|\b(?:system|laptop|computer|pc|files?)\b.{0,20}\block ho|\.locked\b|\bextensions? (?:changed|renamed)|\bpay\w*\b.{0,15}\bdecrypt|\b(?:note|readme|message)\b.{0,30}\b(?:asks?|demands?|wants?)\b.{0,20}\b(?:btc|bitcoin|crypto)\b|\b(?:weird|strange|unknown) extensions?\b|\bdecrypt\w*\b.{0,30}\b(?:key|tool|pay|bitcoin|ransom)|\bread_?me\b.{0,60}\b(?:contact|pay|e-?mail|get (?:them|it|my files|files) back|recover|decrypt)|\bhow_to_(?:recover|decrypt|restore|back)\w*|\b(?:pop-?up|message|note)\b.{0,30}\bpay\w*\b.{0,20}\bunlock|\bpay\w*\b.{0,15}\bto unlock/i],
  ["code", /\b(?:otp|pin|code|password|cvv)\b.{0,20}\b(?:de diya|de di|bata diya|bata di|share kar|share kiya|bhej diya|diya)|\bcode that came\b|\b(?:needed|need|asked for|asking for|wanted|maanga|manga|mang rahe)\b.{0,40}\b(?:otp|code|pin|\d[- ]?digits?(?: number| code)?|number that came)\b.{0,80}\b(?:i (?:told|gave|shared|sent|read)|told (?:him|her|them)|gave (?:it|him|her|them)|bata (?:diya|di)|de (?:diya|di)|share kar (?:diya|di))\b|\b(?:told|gave|said)\b.{0,15}\b(?:him|her|them|the caller|that guy|the man|the lady)\b.{0,20}\b(?:code|otp|pin|number that came)|\b(?:gave|shared|told|sent|typed|read out)\b.{0,15}\b(?:my|the|mera)?\s*(?:atm |upi |card |bank |netbanking )?(?:otp|pin|cvv|password|code)\b/i],
  ["account", /\bregistered on another (?:phone|device|mobile)\b|\b(?:facebook|fb|insta\w*|whats ?app|account|id|profile)\b.{0,15}\b(?:is |was )?(?:sending|posting)\b.{0,40}\b(?:asking for|money|loan|paise)\b|\b(?:whats ?app|insta\w*|facebook|fb|gmail|account|id)\b.{0,20}\b(?:khud se |apne aap )?log ?out ho\b|\bmere (?:number|account|id|naam) se\b.{0,40}\b(?:msg|message|messages|maang|post\w*|chat\w*|fake)|\b(?:fake|duplicate|another|second)\s+(?:account|profile|id)\b.{0,40}\b(?:my name|my photos?|my pics?|of me|pretending)|\b(?:account|id|insta|instagram|facebook|fb|whatsapp|gmail|email)\b.{0,30}\b(?:hack\s*(?:ho|kar|hua)|le liya|chura)|\b(?:someone|somebody|hacker)\b.{0,25}\b(?:posting|messaging|sending|texting|chatting)\b.{0,30}\b(?:from|on|as) my\b|\b(?:friends|contacts|family)\b.{0,30}\b(?:getting|got|received)\b.{0,30}\bmessages?\b.{0,20}\bfrom my\b|\b(?:account|e-?mail|id|insta\w*|whats ?app|facebook|fb|gmail)\b.{0,15}\b(?:got|was|has been|is|been)\s+(?:taken over|hacked|compromised|stolen)|\blost access to (?:my|our)\b|\b(?:account|id|insta\w*|whats ?app|facebook|fb|gmail|e-?mail|linkedin|twitter|snapchat|telegram)\s+(?:hacked|hack ho)|\blog-?in\b.{0,30}\b(?:another|new|unknown|other|different) (?:device|location|phone|place)|\b(?:unknown|new|suspicious) (?:login|sign-?in)s?\b|\bpassword (?:was |got |has been )?changed\b.{0,40}\b(?:never|didn'?t|did not|not me)\b|\b(?:account|acc|id|insta\w*|whats ?app|facebook|fb|gmail|e-?mail|linkedin|twitter)\b.{0,15}\b(?:hijack\w*|compromised)|\bpassword\b.{0,15}\b(?:change ho|badal)|\blogin se nikal|\brecovery (?:number|email|phone)\b.{0,25}\bchange|\bposting\b.{0,30}\b(?:spam|fake|weird|links?|ads?)\b.{0,30}\b(?:under my name|from my|to everyone|everyone)|\bcan'?t log ?in to my\b|\b(?:yahoo|gmail|e-?mail|mail|insta\w*|facebook|fb|whats ?app|id|account)\b.{0,15}\bnahi khul\w*|\b(?:account|profile|id|linkedin|insta\w*|facebook|fb|twitter)\b.{0,40}\b(?:posting|sending|messaging)\b.{0,40}\b(?:never|didn'?t|did not)\s+(?:wr[io]te|sen[dt]|post(?:ed)?|typed?)\b/i],
  // A spy app someone else put on the phone is NOT "an app I installed": its answer must put the
  // person's safety before "uninstall it" (removing it can warn whoever is watching). So it goes
  // to the device questions, whose "Someone knows my chats or location" leaf says that first.
  ["device", SPY_PATTERN],
  ["app", /\b(?:app|apk|software|application)\b.{0,30}\b(?:install|download)\s*(?:kiya|kar liya|ki|kara)\b|\b(?:installed|downloaded)\b.{0,30}\b(?:app|apk|application|software)\b|\bsideload\w*|\bgranted\b.{0,30}\b(?:permission|access)|\b(?:accessibility|permission)\b.{0,20}\b(?:by mistake|galti)|\b(?:ran|run|opened|installed|downloaded|clicked)\b.{0,40}\b(?:setup(?:\.exe)?|installer|crack(?:ed)?|keygen|repack|activator|free game|(?:cracked|pirated|modded) \w+|game (?:setup|installer))\b|\b(?:cracked|pirated|torrent(?:ed)?|free(?: full)?)\s+(?:game|games|software|windows|office|photoshop|version)\b.{0,50}\b(?:download\w*|install\w*|ran|run|setup|opened)\b|\b(?:app|apk)\b.{0,40}\b(?:outside (?:the )?play ?store|from a link|not from (?:the )?play ?store)\b|\b(?:can'?t|cannot|unable to|not able to)\s+uninstall\b|\buninstall\b.{0,40}\b(?:greyed|grayed|disabled|nahi ho|not (?:working|allowed|possible))|\bno icon\b.{0,40}\b(?:app|uninstall|settings|phone)\b|\b(?:app|service)\b.{0,30}\b(?:with )?no icon\b/i],
  ["lost", /\bpick-?pocket\w*|\b(?:i?phone|mobile|laptop)\s+(?:gone|chori)\b|\b(?:left|forgot)\b.{0,10}\bmy (?:i?phone|mobile|laptop|tablet|ipad)\b.{0,20}\bin (?:an? |the )?(?:uber|ola|cab|auto|taxi|train|bus|metro|flight)\b|\b(?:bag|wallet|purse|backpack)\b.{0,15}\b(?:stolen|snatched|chori|lost)\b.{0,60}\b(?:i?phone|mobile|laptop)\b|\b(?:lost|stolen|snatched)\s+(?:iphone|ipad|android)\b|\b(?:phone|mobile|laptop)\b.{0,15}\b(?:chori|kho gaya|kho gya|gum ho|missing)|\b(?:left|forgot|dropped)\b.{0,10}\bmy (?:phone|mobile)\b.{0,30}\b(?:gone|not there|missing|someone took)|\b(?:lost|stolen|snatched|chori|misplaced)\b.{0,25}\b(?:phone|mobile|laptop)\b|\b(?:phone|mobile|laptop)\b.{0,25}\b(?:got |was |been |is )?(?:lost|stolen|snatched|missing)\b|\b(?:phone|mobile)\b.{0,20}\b(?:fell|dropped|gir gaya|gir gya)|\bcan'?t (?:locate|find) (?:it|my (?:phone|mobile))|\b(?:ipad|tablet|macbook|tab)\b.{0,40}\b(?:chori|kho gaya|kho gayi|kho gya|gum ho|lost|stolen|snatched|missing)\b|\b(?:lost|stolen|snatched|chori|misplaced)\b.{0,25}\b(?:ipad|tablet|macbook)\b|\b(?:phone|mobile|laptop)\b.{0,15}\bkho gayi\b/i],
  ["sim", /\bsim (?:is |went |got |has )?(?:dead|gone dead)\b|\b(?:20|twenty)[- ]digit\b.{0,40}\bsim\b|\bsim\b.{0,40}\b(?:20|twenty)[- ]digit\b|\bsim (?:replacement|swap|change|upgrade)\b.{0,60}\b(?:never|didn'?t|did not|not me)\b|\bsim\b.{0,20}\b(?:was |got |been )(?:replaced|swapped|changed)\b|\bnumber\b.{0,20}\bsuddenly stopped working\b|\bsim\b.{0,15}\b(?:band|nahi chal|kaam nahi)|\b(?:no|lost)\s+(?:network|signal)\b.{0,40}\b(?:hours|morning|since|suddenly|whole day)|\b(?:no service|emergency calls? only|sos only|sim not (?:detected|working)|no sim)\b|\b(?:signal|network)\b.{0,15}\b(?:chala gaya|chala gya|nahi aa raha|nahi aa rha|gayab)|\bnaya sim\b|\bsim\b.{0,25}\bnot registered\b|\bnot registered on (?:the )?network\b|\binvalid sim\b|\bsim\b.{0,20}\b(?:deactivat\w*|band ho)|\bsim swap\b|\be-?sim\b.{0,80}\b(?:never|didn'?t|did not|not me|nahi kiya)\b/i],
  ["device", /\b(?:phone|mobile|laptop|computer|pc|system|tab|tablet)\b.{0,30}\b(?:acting (?:weird|strange|up)|behaving (?:weird|strange|oddly)|weird|strange things|by itself|on its own|on their own|by themselves|khud se|apne aap|hack ho|virus aa|full of (?:ads|pop-?ups)|ajeeb|hang)|\b(?:pop-?ups?|ads)\b.{0,30}\b(?:everywhere|keep|coming|khud se|apne aap|bar bar|khulte|khul rahe|on my (?:phone|screen|laptop|home ?screen))|\b(?:spying|watching|tracking|listening|stalking)\b.{0,20}\b(?:on me|me|my)\b|\b(?:reading) my\b|\bsomeone\b.{0,20}\b(?:knows|reads|sees)\b.{0,20}\bmy (?:chats?|messages|location|whereabouts)|\b(?:keeps?|kept)\s+(?:restarting|rebooting|crashing|opening|closing|turning|freezing)|\b(?:unknown|strange|new)\s+(?:icons?|apps?|programs?|files?)\b.{0,15}\b(?:appeared|showing|came|popped)|\bshowing (?:unknown|strange|new) (?:apps?|icons?)|\bapps? (?:i )?(?:never|didn'?t|did not) install|\bfan\b.{0,30}\b(?:loud|always|all the time)|\b(?:phone|mobile|laptop)\b.{0,30}\b(?:heating|heats up|overheat\w*|battery (?:drain\w*|khatam)|drains)|\bpop-?ups?\b.{0,30}\b(?:saying|says|infected|virus|call)|\b(?:camera|mic) (?:light|led)\b|\b(?:garam|garm)\b|\bblue (?:screen|error)\b|\bkeeps? coming back\b.{0,20}\b(?:after|even)\b|\b(?:full ?screen )?(?:adverts?|advertisements?|ads?)\b.{0,30}\b(?:comes?|appears?|pops?)\b.{0,30}\b(?:home ?screen|unlock|every time)|\bsending\b.{0,10}\b(?:sms|messages?|texts?)\b.{0,10}\b(?:on its own|by itself|khud se|apne aap)|\boutbox\b.{0,40}\b(?:don'?t know|unknown|never)|\b(?:icon|app)\b.{0,20}\bno name\b|\b(?:homepage|home page|search engine|new tab)\b.{0,20}\b(?:keeps? chang\w*|changed|hijack\w*)|\bextensions?\b.{0,20}\b(?:i )?(?:never|didn'?t|did not) (?:add|install)|\b(?:restart(?:ed|s|ing)?|reboot\w*)\b.{0,30}\b(?:itself|own|times|again)|\bajeeb\b.{0,30}\b(?:phone|mobile|laptop)\b|\b(?:antivirus|anti-virus|defender|scan\w*|security app)\b.{0,40}\b(?:found|detected|mile|mila|shows?|showing|dikha\w*|says?)\b.{0,25}\b(?:virus\w*|threats?|malware|trojans?|infect\w*)\b|\b\d+\s+(?:virus\w*|threats?|malware)\s+(?:found|detected|mile|mila)\b/i],
  ["link", /\b(?:clicked|opened|tapped|pressed|khola|kholi|click kiya|visited)\b.{0,30}\blink\b|\blink\b.{0,30}\b(?:khola|kholi|click kiya|clicked|opened|tapped)|\blink\b.{0,10}\b(?:pe|par)\s+click|\bclick kar (?:diya|di)\b|\blink\b.{0,60}\b(?:opened|clicked|tapped) it\b|\b(?:clicked|opened|tapped)\b.{0,30}\bforward(?:ed)?\b|\bopened (?:a |an |some )?(?:strange|weird|suspicious|fake|unknown)\s+(?:website|site|page)\b/i],
  ["call", /\b(?:i\s+)?(?:got|received|getting|receiving|had)\s+(?:a|an|this|one|many|some)?\s*(?:strange|weird|suspicious|fake|unknown|scam|fraud)?\s*(?:call|calls|video call|message|sms|text|whats ?app (?:message|call))\s+(?:from|saying|that|claiming|asking)|\b(?:someone|somebody|a (?:man|lady|woman|guy|person)|(?:a|an|one) (?:caller|number))\b.{0,10}\b(?:called|calling|call kiya|phoned|messaged|texted)\b|\b(?:called|calling)\b.{0,15}\b(?:claiming|pretending|saying)\b|\bcall aaya\b|\b(?:message|msg|sms|text|whats ?app)\s+(?:aaya|aayi|aya|ayi|aa (?:raha|rahe|rha|gaya|gya))\b|\bcall kiya\b|\b(?:voice|sounded) (?:exactly |just )?like (?:my )?\w+\b.{0,60}\b(?:crying|needs?|money|police|jail|hospital|accident|\d+k)\b|\b(?:ivr|recorded (?:call|voice|message))\b.{0,100}\b(?:press(?:ed)? \d|asked|gave|officer)\b|\b(?:digital arrest|cbi|customs|narcotics|fedex|courier)\b.{0,120}\b(?:call|called|video|arrest)|\b(?:got|received|getting|receiving|had)\b.{0,25}\b(?:calls?|video calls?|messages?|sms|texts?)\b.{0,10}\b(?:from|saying|that|claiming|asking)|\b(?:missed call|international number|called (?:it |them )?back)\b|\b(?:got|received|getting|had)\s+(?:a |an |some |many |so many )?(?:strange|weird|suspicious|fake|unknown|scam|fraud|spam|threatening)\s+(?:(?:whats ?app|telegram|insta(?:gram)?|facebook|fb|sms|text|e-?mail)\s+)?(?:calls?|video calls?|messages?|msgs?|sms|texts?)\b/i],
];

// Someone who pastes the scam message itself ("Dear customer, your a/c will be blocked") is
// showing us a MESSAGE to check, not describing their own problem.
const PASTED = /\b(?:dear (?:customer|user|sir|madam|member|valued)|your (?:a\/c|account|card|kyc|sim|parcel|order|number|electricity|bill|pan|aadhaar)\b|click (?:here|the link|below)|call (?:on |at )?\+?\d{8,}|you have (?:won|been selected))/i;
// A scam text often speaks as "I" too - the scammer's I ("I am calling from your bank",
// "Hello beta, this is your uncle"). Spoken TO the reader, in that voice, and not retold by the
// person ("he called saying...") = a pasted message, not their own problem.
const SCAMMER_VOICE = /^(?:hello|hi|hey|dear|namaste|namaskar)\b.{0,25}\b(?:beta|sir|madam|mam|customer|friend|mom|mum|mummy|dad|papa|uncle|aunty|bhai|dost)\b|\b(?:i am|i'm|this is|we are)\s+(?:calling |speaking |writing )?(?:from|with)\s+(?:your|the|sbi|hdfc|icici|axis|amazon|flipkart|paytm|airtel|jio|vi|bsnl|customs|police|cbi|trai|rbi|income tax)\b|\bthis is (?:an? )?(?:cbi|police|customs|trai|rbi|income tax|cyber ?cell|narcotics|fedex)\b|\bthis is your (?:uncle|aunty|son|daughter|friend|cousin|boss|bank|brother|sister)\b|^(?:hi |hello )?(?:mom|mum|mummy|maa|papa|dad|beta|bhai|didi)\b.{0,60}\b(?:new number|send|transfer)|\b(?:this is my new number|my new number)\b.{0,80}\b(?:send|transfer|pay|money|urgent)/i;
const RETOLD = /\b(?:called me|calling me|call aaya|said|saying|says|claimed|claiming|told me|messaged|msg|sms|texted|got a|received|pretending|forwarded)\b/i;
const ADDRESSED = /\b(?:you|your|yours|u r|ur|aap|aapka|aapke|aapki|tum|tumhara)\b/i;
// No "we / our / us": scammers write those ("our agent will call", "contact us").
const FIRST_PERSON = /\b(?:i|i'm|im|i've|ive|my|me|mine|mera|mere|meri|maine|mujhe|mujhse|hamara|humara|apna|apne|karu|karun|karoon|dad'?s|mom'?s|father'?s|mother'?s)\b/i;

// Too vague to know which problem: ask what happened first.
const VAGUE = /^(?:please\s+)?(?:help(?:\s+me)?(?:\s+please)?|i need help|need help|sos|urgent(?:\s+help)?|madad|bachao|i(?:'m| am) in trouble|i have a problem|problem|something(?:'s| is)? (?:wrong|happened|bad happened)|something happened|i (?:got|was|have been|think i (?:got|was)) (?:scammed|hacked|cheated|fooled|tricked|duped)|i think i(?:'ve| have)? been (?:scammed|hacked)|i(?:'ve| have)? been (?:scammed|hacked)|(?:i )?(?:got )?(?:scammed|hacked)|i think i(?:'?m| am) (?:hacked|scammed)[,.!?]*\s*(?:what (?:do|should|to) i do|now what|help)?|kuch (?:gadbad|galat|garbar|gadbad)\s+(?:ho\s+)?(?:gayi|gaya|gya|gyi|hua|hui)(?: hai)?(?:[,.!]*\s*(?:samajh nahi aa raha|samajh nahi aa rha|kya karu\w*|help))?)(?:[,.!?]*\s*(?:what (?:do|should|to|can) i do(?: now)?|now what|please help(?: me)?|help(?: me)?(?: please)?|kya karu\w*|kya karoon))?\s*[!.?]*$/i;
// "downloaded a mod apk, worried it's spyware": the person installed it themself, so it is an
// app they chose, not a spy app someone else planted.
// "what should I do if a phone is stolen, just asking", "is ransomware only for big companies":
// asking ahead of time, not reporting. Unless it names a time ("today", "just now").
const HYPOTHETICAL = /\bjust (?:asking|curious)\b|\bto be prepared\b|^(?:what|how)\b.{0,30}\bif (?:a|my|someone|somebody|your|one'?s|the)\b|^(?:is|are|can|could)\b.{0,40}\b(?:only for|also get|happen to)\b/i;
const HAPPENED_NOW = /\b(?:today|yesterday|just now|right now|last night|this morning|abhi|aaj|kal)\b/i;
// The word-count backup only speaks when the message has at least one word about danger or worry:
// "which is better, samsung or redmi" has none, and word counts alone would still pick a family.
const SECURITY_WORD = /\b(?:hack\w*|virus\w*|malware|spy\w*|fraud\w*|scam\w*|cheat\w*|dhoka|otp|pin|cvv|password\w*|stolen|chori|lost|missing|gum|call\w*|link\w*|apps?|apk|install\w*|download\w*|account\w*|money|paise?|paisa|rs|rupees|bank\w*|upi|paytm|gpay|phonepe|wallet|card|sim|network|signal|screen\w*|remote|anydesk|teamviewer|photos?|videos?|threat\w*|dhamki|blackmail\w*|police|arrest\w*|cbi|files?|locked|lock|pay\w*|messages?|msgs?|sms|texts?|log ?in|login|logged|slow|battery|pop-?ups?|ads?|adverts?|strange|weird|suspicious|unknown|ajeeb|khud|apne aap|worried|scared|darr?|help|madad|problem|galat|gadbad|email|mail|whats ?app|insta\w*|facebook|fb|gmail|telegram|kyc|aadhaar|pan)\b/i;
const ASKING = /^(?:is|are|can|could|should|will|would|do|does|did|what|how|why|which|when|where|who|kya|kaise|kyun|kyu)\b/i;
const SELF_INSTALL =/^(?:i\s+)?(?:just\s+)?(?:downloaded|installed)\b|\b(?:i|maine)\s+(?:just\s+)?(?:downloaded|installed|download kiya|install kiya)\b/i;

// Worried words: a message with one of these that no family and no how-to answer caught still
// gets the "What happened?" menu, never "I don't have a good answer".
const DISTRESS = /\b(?:help|madad|bachao|wrong|galat|problem|issue|trouble|scared|worried|darr|dar lag|panic|mistake|galti|kya karu|kya karun|kya karoon|please guide|am i safe|urgent|asap|bad happened|fraud|scam(?:med)?|hacked?|cheated|dhoka)\b/i;

// "a man called saying my computer has a virus" is a CALL: the virus is his claim, not a sign.
const CALLER_CLAIM = /\b(?:called|calling|phoned|call aaya|on (?:a |the )?call)\b.{0,40}\b(?:saying|said|says|claiming|claimed|told me)\b/i;
// "no money gone", "paisa nahi kata", "didn't lose any money": the person says the money is safe.
const NO_MONEY = /\b(?:no|not any|not a single)\s+(?:money|amount|paisa|paise|rupees?|rs)\b.{0,12}\b(?:gone|lost|deducted|debited|cut|taken|went)\b|\b(?:money|paisa|paise|amount)\b.{0,20}\b(?:not|nahi|nhi|never)\s+(?:gone|lost|deducted|debited|cut|kata|kaata|kati|gaya|gaye|went)\b|\bdid(?:n'?t| not) lose (?:any )?money\b|\babhi tak (?:paisa|paise|kuch) nahi (?:kata|kaata|gaya|gaye)\b/i;

// Shared by detectProblem() and closestFamilies(): null = not something that happened to the
// writer (a what-if, a pasted scam text, a scammer's own words); else whether it is their own story.
function storyOf(t) {
  if (HYPOTHETICAL.test(t) && !HAPPENED_NOW.test(t)) return null;
  if (PASTED.test(t) && !FIRST_PERSON.test(t.replace(new RegExp(PASTED.source, "gi"), ""))) return null;
  if (ADDRESSED.test(t) && SCAMMER_VOICE.test(t) && !RETOLD.test(t)) return null;
  // Real people drop the "I" ("linkedin account hacked", "phone chori ho gaya"). What a pasted
  // scam text has instead is "you": so a message counts as the person's own unless it speaks TO
  // someone and never as "I".
  return { first: FIRST_PERSON.test(t) || !ADDRESSED.test(t) || RETOLD.test(t) };
}

// The first problem family whose pattern (or first-aid entry) fires, else null. Split out of
// detectProblem() on 25 Sep so the question can tell a pattern's answer from a word-count guess.
export function patternFamily(t, first) {
  for (const [fam, re] of PATTERNS) {
    if (fam === "device" && CALLER_CLAIM.test(t)) continue;
    if (re === SPY_PATTERN && SELF_INSTALL.test(t)) continue;
    if (fam === "money" && NO_MONEY.test(t)) continue;
    const aid = FIRST_AID.filter((e) => FIRST_AID_FAMILY[e.id] === fam).some((e) => e.test.test(t));
    // A dead SIM, locked files or a call are never written as a scam message TO someone, so
    // they need no "I" ("sim showing no service since yesterday").
    if (aid || (re.test(t) && (first || fam === "call" || fam === "sim" || fam === "ransom"))) return fam;
  }
  return null;
}

export function detectProblem(text) {
  const t = String(text || "").trim();
  if (!t) return null;
  if (VAGUE.test(t)) return "vague";
  const s = storyOf(t);
  if (!s) return null;
  const first = s.first;
  const fam = patternFamily(t, first);
  if (fam) return fam;
  // No pattern matched: ask the word-count backup (learned from people's own wordings), but only
  // for a message that is the person's own story, never one spoken TO them.
  // Not for questions ("is using mod apk safe", "is it ok to charge at the station"): word counts
  // cannot tell asking about a danger from having met it.
  return first && !ASKING.test(t) && SECURITY_WORD.test(t) ? wordGuess(t) : null;
}

// His tap 25 Sep 20:53: when Vigil is unsure, ask ONE "Which is closest?" question instead of
// guessing. Called only when detectProblem() found nothing. Same gates as the word-count backup
// (the person's own story, not a question, a security word), and the words must lean towards
// "something happened" (ASK_FLOOR of the probability is on problem families, not notproblem).
// Answers the likeliest problem families, best first; "Something else" on the page covers the rest.
export const ASK_FLOOR = 0.5;
export const ASK_COUNT = 4;
export function closestFamilies(text) {
  const t = String(text || "").trim();
  if (!t || VAGUE.test(t)) return null;
  const s = storyOf(t);
  if (!s || !s.first || ASKING.test(t) || !SECURITY_WORD.test(t)) return null;
  const r = wordRank(t);
  if (!r) return null;
  const problems = r.filter((x) => x.fam !== "notproblem" && x.fam !== "vague");
  const mass = r.filter((x) => x.fam !== "notproblem").reduce((s, x) => s + x.p, 0);
  return mass >= ASK_FLOOR ? problems.slice(0, ASK_COUNT).map((x) => x.fam) : null;
}

// A pattern fired, but the word counts are almost sure it is ANOTHER problem: ask instead of
// answering the pattern's family. DOUBT_FLOOR measured 25 Sep on the held halves of blind-1..7
// (350 rows): 0.9 fixed 9 wrong answers and cost 2 right ones a tap; 0.7 fixed 11 but cost 12.
// The pattern's own family stays the first button.
export const DOUBT_FLOOR = 0.9;
// No pattern fired and the word counts answered alone: under this they ask instead (25 Sep).
// Chosen on the tune rows of blind-7..9 (never used to build the word counts): of 20 such
// answers the one wrong was at 0.596, the right ones at 0.627 and up; the known misroute
// "whatsapp pe ajeeb message aaya ... reply kar diya" -> remote was at 0.537.
export const GUESS_SURE = 0.65;
// The button for each family in the "Which is closest?" question (same wording as the menus above).
export const CLOSEST_LABELS = {
  money: "Money went from my account",
  code: "I shared an OTP, PIN or password",
  account: "An account got hacked",
  device: "My phone or laptop acts strange",
  call: "I got a suspicious call or message",
  threat: "Someone is threatening me",
  app: "I installed something doubtful",
  link: "I opened a suspicious link",
  lost: "My phone or laptop is lost or stolen",
  sim: "My SIM suddenly has no network",
  ransom: "My files are locked and someone wants money",
  remote: "Someone had my screen (AnyDesk etc.)",
};
export function doubtFamilies(text, fam) {
  if (!fam || fam === "vague") return null;
  const r = wordRank(String(text || "").trim());
  // No pattern fired, so the family is the word counts' own guess: below GUESS_SURE it is a
  // question, with the guess as the first button.
  if (r && r[0].fam === fam && r[0].p < GUESS_SURE && !patternFamily(String(text).trim(), true)) {
    return [fam, ...r.filter((x) => x.fam !== fam && x.fam !== "notproblem" && x.fam !== "vague").slice(0, ASK_COUNT - 1).map((x) => x.fam)];
  }
  if (!r || r[0].fam === fam || r[0].fam === "notproblem" || r[0].fam === "vague" || r[0].p < DOUBT_FLOOR) return null;
  const rest = r.filter((x) => x.fam !== fam && x.fam !== "notproblem" && x.fam !== "vague");
  return [fam, ...rest.slice(0, ASK_COUNT - 1).map((x) => x.fam)];
}

// Called only after the how-to library found nothing: a worried first-person message still
// gets the menu. (A how-to question like "how do I report a fraud" is answered before this.)
// "how to know if my phone has a virus" is a how-to: when the library has a direct answer, it
// beats the questions. "my phone has a virus" (no how-to opening) still gets the questions.
export const HOW_TO = /^(?:how (?:to|do|can|should|would) |how does |where (?:do|can|should) i |what (?:should|do) i do (?:if|when) |is it (?:safe|ok|okay) )/i;

const ASKS_ABOUT_HELP = /^(?:what|how|which|who|where|can you|could you|will you|do you)\b[^.!]*\bhelp\b/i;
export const isDistress = (text) => DISTRESS.test(ASKS_ABOUT_HELP.test(text) ? String(text).replace(/\bhelp\b/gi, "") : text) && (FIRST_PERSON.test(text) || String(text).trim().split(/\s+/).length <= 6);

// ---------- the questions ----------
const NOT_SURE = { label: "Not sure", set: {} };

export const FAMILIES = {
  vague: { start: "vague.what" },
  money: { start: "money.how", urgent: "If money is leaving your account right now, call 1930 first (India's cyber fraud helpline) - the first hours matter most. Then two quick questions so I can guide you exactly." },
  code: { start: "code.what", urgent: "A shared code can be used within minutes. Two quick questions, then exactly what to lock first." },
  account: { start: "account.which" },
  device: { start: "device.which" },
  link: { start: "link.did" },
  app: { start: "app.from", urgent: "If you're worried it's doing something right now, turn on flight mode / switch Wi-Fi off first. Then a couple of quick questions." },
  remote: { start: "remote.still", urgent: "If they are still connected, switch the internet off right now (flight mode or Wi-Fi off). Then two quick questions." },
  call: { start: "call.asked" },
  lost: { start: "lost.what" },
  sim: { start: "sim.others" },
  threat: { start: "threat.kind", urgent: "You're not in trouble - they are. Don't reply to them for now. A few quick questions so I can guide you." },
  ransom: { start: "ransom.spread", urgent: "Switch Wi-Fi off and unplug any USB or backup drive right now, so they don't get locked too." },
};

const MONEY_WORDS = /\b(?:money|paise?|paisa|rs\.?|₹|rupees|amount|debited|deducted|withdrawn|transaction)\b/i;

export const NODES = {
  "vague.what": {
    ask: "I'm here. What happened? Pick the closest one.",
    noSkip: true,
    options: [
      { label: "Money went from my account", to: "money.how" },
      { label: "I shared an OTP, PIN or password", to: "code.what" },
      { label: "An account got hacked", to: "account.which" },
      { label: "My phone or laptop acts strange", to: "device.which" },
      { label: "I got a suspicious call or message", to: "call.asked" },
      { label: "Someone is threatening me", to: "threat.kind" },
      { label: "I installed something doubtful", to: "app.from" },
      { label: "I opened a suspicious link", to: "link.did" },
      { label: "Something else ›", to: "more.which" },
    ],
  },
  "more.which": {
    ask: "Which of these is closest?",
    noSkip: true,
    options: [
      { label: "My phone is lost or stolen", set: { what: "phone" }, to: "lost.how" },
      { label: "My laptop is lost or stolen", set: { what: "laptop" }, to: "lost.how" },
      { label: "My SIM suddenly has no network", to: "sim.others" },
      { label: "My files are locked and someone wants money", to: "ransom.spread" },
      { label: "Someone had my screen (AnyDesk etc.)", to: "remote.still" },
      { label: "None of these - I'll type it", to: null },
    ],
  },

  "money.how": {
    ask: "How did the money go?",
    options: [
      { label: "I shared an OTP or PIN", set: { how: "otp" }, to: "money.when", hint: /(?<!\b(?:didn'?t|did not|never|no|not|without|nahi)\b[^.,;]{0,25})\b(?:otp|pin|code|cvv)\b(?![^.,;]{0,15}\b(?:nahi|not)\b)/i },
      { label: "I scanned a QR or approved a request", set: { how: "qr" }, to: "money.when", hint: /\b(?:qr|scann?ed|scan kiya|collect request|approved? (?:a |the )?request|request (?:aaya|accept))/i },
      { label: "I paid someone who turned out fake", set: { how: "paid" }, to: "money.when", hint: /\b(?:paid|sent|transferred|bheje|bheja|diye)\b.{0,50}\b(?:seller|olx|job|task|investment|trading|fake|shop|order|delivery|advance|registration|fee)|\bfake (?:seller|shop|website|job|company)|\b(?:part[- ]?time|task|investment|trading) (?:job|app|scam|group)|\bolx\b/i },
      { label: "Someone had my screen (AnyDesk etc.)", set: { how: "remote" }, to: "money.when", hint: /\b(?:anydesk|any desk|teamviewer|quick ?support|rustdesk|airdroid|screen ?shar)/i },
      { label: "It just went - I did nothing", set: { how: "unknown" }, to: "money.when", hint: /\b(?:didn'?t do|did not do|i did nothing|without (?:me|my)|no otp|never shared|nahi kiya|i didn'?t (?:share|give|make|authori))/i },
      { ...NOT_SURE, set: { how: "unsure" }, to: "money.when" },
    ],
  },
  "money.when": {
    ask: "When did it happen?",
    options: [
      { label: "Today", set: { when: 0 }, hint: /\b(?:today|just now|right now|abhi|aaj|minutes? ago|an hour ago|hours? ago|this morning)\b/i },
      { label: "1-3 days ago", set: { when: 3 }, hint: /\b(?:yesterday|kal|(?:2|3|two|three) days)\b/i },
      { label: "4-7 days ago", set: { when: 7 }, hint: /\b(?:[4-7]|four|five|six|seven) days\b|\ba week ago\b/i },
      { label: "More than a week ago", set: { when: 8 }, hint: /\b(?:last month|weeks ago|months? ago|[2-9] weeks)\b/i },
      { ...NOT_SURE },
    ],
  },

  "code.what": {
    ask: "What was the code or password for?",
    options: [
      { label: "Bank, card or UPI", set: { what: "bank" }, to: "code.since", hint: /\b(?:bank|upi|card|atm|cvv|paytm|phone ?pe|g ?pay|google pay|bhim|debit|credit|net ?banking|sbi|hdfc|icici|axis)\b/i },
      { label: "WhatsApp or Telegram", set: { what: "chat" }, to: "code.since", hint: /\b(?:whats ?app|telegram)\b/i },
      { label: "Email, Google, Instagram or Facebook", set: { what: "account" }, to: "code.since", hint: /\b(?:gmail|google|e-?mail|insta|instagram|facebook|fb|microsoft|outlook)\b/i },
      { label: "Aadhaar or a government site", set: { what: "gov" }, to: "code.since", hint: /\b(?:aadh?aa?r|uidai|digilocker|pan card)\b/i },
      { ...NOT_SURE, set: { what: "unsure" }, to: "code.since" },
    ],
  },
  "code.since": {
    ask: "Has anything happened since?",
    options: [
      { label: "Money left my account", set: { how: "otp" }, to: "money.when", hint: MONEY_WORDS },
      { label: "I got logged out of something", set: { since: "out" }, hint: /\blogged out\b|\bcan'?t (?:log|sign) ?in\b|\blocked out\b/i },
      { label: "Nothing yet", set: { since: "none" }, hint: /\bnothing (?:yet|happened)\b|\bnot yet\b/i },
      { ...NOT_SURE, set: { since: "unsure" } },
    ],
  },

  "account.which": {
    ask: "Which account?",
    options: [
      { label: "WhatsApp", set: { which: "whatsapp" }, to: "account.access", hint: /\bwhats ?app\b/i },
      { label: "Instagram", set: { which: "insta" }, to: "account.access", hint: /\binsta(?:gram)?\b/i },
      { label: "Facebook", set: { which: "fb" }, to: "account.access", hint: /\b(?:facebook|fb)\b/i },
      { label: "Gmail or Google", set: { which: "google" }, to: "account.access", hint: /\b(?:gmail|google|youtube)\b/i },
      { label: "Microsoft or Outlook", set: { which: "microsoft" }, to: "account.access", hint: /\b(?:microsoft|outlook|hotmail|live\.com)\b/i },
      { label: "Something else", set: { which: "other" }, to: "account.access", hint: /\b(?:telegram|snapchat|twitter|linkedin|amazon|flipkart|paytm)\b/i },
    ],
  },
  "account.access": {
    ask: "Can you still get into it?",
    options: [
      { label: "Yes, I'm still logged in", set: { access: "in" }, hint: /\bstill (?:logged in|have access|can (?:log|open|use))\b/i },
      { label: "No, I'm locked out", set: { access: "out" }, hint: /\b(?:can'?t|cannot|unable to|not able to)\s+(?:log|sign|get|open)|\blocked out\b|password (?:was |got |has been )?changed|\b(?:not opening|khul nahi)\b|\blogged (?:me )?out\b/i },
      { ...NOT_SURE, set: { access: "unsure" } },
    ],
  },

  "device.which": {
    ask: "Which device are you worried about?",
    options: [
      { label: "This phone", set: { dev: "this" }, to: "device.sign", only: "phone", hint: /\b(?:phone|mobile)\b/i },
      { label: "This laptop", set: { dev: "this" }, to: "device.sign", only: "laptop", hint: /\b(?:laptop|computer|pc|desktop)\b/i },
      { label: "My laptop or computer", set: { dev: "other" }, to: "device.sign", only: "phone", hint: /\b(?:laptop|computer|pc|desktop)\b/i },
      { label: "My phone", set: { dev: "other" }, to: "device.sign", only: "laptop", hint: /\b(?:phone|mobile)\b/i },
    ],
  },
  "device.sign": {
    ask: "What made you think something is wrong?",
    options: [
      { label: "Pop-ups or ads everywhere", set: { sign: "ads" }, hint: /\b(?:pop-?ups?|ads|advertisements?)\b/i },
      { label: "Apps I didn't install", set: { sign: "apps" }, hint: /\bapps?\b.{0,20}\b(?:didn'?t|did not|never)\s+install|\b(?:new|unknown|strange) apps?\b/i },
      { label: "Messages or posts I didn't send", set: { sign: "sent" }, hint: /\b(?:messages?|posts?|mails?|emails?)\b.{0,25}\b(?:didn'?t|did not|never)\s+(?:send|sent|post)/i },
      { label: "OTPs or login alerts I didn't ask for", set: { sign: "otp" }, hint: /\b(?:otps?|codes?|login alerts?)\b.{0,30}\b(?:didn'?t|did not|never|not)\s+(?:ask|request)|\bunknown login\b/i },
      { label: "Slow, hot or battery drains fast", set: { sign: "slow" }, hint: /\b(?:slow|hang|hangs|heat|heating|hot|battery|lag|lagging)\b/i },
      { label: "Someone knows my chats or location", set: { sign: "spy" }, hint: /\b(?:spy|spying|spyware|stalkerware|track|tracking|tracker|watching|stalk|stalking|knows (?:my|where)|reading my|location|mspy|flexispy|thetruthspy|truthspy|spyzie|hoverwatch|cocospy|eyezy|spyic|xnspy)\b/i },
      { ...NOT_SURE, set: { sign: "unsure" } },
    ],
  },

  "link.did": {
    ask: "After the page opened, what did you do there?",
    options: [
      { label: "Nothing - I just opened it", set: { did: "nothing" }, hint: /\b(?:just|only) (?:opened|clicked|tapped)\b|\bdidn'?t (?:type|enter|fill)/i },
      { label: "Typed a password", set: { did: "password" }, hint: /\bpassword\b/i },
      { label: "Typed card, UPI PIN or an OTP", set: { did: "bank" }, hint: /\b(?:card|cvv|upi|pin|otp|bank)\b/i },
      { label: "It downloaded a file or app", set: { did: "download" }, hint: /\b(?:download|downloaded|apk|installed)\b/i },
      { ...NOT_SURE, set: { did: "unsure" } },
    ],
  },

  "app.from": {
    ask: "Where did it come from?",
    options: [
      { label: "A link or a file someone sent", set: { from: "link" }, to: "app.perm", hint: /^(?!.*\b(?:crack\w*|pirated|keygen|torrent\w*|repack|activator|free game|free full)\b).*\b(?:link|sent|whats ?app|sms|message|apk|telegram|friend|website)\b/i },
      { label: "The Play Store / Microsoft Store", set: { from: "store" }, to: "app.perm", hint: /\b(?:play ?store|app store|microsoft store|google play)\b/i },
      { label: "A cracked or 'free' version", set: { from: "cracked" }, to: "app.perm", hint: /\b(?:crack|cracked|mod|modded|patched|pirated|free version|free game|free full|keygen|torrent\w*|repack|activator)\b/i },
      { ...NOT_SURE, set: { from: "unsure" }, to: "app.perm" },
    ],
  },
  "app.perm": {
    ask: "When you opened it, did it ask you to allow anything special?",
    options: [
      { label: "Read SMS or notifications", set: { perm: "sms" }, only: "phone", hint: /\b(?:sms|messages|notification)\b/i },
      { label: "Accessibility, or 'install unknown apps'", set: { perm: "access" }, only: "phone", hint: /\baccessibility\b|\bunknown apps\b/i },
      { label: "Admin / 'allow changes to this device'", set: { perm: "admin" }, only: "laptop", hint: /\badmin|allow changes\b/i },
      { label: "It asked for bank or card details", set: { perm: "bank" }, hint: /\b(?:bank|card|upi|account number)\b/i },
      { label: "Nothing special / don't remember", set: { perm: "none" } },
    ],
  },

  "remote.still": {
    ask: "Is the screen-sharing app still on your device?",
    options: [
      { label: "Yes, still installed", set: { still: true } },
      { label: "I already removed it", set: { still: false }, hint: /\b(?:removed|uninstalled|deleted)\b/i },
      { ...NOT_SURE, set: { still: true } },
    ],
    next: "remote.saw",
  },
  "remote.saw": {
    ask: "While they were connected, did you open a bank or UPI app, or did an OTP arrive?",
    options: [
      { label: "Yes", set: { saw: true }, hint: /\b(?:bank|upi|otp|paytm|phone ?pe|g ?pay|refund)\b/i },
      { label: "No", set: { saw: false } },
      { ...NOT_SURE, set: { saw: true } },
    ],
  },

  "call.asked": {
    ask: "What did they want from you?",
    options: [
      { label: "An OTP, PIN or password", set: { asked: "code" }, to: "call.did", hint: /\b(?:otp|pin|code|password|cvv)\b/i },
      { label: "To install an app or open a link", set: { asked: "app" }, to: "call.did", hint: /\b(?:install|download|anydesk|apk|app|link|teamviewer)\b/i },
      { label: "To pay a fine, fee or 'clear your name'", set: { asked: "pay" }, to: "call.did", hint: /\b(?:pay|fine|fee|arrest|police|cbi|customs|narcotics|parcel|courier|drugs|case|money|send)\b/i },
      { label: "Personal details (Aadhaar, bank, KYC)", set: { asked: "details" }, to: "call.did", hint: /\b(?:aadh?aa?r|pan|kyc|details|account number|date of birth)\b/i },
      { ...NOT_SURE, set: { asked: "unsure" }, to: "call.did" },
    ],
  },
  "call.did": {
    ask: "Did you do what they asked?",
    options: [
      { label: "Yes", set: { did: "yes" }, hint: /\b(?:i (?:gave|told|shared|paid|installed|sent|did)|i (?:have |had )?(?:given|told|shared|paid|installed|sent))\b/i },
      { label: "No - I stopped", set: { did: "no" }, hint: /\b(?:didn'?t|did not|refused|cut the call|hung up|disconnected|ignored)\b/i },
      { label: "Partly", set: { did: "partly" } },
    ],
  },

  "lost.what": {
    ask: "Is it a phone or a laptop?",
    options: [
      { label: "A phone", set: { what: "phone" }, hint: /\b(?:phone|mobile|smartphone)\b/i },
      { label: "A laptop", set: { what: "laptop" }, hint: /\b(?:laptop|computer|macbook)\b/i },
    ],
    next: "lost.how",
  },
  "lost.how": {
    ask: "Lost, or stolen?",
    options: [
      { label: "Lost - it may still be somewhere", set: { how: "lost" }, hint: /\b(?:lost|misplaced|left it|forgot|kho)\b/i },
      { label: "Stolen or snatched", set: { how: "stolen" }, hint: /\b(?:stolen|stole|snatch|snatched|theft|thief|pickpocket|chori)\b/i },
      { ...NOT_SURE, set: { how: "unsure" } },
    ],
    next: "lost.lock",
  },
  "lost.lock": {
    ask: "Did it have a screen lock (PIN, pattern or fingerprint)?",
    options: [
      { label: "Yes, it was locked", set: { lock: true } },
      { label: "No screen lock", set: { lock: false }, hint: /\bno (?:screen )?lock\b|\bwasn'?t locked\b|\bno password\b/i },
      { ...NOT_SURE, set: { lock: false } },
    ],
  },

  "sim.others": {
    ask: "Do other people near you, on the same network, have signal?",
    options: [
      { label: "Yes - only mine is dead", set: { others: "fine" } },
      { label: "No - everyone's network is down", set: { others: "down" } },
      { ...NOT_SURE, set: { others: "unsure" } },
    ],
    next: "sim.otp",
  },
  "sim.otp": {
    ask: "Just before it stopped, did you get OTPs, calls or messages you didn't expect?",
    options: [
      { label: "Yes", set: { otp: true }, hint: /\b(?:otps?|codes?)\b.{0,30}\b(?:didn'?t|not|never)\b|\bstrange (?:calls?|messages?)\b/i },
      { label: "No", set: { otp: false } },
      { ...NOT_SURE, set: { otp: true } },
    ],
  },

  "threat.kind": {
    ask: "What are they threatening you with?",
    options: [
      { label: "Sharing real photos or videos of me", set: { kind: "real" }, to: "threat.paid", hint: /\b(?:video call|recorded|my (?:photos?|pics?|pictures?|videos?)|nude|private|intimate)\b/i },
      { label: "An email saying they 'recorded me' (no proof)", set: { kind: "bluff" }, to: "threat.paid", hint: /\b(?:email|mail)\b.{0,60}\b(?:webcam|camera|recorded|bitcoin|hacked your)\b/i },
      { label: "Fake or edited pictures of me", set: { kind: "morphed" }, to: "threat.paid", hint: /\b(?:morph|morphed|edited|fake (?:photos?|pics?|pictures?)|deepfake)\b/i },
      { label: "A loan app or recovery agents", set: { kind: "loan" }, to: "threat.paid", hint: /\bloan\b/i },
      { label: "Something else", set: { kind: "other" }, to: "threat.paid" },
    ],
  },
  "threat.paid": {
    ask: "Have you paid them anything so far?",
    options: [
      { label: "Yes", set: { paid: true }, hint: /\b(?:i (?:have |already )?paid|i sent (?:them|him|her) money|paid them)\b/i },
      { label: "No", set: { paid: false }, hint: /\b(?:haven'?t paid|not paid|didn'?t pay|did not pay)\b/i },
    ],
  },

  "ransom.spread": {
    ask: "Is anything else connected - a USB or backup drive, or other computers on the same Wi-Fi?",
    options: [
      { label: "Yes", set: { spread: true } },
      { label: "No", set: { spread: false } },
      { ...NOT_SURE, set: { spread: true } },
    ],
  },
};

// Family a node belongs to (its leaf answers when the questions end there)
export const familyOf = (nodeId) => nodeId.split(".")[0];

// Options this device should see
export const optionsFor = (node, phone) => node.options.filter((o) => !o.only || o.only === (phone ? "phone" : "laptop"));

// If the message already answers this question, pick that option without asking. Only when
// exactly ONE option matches - two matches means the message is ambiguous, so ask.
export function autoPick(node, text, phone) {
  const hits = optionsFor(node, phone).filter((o) => o.hint && o.hint.test(text));
  return hits.length === 1 ? hits[0] : null;
}

// Where an option leads: its own `to`, else the node's `next`, else answer now
export const nextOf = (node, opt) => opt.to || node.next || null;

// ---------- the answers ----------
const RBI = (when) => when === undefined ? "Tell your bank in writing (email, or the complaint form in its app) as soon as you can: under RBI rules, if neither you nor the bank caused it, reporting within 3 working days means you lose nothing."
  : when <= 3 ? "Tell your bank in writing today (email, or the complaint form in its app). Under RBI rules, if neither you nor the bank caused it, reporting within 3 working days means you lose nothing."
    : when <= 7 ? "Tell your bank in writing today. You're in the 4-7 working-day window: under RBI rules your loss is capped (₹5,000 to ₹25,000 depending on the account), if neither side caused it."
      : "Tell your bank in writing anyway. After 7 working days the bank's own board-approved policy decides - but without a written complaint nothing can happen.";

const BANK_BLOCK = "Call your bank on the number printed on your card or passbook (never one from Google search) and block the card / UPI. Ask for a complaint number and write it down.";
const EVIDENCE = "Keep proof: screenshots of the messages and the payment, the transaction ID, and the number or UPI ID of the other person.";
const P = (phone, onPhone, onLaptop) => (phone ? onPhone : onLaptop);

const LEAVES = {
  vague: () => ({
    typeIt: true,
    title: "Tell me in your own words",
    say: "Write what happened in one or two sentences - for example 'money was deducted from my account' or 'my Instagram got hacked' - and I'll guide you step by step.",
    steps: [],
  }),

  money: (c) => {
    const s = [];
    const when = c.when;
    s.push(when === 8
      ? "Call 1930 (India's cyber fraud helpline) or report at cybercrime.gov.in - even late, a report starts the case and lets police trace the accounts the money went to."
      : "Call 1930 now (India's cyber fraud helpline). They can ask the banks to hold the money while it is still moving between accounts.");
    s.push(BANK_BLOCK);
    if (c.how === "otp") {
      s.push("Because the OTP was shared, the bank may treat it as partly your side - so don't wait on the bank: 1930 is the fastest way to stop the money.");
      s.push("Change the PIN or password that code protected - from the real app, never from a link.");
    } else if (c.how === "qr") {
      s.push("Remember for next time: scanning a QR code or approving a 'collect' request only ever SENDS money. To RECEIVE money you never scan anything or enter your PIN.");
    } else if (c.how === "paid") {
      s.push("Because you made the payment yourself, the bank's 'unauthorised transaction' refund rules usually don't cover it. 1930 and a cybercrime.gov.in complaint are your real chance - fast, while the money is still moving.");
      s.push("Report the seller's profile or ad on that website or app too, so it's taken down.");
    } else if (c.how === "remote") {
      s.push("Uninstall the screen-sharing app (AnyDesk, TeamViewer, QuickSupport...). Then change your banking and email passwords - they may have seen them.");
    } else {
      s.push(RBI(when));
      if (c.how === "unknown") s.push("If you really shared nothing, also check this device: an app reading your SMS could have taken the OTP without you seeing it.");
    }
    s.push(EVIDENCE);
    return {
      title: { otp: "Money lost after sharing a code", qr: "Money lost through a QR or payment request", paid: "Money paid to a fake seller or scheme", remote: "Money lost during a screen-sharing call" }[c.how] || "Money left your account without you",
      say: when === 0 ? "It happened today - that's the best time to act. Do these in order, starting now." : "Do these in order. It's not too late to report.",
      steps: s,
      links: [REPORT],
      go: c.how === "unknown" || c.how === "remote" || c.how === "unsure" ? ["hacked", "apps"] : ["payment"],
      danger: true,
    };
  },

  code: (c0, phone) => {
    const c = { what: "unsure", ...c0 };
    const s = [];
    if (c.what === "bank" || c.what === "unsure") {
      s.push(BANK_BLOCK);
      s.push("Change your UPI PIN and netbanking password from the bank's own app.");
      s.push("Watch your account for the next 2 days. If any payment isn't yours: 1930 and cybercrime.gov.in at once.");
    }
    if (c.what === "chat") {
      s.push(c.since === "out"
        ? "Open WhatsApp / Telegram and verify your own phone number again with the SMS code - the person using your account gets logged out when you do."
        : "Open WhatsApp / Telegram now. If it still works, the code may not have been used yet.");
      s.push("Turn on two-step verification (a PIN of your own) in the app's Account settings - then a stolen SMS code alone is not enough next time.");
      s.push("Tell your contacts: any message 'from you' asking for money or codes is not from you.");
    }
    if (c.what === "account") {
      s.push(c.since === "out"
        ? "Use the service's official recovery page (buttons below) - never someone who offers to 'recover' it for money."
        : "Change that account's password now, from the real app or website.");
      s.push("Then turn on two-step verification and sign out of every other device from the account's security settings.");
    }
    if (c.what === "gov") {
      s.push("An Aadhaar OTP can let someone use your Aadhaar for verification. Lock your biometrics on the myAadhaar portal or the mAadhaar app (Lock/Unlock Biometrics).");
      s.push("Check that no SIM or account was opened in your name: Sanchar Saathi shows every mobile number registered with your ID.");
    }
    if (c.what === "unsure") s.push("If it was for WhatsApp, Instagram, email or another app: open that app now and change its password / turn on two-step verification.");
    if (c.since === "none") s.push("Nothing has happened yet - good. Doing the steps above now usually stops it.");
    s.push("Remember: no real bank, company or police officer ever asks for an OTP. Whoever asked was the scammer.");
    const links = c.what === "account" ? [RECOVERY.google, RECOVERY.insta, RECOVERY.fb, RECOVERY.microsoft]
      : c.what === "gov" ? [{ label: "myAadhaar", url: "https://myaadhaar.uidai.gov.in" }, { label: "Sanchar Saathi", url: "https://sancharsaathi.gov.in" }]
        : [REPORT];
    return {
      title: { bank: "You shared a bank or UPI code", chat: "You shared a WhatsApp / Telegram code", account: "You shared an account code or password", gov: "You shared an Aadhaar OTP" }[c.what] || "You shared a code",
      say: "Lock the thing the code opens, first - before anything else.",
      steps: s,
      links,
      go: c.what === "bank" ? ["hacked"] : ["accounts"],
      danger: true,
    };
  },

  account: (c) => {
    const s = [];
    const name = { whatsapp: "WhatsApp", insta: "Instagram", fb: "Facebook", google: "Google", microsoft: "Microsoft" }[c.which] || "that account";
    if (c.access === "in") {
      s.push(`Change the ${name} password now, from the real app or website.`);
      s.push("In its security settings, sign out of every device you don't recognise, and check the recovery phone number and email are still yours (hackers change them).");
      s.push("Turn on two-step verification.");
    } else if (c.which === "whatsapp") {
      s.push("Open WhatsApp and register your own number again with the SMS code - the person using it gets logged out.");
      s.push("If WhatsApp then asks for a two-step PIN you never set, the hacker set it. Follow what WhatsApp shows on screen - never pay anyone who offers to 'unlock' it.");
      s.push("Once back in: set your own two-step verification PIN in Account settings.");
    } else {
      s.push(`Go to ${name}'s official recovery page (button below) and follow it. It usually asks for your old password, phone number or email - use whatever you still have.`);
      s.push("Never use a 'recovery expert' who messages you - they are the second scam after a hack.");
      s.push("Once back in: change the password, turn on two-step verification, and sign out of every other device.");
    }
    s.push("Tell your friends and family now: messages 'from you' asking for money or codes are not from you.");
    s.push("If you used the same password anywhere else, change it there too.");
    const link = { insta: [RECOVERY.insta], fb: [RECOVERY.fb], google: [RECOVERY.google], microsoft: [RECOVERY.microsoft] }[c.which]
      || (c.which === "whatsapp" ? [] : [RECOVERY.google, RECOVERY.insta, RECOVERY.fb, RECOVERY.microsoft]);
    return {
      title: `${name === "that account" ? "An account" : name} was taken over`,
      say: c.access === "in" ? "You're still inside - that's the best case. Lock them out now, before they lock you out." : "Most accounts can be recovered through the service's own recovery page, if you start soon.",
      steps: s,
      links: link,
      go: ["password", "accounts"],
      danger: true,
    };
  },

  device: (c, phone) => {
    const here = c.dev !== "other";
    const on = here ? (phone ? "this phone" : "this laptop") : (phone ? "your laptop" : "your phone");
    const devPhone = here ? phone : !phone;
    const s = [];
    const go = ["hacked"];
    let title = `Checking ${on}`;
    let say = "Let's look at the real signs instead of guessing.";
    switch (c.sign) {
      case "ads":
        title = `Pop-ups and ads on ${on}`;
        say = "Pop-ups are almost always adware or a website that you once allowed to send notifications - annoying, usually not a hacker inside.";
        if (devPhone) {
          // Paths checked against Chrome Help (Android tab, answer 3220216), 24 Sep 2026.
          s.push("Stop the site's notifications: open that site in Chrome, tap the icon to the left of the address bar → Permissions → switch Notifications off. To stop every site at once: Chrome ⋮ → Settings → Site settings → Notifications → turn it off.");
          s.push("Uninstall apps you added just before the ads began - especially cleaners, battery savers, free VPNs, wallpaper, flashlight and 'booster' apps.");
          s.push("If ads cover the whole screen even outside apps, go through your apps list: the one with the odd name or no icon is usually it.");
          go.push("apps");
        } else {
          s.push("In your browser, block sites you don't know from sending notifications (Chrome: Settings → Privacy and security → Site settings → Notifications).");
          s.push("Remove browser add-ons you didn't add on purpose - I can list them.");
          s.push("Uninstall programs installed around the time the ads started (Settings → Apps → Installed apps, sort by date).");
        }
        break;
      case "apps":
        title = `Apps you didn't install, on ${on}`;
        say = "Apps that appear by themselves are a real warning sign - usually brought in by another app or a file you opened.";
        s.push(devPhone ? "Uninstall each one you don't recognise (Settings → Apps). If Uninstall is greyed out, it made itself a device admin: switch that off in Settings (search 'device admin'), then uninstall." : "Uninstall each one you don't recognise (Settings → Apps → Installed apps, sort by install date).");
        s.push("Think back: what did you install or open just before they appeared? Remove that too.");
        s.push("Change your email password from a device you trust.");
        go.push("apps");
        break;
      case "sent":
        title = "Messages you didn't send";
        say = "That usually means an ACCOUNT was taken over (WhatsApp, Instagram, email) - not the whole device.";
        s.push("Change the password of the account that sent them, and sign out of every other device from its security settings.");
        s.push("WhatsApp: check Linked devices in its settings and log out any computer you don't recognise.");
        s.push("Turn on two-step verification.");
        s.push("Tell the people who got the messages that they were not from you.");
        go.push("accounts");
        break;
      case "otp":
        title = "Codes or login alerts you didn't ask for";
        say = "Someone knows your number or email and is TRYING to get in. That's not proof your device is hacked - and they can't get in without the code.";
        s.push("Never share those codes, whoever calls asking for them.");
        s.push("Change the password of that account and turn on two-step verification.");
        s.push("If the codes are from your bank: call the bank on the number on your card and tell them.");
        go.push("password");
        break;
      case "slow":
        title = `${on[0].toUpperCase() + on.slice(1)} is slow, hot or draining battery`;
        say = "On its own, that's almost never a hack - usually age, low storage, or one heavy app. But let's rule it out.";
        s.push(devPhone ? "Settings → Battery: see which app uses the most. An app you don't recognise at the top is worth removing." : "Open Task Manager (Ctrl+Shift+Esc) and sort by CPU: note anything you don't recognise using a lot.");
        s.push(devPhone ? "Free up storage below 85% full and restart the phone." : "Restart, and install pending Windows updates.");
        s.push(`Then let me check ${here ? "it" : "that device"} for the real signs.`);
        go.push(devPhone ? "apps" : "checkup");
        break;
      case "spy":
        title = "Someone may be watching your chats or location";
        say = "Spying usually needs someone who had your phone in their hand, or your account password - most often someone close to you.";
        s.push("Safety first: if it may be someone close and you feel unsafe, removing a spy app or changing passwords can alert them. Get help before you change anything - call 181 (women helpline) or 112 from a phone they cannot see.");
        s.push("Check your Google account's devices and your location sharing (Google Maps → your picture → Location sharing → tap anyone you don't want to share with → Stop).");
        s.push("WhatsApp: check Linked devices and log out anything you don't know.");
        s.push("On the phone, look for apps with special access: Accessibility, Device admin and Notification access (search those words in Settings). A spy app hides its icon but shows up there.");
        s.push("Change your phone's screen lock and your Google password.");
        if (here && devPhone) go.push("hacked");
        go.push("apps");
        break;
      default:
        s.push("Real signs are: apps you didn't install, settings you didn't change, messages you didn't send, codes you didn't ask for.");
        s.push("Slow, hot or battery-hungry on its own is usually NOT a hack.");
        s.push("Change your email password first, from a device you trust - email is the key to everything else.");
    }
    if (!here) s.push(`Install Virus Vigil on ${on} too, so I can check it directly.`);
    return { title, say, steps: s, go: here ? go : ["accounts"], links: [] };
  },

  link: (c) => {
    const s = [];
    let title = "You opened a suspicious link";
    let say = "Just opening a page rarely harms a phone or laptop by itself. What matters is what you did there.";
    let danger = false;
    if (c.did === "nothing") {
      say = "Just opening a page almost never harms a device by itself. You're most likely fine.";
      s.push("Close the page and delete the message it came from.");
      s.push("If it asked you to allow notifications and you tapped Allow, remove it in your browser's notification settings.");
    } else if (c.did === "password") {
      title = "You typed a password into a doubtful page"; danger = true;
      s.push("Change that password now - from the real app or website, not from that page.");
      s.push("If you use the same password anywhere else, change it there too, starting with email.");
      s.push("Turn on two-step verification for that account.");
    } else if (c.did === "bank") {
      title = "You typed bank details into a doubtful page"; danger = true;
      s.push(BANK_BLOCK);
      s.push("Check your last transactions. If anything isn't yours: 1930 and cybercrime.gov.in straight away.");
    } else if (c.did === "download") {
      title = "A doubtful page downloaded something"; danger = true;
      s.push("Don't open the file. Delete it from Downloads.");
      s.push("If you already opened or installed it: tell me 'I installed an app' and I'll walk you through removing it.");
    } else {
      s.push("Did you type a password there? Change it from the real app. Card, UPI PIN or OTP? Block it with your bank.");
      s.push("Did it download something? Delete it without opening it.");
      s.push("Nothing typed, nothing installed? You're most likely fine.");
    }
    return { title, say, steps: s, go: ["checkup"], links: c.did === "bank" ? [REPORT] : [], danger };
  },

  app: (c, phone) => {
    const s = [];
    s.push(phone ? "Turn on flight mode for a minute so it can't send anything while you work." : "Switch Wi-Fi off so it can't send anything while you work.");
    s.push(phone
      ? "Settings → Apps → find it → Uninstall. If Uninstall is greyed out, it made itself a device admin: search 'device admin' in Settings, switch it off, then uninstall."
      : "Settings → Apps → Installed apps → find it → Uninstall. Then run a full Windows Security scan.");
    if (c.perm === "sms") s.push("It could read your SMS - including bank OTPs. Call your bank on the number on your card and ask them to watch for / block payments.");
    if (c.perm === "access") s.push("Accessibility lets an app read your screen and tap for you - including passwords as you type them. Change your banking and email passwords from ANOTHER device.");
    if (c.perm === "admin") s.push("It got administrator rights, so it may have changed deeper settings. After uninstalling, let me check what starts by itself.");
    if (c.perm === "bank") s.push(BANK_BLOCK);
    const cracked = c.from === "cracked";
    if (cracked && !phone) {
      s.push("Treat it as a password stealer - free and cracked game installers are the commonest way they arrive, and they copy your saved passwords and 'stay signed in' tickets within seconds. From your PHONE, not this laptop: sign out of every device on your email, bank, WhatsApp and Telegram, then change those passwords (tap 'After a password stealer' below for the full order).");
      s.push("Run a Defender offline scan (More checks → Scan with Windows Defender → Offline scan), then a second opinion scan (below).");
    } else if (cracked) {
      s.push("Cracked and 'mod' apps are the commonest way password stealers arrive. From another device, sign out of every device on your email and bank, then change those passwords (tap 'After a password stealer' below).");
    }
    if (c.from === "store") s.push("Store apps are checked, but not perfectly. If it asked for more than it needs (a torch app wanting SMS), it's a bad sign.");
    s.push(phone ? "Then let me check this phone's apps for what such apps leave behind." : "Then let me check what starts by itself on this laptop.");
    return {
      title: "Removing an app you doubt",
      say: "Take it off first, then check what it could have touched.",
      steps: s,
      go: cracked ? ["stealer", "second", "hacked"] : ["apps", "hacked"],
      links: [],
      danger: cracked || c.perm === "sms" || c.perm === "access" || c.perm === "bank",
    };
  },

  remote: (c, phone) => {
    const s = ["Keep the internet off until the app is gone."];
    if (c.still) s.push("Uninstall the screen-sharing app now (AnyDesk, TeamViewer, QuickSupport, RustDesk, AirDroid...).");
    if (c.saw) {
      s.push(BANK_BLOCK);
      s.push("Check your transactions. If money is gone: 1930 and cybercrime.gov.in at once.");
    }
    s.push("Change passwords they could have seen - email first, then banking and social apps. Do it from another device if you can.");
    s.push(phone ? "Check this phone for other apps they may have made you install." : "Check this laptop for programs they may have left to start by themselves.");
    s.push("Real banks, telecom and 'refund' teams never ask you to install a screen-sharing app. That request is the scam.");
    return { title: "Someone had remote access to your screen", say: "Screen-sharing shows the other person everything, including OTPs as they arrive. Cut them off first.", steps: s, links: [REPORT], go: ["apps", "hacked"], danger: true };
  },

  call: (c, phone) => {
    if (c.did === "yes" || c.did === "partly") {
      const map = { code: ["code", { what: "unsure", since: "unsure" }], app: ["app", { from: "link", perm: "none" }], pay: ["money", { how: "paid" }], details: null, unsure: null };
      const m = map[c.asked];
      if (m) return LEAVES[m[0]](m[1], phone);
      return {
        title: "You gave details to a caller",
        say: "Details alone (name, Aadhaar number, date of birth) can't empty an account, but they make the NEXT scam call sound real.",
        steps: [
          "Expect follow-up calls that 'know' your details - that's how they win trust. Still never share an OTP or PIN.",
          "If you gave card or bank details: " + BANK_BLOCK,
          "If you gave Aadhaar details: lock your biometrics on the myAadhaar portal or the mAadhaar app.",
          "Report the number on Sanchar Saathi (Chakshu).",
        ],
        links: [CHAKSHU, { label: "myAadhaar", url: "https://myaadhaar.uidai.gov.in" }],
        go: ["accounts"],
        danger: true,
      };
    }
    const why = {
      code: "No bank, company or police officer ever needs your OTP or PIN. Asking for one is the scam, every time.",
      app: "Callers who ask you to install an app or open a link want control of your phone or your details.",
      pay: "Police, CBI, customs or courier companies never demand money on a call or video call to 'clear your name' or release a parcel. That's the 'digital arrest' / parcel scam.",
      details: "A real bank or company already has your details - they don't call to collect them. That call was fishing.",
      unsure: "Pressure, hurry, fear, or a prize - any of those on an unexpected call is the warning sign.",
    }[c.asked] || "";
    return {
      title: "A suspicious call or message",
      say: `You did the right thing by stopping. ${why}`,
      steps: [
        "Block the number.",
        "Report it on Sanchar Saathi → Chakshu, so the number can be cut off.",
        "If they call again, don't argue - just hang up. You don't owe them anything.",
        "If you're not sure it was fake: call the company or bank yourself, on the number from its own app or the back of your card.",
      ],
      links: [CHAKSHU],
      go: [],
      danger: false,
    };
  },

  lost: (c) => {
    const s = [];
    if (c.what === "laptop") {
      s.push("From another device, change your email password first - email resets every other account - then the passwords your browsers had saved.");
      s.push("Sign it out of everything: in your Google / Microsoft account's security settings choose sign out of other devices, and on your phone check WhatsApp's Linked devices.");
      s.push("If you used netbanking on it: change that password too, and ask the bank to watch your account.");
      s.push(c.how === "lost" ? "If it doesn't turn up within a day: file a police complaint with the laptop's serial number (it's on the bill or the box)." : "File a police complaint with the laptop's serial number (it's on the bill or the box).");
      s.push("If it had office or college data, tell their IT team today.");
      return {
        title: c.how === "stolen" ? "Your laptop was stolen" : "Your laptop is lost",
        say: "The laptop can be replaced; what matters is the accounts that are still signed in on it. Cut those off first.",
        steps: s, links: [], go: ["accounts", "password"], danger: c.lock === false,
      };
    }
    if (c.lock === false) {
      s.push("With no screen lock, whoever has it can open your apps. Call your bank FIRST and block UPI and cards on that number.");
    }
    if (c.how === "lost") s.push("Call it from another phone - someone may answer. Find My Device can also make it ring, even on silent.");
    s.push("From another device, open Find My Device (google.com/android/find): see where it is, lock it, or erase it if it's gone for good.");
    s.push("Call your mobile operator to block the SIM, and get a new SIM on the same number.");
    if (c.lock !== false) s.push("Call your bank to block UPI on that number.");
    if (c.how !== "lost") s.push("File a police complaint, then block the phone's IMEI on Sanchar Saathi (CEIR) using the complaint number - a blocked phone can't be used on any network in India.");
    else s.push("If it doesn't turn up within a day: file a police complaint and block the IMEI on Sanchar Saathi (CEIR).");
    s.push("Change your Google / email password, and log WhatsApp in on your new phone - that logs the old one out.");
    return {
      title: c.how === "stolen" ? "Your phone was stolen" : "Your phone is lost",
      say: c.lock === false ? "No screen lock makes speed matter: money first, then everything else." : "Two jobs: stop it being used against you, then block it.",
      steps: s,
      links: [{ label: "Find My Device", url: "https://www.google.com/android/find" }, { label: "Sanchar Saathi (CEIR)", url: "https://sancharsaathi.gov.in" }],
      go: ["accounts"],
      danger: c.lock === false,
    };
  },

  sim: (c) => {
    if (c.others === "down" && !c.otp) {
      return {
        title: "Probably just the network",
        say: "If everyone around you has no signal too, it's a network outage, not your SIM.",
        steps: ["Wait a few hours. Restart the phone once.", "If you're the ONLY one still without network after that, call your operator from another phone and ask whether a new SIM was issued on your number."],
        links: [], go: [],
      };
    }
    const s = [
      "From another phone, call your operator's customer care now and ask: 'Was a new SIM issued on my number today?'",
      "If yes - or they aren't sure - ask them to block it at once.",
      "Call your bank and block UPI and netbanking until your SIM works again.",
      "Watch your bank and email for the next day. Change your email password from a trusted device.",
    ];
    return {
      title: c.otp ? "Your SIM stopped after strange OTPs - possible SIM swap" : "Your SIM suddenly stopped working",
      say: c.otp ? "Unexpected OTPs followed by 'no network' is the classic sign of a SIM swap: a criminal got a copy of your SIM to receive your OTPs. Act now." : "Sometimes it's just the SIM or network. But when only your phone loses signal out of the blue, rule out a SIM swap.",
      steps: s, links: [], go: ["accounts"], danger: !!c.otp,
    };
  },

  threat: (c) => {
    const s = [];
    let say = "Blackmailers want you scared and alone. Paying almost never makes them stop - it tells them you'll pay again.";
    let title = "Someone is threatening you";
    if (c.kind === "bluff") {
      title = "A 'we recorded you' email";
      say = "These emails go out to millions of people with the same text. If they show no real photo or video of you, they have nothing - the 'password' they quote usually comes from an old data leak.";
      s.push("Don't reply and don't pay. Delete it or mark it as spam.");
      s.push("If it shows a real old password of yours, change that password everywhere you used it.");
    } else if (c.kind === "loan") {
      title = "A loan app is harassing you";
      say = "Illegal loan apps copy your contacts and photos and use shame to squeeze money. It's a crime, and you can report it.";
      s.push("Don't pay extra 'fees' or 'penalties'. Keep proof of what you actually borrowed and repaid.");
      s.push("Uninstall the app. Warn your contacts that fake or edited messages may reach them.");
      s.push("Report at cybercrime.gov.in or call 1930. Check whether the lender is registered with the RBI before paying anything more.");
    } else {
      if (c.kind === "morphed") say = "Edited or fake pictures are a crime to make and to share - the shame belongs to them, not to you.";
      s.push("Stop replying. Don't argue, don't beg, don't pay.");
      s.push("Keep evidence first: screenshots of the chats, their profile link, phone numbers and any payment IDs.");
      s.push("Then block and report the account on that app.");
      s.push("Report at cybercrime.gov.in (it has a section for women and children) or call 1930.");
      s.push("Tell one person you trust. If you're under 18, tell a parent or teacher - you won't be in trouble.");
    }
    if (c.paid) s.push("You've paid once - they will ask again. Don't pay more, and give the payment ID to 1930 / cybercrime.gov.in.");
    return { title, say, steps: s, links: c.kind === "bluff" ? [] : [REPORT], go: c.kind === "bluff" ? ["password"] : [], danger: c.kind !== "bluff" };
  },

  ransom: (c) => {
    const s = [];
    if (c.spread) s.push("Unplug every USB and backup drive now, and switch Wi-Fi off on the other computers until you know what happened.");
    s.push("Don't pay - payment often doesn't bring the files back, and marks you as someone who pays.");
    s.push("Don't delete the ransom note - it names the ransomware type.");
    s.push("From another device, check nomoreransom.org: for some types there's a free unlock tool.");
    s.push("Report at cybercrime.gov.in.");
    return { title: "Your files are locked and someone wants money", say: "That's ransomware. Stop it spreading first.", steps: s, links: [{ label: "No More Ransom", url: "https://www.nomoreransom.org" }, REPORT], go: [], danger: true };
  },
};

export function leafFor(family, ctx, phone) {
  const f = LEAVES[family] || LEAVES.vague;
  const r = f(ctx || {}, !!phone);
  return { links: [], go: [], danger: false, ...r };
}
