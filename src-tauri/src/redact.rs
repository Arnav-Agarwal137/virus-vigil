//! Strip personal details from a typed question BEFORE it may go to an online AI.
//! His rule (RULES.md, 24 Sep 19:45): only what is needed for the reply leaves the device -
//! no numbers, no personal things. So this removes phone / card / account / Aadhaar numbers,
//! OTP-like codes, e-mails, UPI ids, links, PAN / IFSC codes, passwords written out, and
//! names after "my name is / I am / this is / Mr ..." - and says which kinds it removed.
//! Amounts with a currency word ("Rs 5000", "5000 rupees") stay: the advice depends on them.
//! What this CANNOT catch (a name typed in lower case, an address) is why the page shows the
//! exact text and asks before sending. Pure function; tests in tests.rs.

use regex::Regex;
use std::sync::OnceLock;

pub struct Redacted {
    pub text: String,
    /// Kinds removed, in a fixed order, each once: "link", "email", "upi id", ...
    pub removed: Vec<&'static str>,
}

struct Rule {
    kind: &'static str,
    re: Regex,
    /// Replacement; "$1" etc. keep the words around the removed part.
    with: &'static str,
}

fn rules() -> &'static [Rule] {
    static R: OnceLock<Vec<Rule>> = OnceLock::new();
    R.get_or_init(|| {
        let r = |kind, pat: &str, with| Rule { kind, re: Regex::new(pat).expect("redact pattern"), with };
        vec![
            // Order matters: links and e-mails before UPI ids and numbers (they contain both).
            r("link", r"(?i)\b(?:https?://|www\.)\S+", "[link]"),
            r("email", r"(?i)\b[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b", "[email]"),
            r("upi id", r"(?i)\b[a-z0-9._-]{2,}@[a-z]{2,}\b", "[upi id]"),
            r("link", r"(?i)\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|in|net|org|co|io|ly|me|xyz|top|info|app|link|site|online|live|shop|club|biz|tk|ml|ga|cf|gq|cc|ru|cn)\b(?:/\S*)?", "[link]"),
            // A password / PIN / OTP written out: keep the word, drop the value.
            r("password", r"(?i)\b((?:password|passcode|passwd|pwd|m-?pin|upi pin|pin|otp|cvv)\s*(?:is|was|=|:|-)\s*)\S+", "$1[hidden]"),
            r("id number", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", "[id]"),
            r("id number", r"\b[A-Z]{4}0[A-Z0-9]{6}\b", "[id]"),
            // Phone, card, account, Aadhaar: 9+ digits, spaces/dashes/brackets allowed between.
            r("number", r"\+?\d(?:[\s().-]{0,2}\d){8,}", "[number]"),
            // Amounts are kept: shield them, then remove every other 4-8 digit code.
            r("code", r"(?i)(^|[^\w₹.,])(\d{4,8})\b", "$1[code]"),
            // Names. Titles first, then introductions. Case-insensitive intro, capitalised name
            // after "I am / I'm / this is" (lower case there is usually a feeling: "I am worried").
            r("name", r"\b(?:Mr|Mrs|Ms|Miss|Dr|Shri|Smt|Kumari)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?", "[name]"),
            r("name", r"(?i)\b(my name is|my name's|name\s*:)\s+[a-z]+(?:\s+[a-z]+)?", "$1 [name]"),
            r("name", r"\b((?i:i am|i'm|im|this is|it's|its|mera naam|main))\s+([A-Z][a-z]+)(?:\s+[A-Z][a-z]+)?", "$1 [name]"),
            r("name", r"(?i)\b(my\s+(?:mom|mum|mother|father|dad|papa|mummy|brother|sister|son|daughter|wife|husband|friend|uncle|aunt|aunty|boss|colleague|cousin|grandfather|grandmother|nani|dadi))\s+([A-Z][a-z]+)", "$1 [name]"),
        ]
    })
}

/// Words a capitalised "I am X" is NOT a name for (sentence-style capitals, feelings).
const NOT_NAMES: &[&str] = &[
    "Not", "So", "Very", "Really", "Worried", "Scared", "Afraid", "Confused", "Sure", "Unable",
    "Getting", "Trying", "Using", "From", "In", "On", "At", "The", "A", "An", "Also", "Just",
    "Now", "Still", "Being", "Having", "Facing", "Feeling", "Sorry", "New", "Old", "Your",
    "Safe", "Fine", "Ok", "Okay", "Hacked", "Locked", "Stuck", "Here", "There", "That", "What",
    "Calling", "Writing", "Asking", "Android", "Windows", "Google", "Whatsapp", "WhatsApp",
];

/// Public helplines are not personal: 1930 cyber-crime, 1909 TRAI DND, 1098 child line, 155260 old cyber line.
const PUBLIC_NUMBERS: &[&str] = &["1930", "1909", "1098", "155260"];

/// Currency words (or "lost / paid / debited") next to a number mark it as an amount (kept).
fn is_amount(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].to_lowercase();
    let after = text[end..].to_lowercase();
    let b = before.trim_end();
    let a = after.trim_start();
    ["rs", "rs.", "₹", "inr", "rupees", "rupee", "lost", "paid", "debited", "deducted", "transferred", "worth", "amount"].iter().any(|w| b.ends_with(w))
        || ["rs", "₹", "inr", "rupee", "rupees", "/-", "k ", "lakh", "thousand"].iter().any(|w| a.starts_with(w))
}

pub fn redact(input: &str) -> Redacted {
    let mut text: String = input.chars().take(1500).collect();
    let mut removed: Vec<&'static str> = Vec::new();
    for rule in rules() {
        let mut hit = false;
        let out = rule.re.replace_all(&text, |c: &regex::Captures| {
            let whole = c.get(0).unwrap();
            if rule.kind == "code" {
                let n = c.get(2).unwrap();
                let v: u32 = n.as_str().parse().unwrap_or(0);
                // Years (1950-2039) and amounts stay.
                if (n.as_str().len() == 4 && (1950..=2039).contains(&v)) || PUBLIC_NUMBERS.contains(&n.as_str()) || is_amount(&text, n.start(), n.end()) {
                    return whole.as_str().to_string();
                }
            }
            if rule.kind == "name" && c.len() >= 3 {
                if let Some(n) = c.get(2) {
                    if NOT_NAMES.contains(&n.as_str()) {
                        return whole.as_str().to_string();
                    }
                }
            }
            hit = true;
            let mut s = String::new();
            c.expand(rule.with, &mut s);
            s
        });
        text = out.into_owned();
        if hit && !removed.contains(&rule.kind) {
            removed.push(rule.kind);
        }
    }
    Redacted { text: text.trim().to_string(), removed }
}
