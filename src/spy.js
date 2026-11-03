// Match installed phone apps against the bundled stalkerware list (stalkerware.js, Echap, CC-BY 4.0).
// Pure - no DOM - so tests/spy/match.mjs can run it in Node. An app matches by its package name,
// or by a signing certificate (SHA-1, uppercase hex, from PhonePlugin.kt "certs"). Certificates
// that could not be read (certs null) simply give no certificate match - never a verdict.
import { STALKERWARE } from "./stalkerware.js";

const BY_PKG = new Map();
const BY_CERT = new Map();
for (const a of STALKERWARE.apps) {
  for (const p of a.packages) if (!BY_PKG.has(p)) BY_PKG.set(p, a.name);
  for (const c of a.certs) if (!BY_CERT.has(c)) BY_CERT.set(c, a.name);
}

/** {name, by: "package"|"certificate"} or null. */
export function spyOf(app) {
  if (!app) return null;
  const n = BY_PKG.get(app.pkg);
  if (n) return { name: n, by: "package" };
  for (const c of Array.isArray(app.certs) ? app.certs : []) {
    const m = BY_CERT.get(String(c).toUpperCase());
    if (m) return { name: m, by: "certificate" };
  }
  return null;
}

export const SPY_LIST = {
  apps: STALKERWARE.apps.length,
  packages: BY_PKG.size,
  certs: BY_CERT.size,
  commit: STALKERWARE.commit.slice(0, 8),
  credit: `Echap stalkerware-indicators (${STALKERWARE.license})`,
};
