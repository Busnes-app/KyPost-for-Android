// Seals the v4/v5 fixtures in browser-sealed-envelopes.json with KyPost-Server's real browser sealer
// (frontend/src/lib/deviceEnrollment.ts, @hpke/core). Test data only: the recipient key is public.
//
//   node seal-with-kypost-server.mjs <KyPost-Server checkout, frontend deps installed> > browser-sealed-envelopes.json
import { createECDH, createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { register } from "node:module";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const server = resolve(process.argv[2] ?? "");
// The sealer imports "./pgpKeyring" without an extension, as its bundler allows; Node needs ".ts".
register("data:text/javascript," + encodeURIComponent(`
export async function resolve(spec, context, next) {
  try { return await next(spec, context); }
  catch (e) { if (spec.startsWith(".") && !spec.endsWith(".ts")) return next(spec + ".ts", context); throw e; }
}`));
const sealer = await import(pathToFileURL(join(server, "frontend/src/lib/deviceEnrollment.ts")).href);
const pgp = await import(pathToFileURL(join(server, "frontend/node_modules/openpgp/dist/node/openpgp.mjs")).href);

const here = new URL(".", import.meta.url).pathname;
const ring = JSON.parse(readFileSync(join(here, "../kypost-server/pgp-keyring-v1.json"), "utf8")).ring;
const raw = JSON.stringify(ring);
const active = ring.activeFingerprint;
const activeArmor = ring.keys.find(k => k.fingerprint === active).privateKey;

const skR = createHash("sha256").update("kypost-android hpke fixture recipient").digest();
const ecdh = createECDH("prime256v1");
ecdh.setPrivateKey(skR);
const pkR = ecdh.getPublicKey().toString("base64");
const deviceId = "dev-hpke-ü";

const v4 = await sealer.sealEnvelopeForDevice(pkR, deviceId, active, activeArmor, 4);
const typedCode = await sealer.deriveEnrollmentCode(pkR, deviceId, sealer.bucketFor(Math.floor(Date.now() / 1000)));
const publicKey = (await pgp.readPrivateKey({ armoredKey: activeArmor })).toPublic().armor();
const keyring = { version: 1, materialGeneration: ring.materialGeneration,
  primaryFingerprints: ring.keys.map(k => k.fingerprint), keyFingerprints: ring.keyFingerprints };
const v5 = await sealer.sealKeyringForDevice({ publicKeyB64: pkR, deviceId, typedCode, raw,
  snapshot: { fingerprint: active, publicKey, keyring }, version: 5 });

const git = args => execFileSync("git", ["-C", server, ...args], { encoding: "utf8" }).trim();
process.stdout.write(JSON.stringify({
  description: "v4/v5 device envelopes sealed by KyPost-Server's browser sealer. Public test data only.",
  generator: { script: "seal-with-kypost-server.mjs", serverCommit: git(["rev-parse", "HEAD"]),
    hpkeCore: JSON.parse(readFileSync(join(server, "frontend/node_modules/@hpke/core/package.json"), "utf8")).version,
    node: process.version },
  recipient: { skR: skR.toString("hex"), pkR },
  deviceId,
  fingerprint: active,
  cases: [
    { version: 4, plaintext: activeArmor, envelope: JSON.stringify(v4) },
    { version: 5, plaintext: raw, envelope: JSON.stringify(v5), materialGeneration: ring.materialGeneration,
      primaryFingerprints: keyring.primaryFingerprints, keyFingerprints: ring.keyFingerprints },
  ],
}, null, 2) + "\n");
