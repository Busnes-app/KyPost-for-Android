// Seeds sam's demo mailbox with store-screenshot mail over IMAP APPEND on loopback.
// Run inside the mail container: docker exec -i <mail> node --input-type=module - < seed-mail.mjs
// Idempotent: a message whose Message-ID is already in its folder is skipped.
import tls from 'node:tls';

const ME = 'Sam Rivera <sam@kypost-demo.local>';
const now = Date.now();
const ago = (min) => new Date(now - min * 60000);

// [minutesAgo, folder, flags, from, subject, body, extraHeaders]
const MAIL = [
  [12, 'INBOX', ['Primary'], 'Maya Chen <maya.chen@example.com>', 'Saturday hike: trailhead at 8?',
    `Hey Sam,\n\nForecast looks clear for Saturday. Want to do the Ridge Loop? I can pick you up around 7:30 and we'd be at the trailhead by 8.\n\nI'll bring coffee if you bring the good trail mix.\n\nMaya`],
  [47, 'INBOX', ['Primary'], 'Jordan Ellis <jordan@northwind.example>', 'Re: Q4 roadmap draft',
    `Thanks for pulling this together. Two notes:\n\n1. Let's move the self-hosted backup work up to October. It unblocks the migration.\n2. The mobile release can slip a week if QA needs it.\n\nOtherwise this looks great. Can we review Thursday at 2?\n\nJordan`,
    'In-Reply-To: <roadmap-001@kypost-demo.local>\nReferences: <roadmap-001@kypost-demo.local>'],
  [95, 'INBOX', ['Updates'], 'Parcelwise <tracking@parcelwise.example>', 'Your package arrives today',
    `Good news! Your order is out for delivery and should arrive by 6 PM.\n\nItem: 2x 8TB NAS drives\nCarrier: Parcelwise Ground\n\nTrack it any time from your Parcelwise account.`],
  [140, 'INBOX', ['Primary', '\\Seen'], 'Leo Martins <leo@martins.example>', 'Re: NAS upgrade parts list',
    `That list looks solid. I'd swap the 4GB stick for 8GB if the board supports it. ZFS will happily use the extra RAM.\n\nHappy to come over and help with the build next weekend.\n\nLeo`],
  [210, 'INBOX', ['Social'], 'Elm Street Garden Club <hello@elmgarden.example>', 'Seed swap this Sunday 🌱',
    `Hi neighbors,\n\nOur fall seed swap is this Sunday from 10 to 1 at the community plot. Bring labeled seeds, cuttings or just your curiosity.\n\nThere will be cider!\n\nThe Garden Club`],
  [300, 'INBOX', ['Updates', '\\Seen'], 'Harbor Credit Union <statements@harborcu.example>', 'Your October statement is ready',
    `Your monthly statement for checking account ending in 4821 is now available.\n\nSign in to online banking to view it. We will never ask for your password by email.`],
  [420, 'INBOX', ['Primary', '\\Seen', '\\Flagged'], "Dr. Okafor's Office <frontdesk@okaforclinic.example>", 'Appointment reminder: Thu 10:30 AM',
    `This is a reminder of your appointment on Thursday at 10:30 AM.\n\nPlease arrive 10 minutes early. Reply to this email if you need to reschedule.`],
  [560, 'INBOX', ['Promotions'], 'Fieldnotes Coffee <roasts@fieldnotes.example>', '20% off fall roasts this week',
    `Our Maple Ridge and Harvest Blend are back.\n\nUse code FALL20 for 20% off whole beans through Sunday.`],
  [720, 'INBOX', ['Updates', '\\Seen'], 'Homelab Git <git@homelab.example>', '[homelab/infra] PR #42 merged: rotate backup keys',
    `Pull request #42 "rotate backup keys" was merged into main by sam.\n\n3 files changed, 41 insertions(+), 12 deletions(-)`],
  [900, 'INBOX', ['Social', '\\Seen'], 'Riverside Book Club <club@riversidebooks.example>', "Next month's pick is in",
    `We voted, and next month we're reading "The Ministry for the Future."\n\nWe meet the 3rd Tuesday at 7 PM at the library. See you there!`],
  [1300, 'INBOX', ['Promotions', '\\Seen'], 'Trailhead Outfitters <news@trailhead.example>', 'New arrivals: insulated layers for fall',
    `Stay warm on the trail. Our new insulated jackets and fleece layers just landed.\n\nFree shipping on orders over $75.`],
  [1500, 'INBOX', ['Primary', '\\Seen'], 'Priya Raman <priya@raman.example>', 'Cabin photos are up',
    `Finally uploaded everything from the lake weekend. The sunset ones came out amazing.\n\nShared album link is in our group chat. Same time next year?\n\nPriya`],
  [1600, 'Sent Items', ['\\Seen'], ME, 'Q4 roadmap draft',
    `Hi Jordan,\n\nAttached is the first pass at the Q4 roadmap. Let me know what you'd shuffle.\n\nSam`,
    'Message-ID: <roadmap-001@kypost-demo.local>', 'Jordan Ellis <jordan@northwind.example>'],
];

const imapDate = (d) => {
  const m = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][d.getUTCMonth()];
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getUTCDate())}-${m}-${d.getUTCFullYear()} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} +0000`;
};

// Non-ASCII headers must be RFC 2047 words; raw 8-bit is decoded as Latin-1.
const word = (s) => (/[^\x00-\x7f]/.test(s) ? `=?UTF-8?B?${Buffer.from(s).toString('base64')}?=` : s);

function message([min, , , from, subject, body, extra = '', to = ME], i) {
  const id = extra.includes('Message-ID:') ? '' : `Message-ID: <playshot-v2-${i}@kypost-demo.local>\n`;
  const raw = `From: ${from}\nTo: ${to}\nSubject: ${word(subject)}\nDate: ${ago(min).toUTCString().replace('GMT', '+0000')}\n${id}${extra ? extra + '\n' : ''}MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\n${body}\n`;
  return raw.replace(/\r?\n/g, '\r\n');
}

const sock = tls.connect({ host: '127.0.0.1', port: 993, rejectUnauthorized: false });
let buf = '';
let waiter = null;
sock.on('data', (d) => { buf += d.toString('utf8'); waiter?.(); });
const until = (re) => new Promise((res, rej) => {
  const t = setTimeout(() => rej(new Error('timeout waiting for ' + re + '\n' + buf)), 10000);
  waiter = () => { const m = buf.match(re); if (m) { clearTimeout(t); waiter = null; const out = buf.slice(0, m.index + m[0].length); buf = buf.slice(m.index + m[0].length); res(out); } };
  waiter();
});
let n = 0;
const cmd = async (line) => { const tag = 'T' + ++n; sock.write(`${tag} ${line}\r\n`); const out = await until(new RegExp(`^${tag} (OK|NO|BAD).*\\r\\n`, 'm')); if (!new RegExp(`^${tag} OK`, 'm').test(out)) throw new Error(out); return out; };

await until(/^\* OK.*\r\n/m);
await cmd('LOGIN sam@kypost-demo.local demo');
const wanted = MAIL.map((m, i) => ({ m, raw: message(m, i) }));
for (const w of wanted) w.id = w.raw.match(/^Message-ID: (<[^>]+>)/m)[1];

// Reconcile: each seeded folder holds exactly the wanted messages.
let removed = 0;
for (const folder of new Set(MAIL.map((m) => m[1]))) {
  await cmd(`SELECT "${folder}"`);
  const keep = new Set(wanted.filter((w) => w.m[1] === folder).map((w) => w.id));
  const uids = ((await cmd('UID SEARCH ALL')).match(/^\* SEARCH([\d ]*)\r$/m)?.[1] ?? '').trim().split(/\s+/).filter(Boolean);
  for (const uid of uids) {
    const hdr = await cmd(`UID FETCH ${uid} (BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])`);
    const id = hdr.match(/Message-ID:\s*(<[^>]+>)/i)?.[1];
    if (keep.has(id)) continue;
    await cmd(`UID STORE ${uid} +FLAGS.SILENT (\\Deleted)`);
    removed++;
  }
  await cmd('EXPUNGE');
}

let added = 0, skipped = 0;
for (const { m, raw, id: msgId } of wanted) {
  await cmd(`SELECT "${m[1]}"`);
  const found = await cmd(`SEARCH HEADER Message-ID "${msgId}"`);
  if (/^\* SEARCH \d/m.test(found)) { skipped++; continue; }
  const bytes = Buffer.byteLength(raw);
  const tag = 'T' + ++n;
  sock.write(`${tag} APPEND "${m[1]}" (${m[2].join(' ')}) "${imapDate(ago(m[0]))}" {${bytes}}\r\n`);
  await until(/^\+.*\r\n/m);
  sock.write(raw + '\r\n');
  const out = await until(new RegExp(`^${tag} (OK|NO|BAD).*\\r\\n`, 'm'));
  if (!new RegExp(`^${tag} OK`, 'm').test(out)) throw new Error(out);
  added++;
}
await cmd('LOGOUT').catch(() => {});
console.log(`seeded: ${removed} removed, ${added} added, ${skipped} already present`);
sock.end();
