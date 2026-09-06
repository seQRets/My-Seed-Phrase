#!/usr/bin/env node
'use strict';
/*
 * verify.js — checks index.html against the BIP-39 standard and its own invariants.
 *
 *   node verify.js              run every check
 *   node verify.js --calibrate  re-measure the strength read-out (slow, ~1 min)
 *
 * One file, no dependencies, no install step — the same rule the page follows.
 * Needs Node 22+ (for global WebSocket) and Google Chrome. Set CHROME to point
 * at a different binary.
 *
 * The page can already check itself: "Verify this page" runs nine published
 * BIP-39 vectors and hashes its own word list. This exists because a page
 * should not be the only judge of whether it is correct. Everything below is
 * worked out independently — the expected answers come from a separate BIP-39
 * implementation built on Node's crypto, not from the page.
 */

const { spawn } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path');
const http = require('http'), crypto = require('crypto');
const { pathToFileURL } = require('url');

const ROOT = __dirname;
const PAGE = path.join(ROOT, 'index.html');
// Planted in the /snapshot page below: the note naming a word of a seed, and a
// wallet's master fingerprint, exactly as File → Save Page As would write them
// into a copy saved mid-use. Neither may survive the page opening. The whole
// sentence is matched rather than the bare word, because every BIP-39 word —
// "midnight" included — is in the wordlist this file embeds.
const SNAP_WORD = 'midnight';
const SNAP_NOTE = `“${SNAP_WORD}” is word 12 — the completed seed is in the box at the top.`;
const SNAP_FP = '45618c53';
// The dice read-out is worked out from the rolls, so it is derived state and
// scrubs with the rest. The rolls themselves never reach a saved file — a
// textarea's value is not part of the document — but what they produced does.
// The sentence has to be one the page BUILDS rather than one it contains: the
// wording is assembled around ${period} at runtime, so this exact string is
// nowhere in the source. Planting a phrase that is in the source matches the
// script tag itself and the check can only ever fail. Asserted below, because
// that mistake is invisible once made.
const SNAP_ROLLQ = 'the same 7 rolls repeat over and over';
const WORDLIST_SHA256 = '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda';
// Tripwire. assess() is tuned so genuine random draws almost never trip a
// warning while every hand-picking pattern is still caught; changing it without
// re-measuring both sides quietly wrecks it. If you changed it deliberately,
// run --calibrate, confirm the numbers, then update this.
const ASSESS_SHA256 = 'fe7d49ab746ea176';
const ASSESS_BYTES  = 2670;

let fails = 0, count = 0;
const chk = (name, ok, extra = '') => {
  count++; if (!ok) fails++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${name}${extra ? '  — ' + extra : ''}`);
};

/* ---- chrome ---------------------------------------------------------- */
function findChrome() {
  const candidates = [process.env.CHROME,
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  ].filter(Boolean);
  for (const c of candidates) { try { fs.accessSync(c, fs.constants.X_OK); return c } catch {} }
  return null;
}

async function launch(bin, port = 9333) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bip39-verify-'));
  const proc = spawn(bin, ['--headless=new', `--remote-debugging-port=${port}`,
    `--user-data-dir=${dir}`, '--no-first-run', '--no-default-browser-check',
    '--disable-gpu', '--disable-extensions', '--disable-background-networking',
    '--disable-component-update', '--disable-sync', '--no-pings',
    '--window-size=1280,900', 'about:blank'], { stdio: ['ignore', 'pipe', 'pipe'] });
  let err = ''; proc.stderr.on('data', d => err += d);
  for (let i = 0; i < 100; i++) {
    try {
      const v = await fetch(`http://127.0.0.1:${port}/json/version`).then(r => r.json());
      return { proc, wsUrl: v.webSocketDebuggerUrl, version: v.Browser };
    } catch { await new Promise(r => setTimeout(r, 100)); }
  }
  proc.kill(); throw new Error('Chrome did not start.\n' + err);
}

function connect(wsUrl) {
  const ws = new WebSocket(wsUrl);
  let id = 0; const pending = new Map(), listeners = [];
  const ready = new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  ws.onmessage = ev => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) {
      const { res, rej } = pending.get(m.id); pending.delete(m.id);
      m.error ? rej(new Error(JSON.stringify(m.error))) : res(m.result);
    } else if (m.method) listeners.forEach(f => f(m));
  };
  const send = async (method, params = {}, sessionId) => {
    await ready; const mid = ++id;
    return new Promise((res, rej) => {
      pending.set(mid, { res, rej });
      ws.send(JSON.stringify({ id: mid, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  };
  return { send, on: f => listeners.push(f) };
}

async function openPage(browser, url) {
  const cdp = connect(browser.wsUrl);
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  const S = (m, p, sid) => cdp.send(m, p, sid || sessionId);
  const logs = [], requests = [], exceptions = [];
  const childSessions = new Set();
  cdp.on(m => {
    // a sandboxed or cross-origin frame runs in its own process, so it arrives
    // as a separate session rather than an execution context in this one
    if (m.method === 'Target.attachedToTarget' && m.params.targetInfo.type === 'iframe') {
      childSessions.add(m.params.sessionId);
      cdp.send('Runtime.enable', {}, m.params.sessionId).catch(() => {});
    }
    if (m.method === 'Target.detachedFromTarget') childSessions.delete(m.params.sessionId);
    if (m.sessionId !== sessionId) return;
    if (m.method === 'Runtime.consoleAPICalled') logs.push({ type: m.params.type });
    if (m.method === 'Runtime.exceptionThrown')
      exceptions.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text);
    if (m.method === 'Network.requestWillBeSent') requests.push(m.params.request.url);
  });
  await S('Runtime.enable'); await S('Network.enable'); await S('Page.enable');
  await S('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: false, flatten: true });
  const goto = async u => {
    await S('Page.navigate', { url: u });
    for (let i = 0; i < 200; i++) {
      const r = await S('Runtime.evaluate', { expression: 'document.readyState', returnByValue: true });
      if (r.result.value === 'complete') break;
      await new Promise(r2 => setTimeout(r2, 50));
    }
  };
  await goto(url);
  return {
    logs, requests, exceptions, S, goto, childSessions,
    evalIn: async (expr, sid) => {
      const r = await S('Runtime.evaluate',
        { expression: `(async()=>{${expr}})()`, awaitPromise: true, returnByValue: true }, sid);
      if (r.exceptionDetails)
        throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
      return r.result.value;
    },
    evaluate: async expr => {
      const r = await S('Runtime.evaluate',
        { expression: `(async()=>{${expr}})()`, awaitPromise: true, returnByValue: true });
      if (r.exceptionDetails)
        throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
      return r.result.value;
    },
    setViewport: (width, height) => S('Emulation.setDeviceMetricsOverride',
      { width, height, deviceScaleFactor: 1, mobile: false }),
    close: () => cdp.send('Target.closeTarget', { targetId }),
  };
}

/* ---- an independent BIP-39, so the page is not its own judge ---------- */
const SRC = fs.readFileSync(PAGE, 'utf8');
const WORDS = SRC.match(/const WORDS = "([^"]+)"\.split\(" "\);/)[1].split(' ');
const IDX = new Map(WORDS.map((w, i) => [w, i]));
// The third carrier of a seed word, alongside the note and the fingerprint: the
// endings grid marks the chosen chip, and that chip IS a word of the seed. Built
// exactly as calculate() builds it, so the snapshot is what Save Page As would
// really have written. Matched as the whole element for the same reason the note
// is matched as a whole sentence — the bare word is in the embedded wordlist.
const SNAP_CHIP = `<div class="w sel"><span>${SNAP_WORD}</span>`
                + `<span class="i">${IDX.get(SNAP_WORD)}</span></div>`;

// bits -> entropy bytes -> sha256 -> compare the checksum the standard's way
// Dice vectors. One clean 100-roll sequence whose first 51 rolls are also
// clean, so the same string exercises both a 12- and a 24-word seed without
// tripping the page's own roll-quality check and turning these into tests of
// the warning instead of the maths.
const ROLLS100 = '6316122265665236562562146265354545666262333213561554411262152314163156124665425312164255413412222533';
const ROLLS51 = ROLLS100.slice(0, 51);

// Dice -> seed built on Node's crypto, independent of the page: hash the
// digits, take the leading bytes as entropy, append the checksum they imply.
function diceMnemonic(rolls, words) {
  const ent = crypto.createHash('sha256').update(rolls, 'utf8').digest().slice(0, words / 3 * 4);
  const eb = [...ent].map(b => b.toString(2).padStart(8, '0')).join('');
  const cs = [...crypto.createHash('sha256').update(ent).digest()]
    .map(b => b.toString(2).padStart(8, '0')).join('').slice(0, eb.length / 32);
  return (eb + cs).match(/.{11}/g).map(b => WORDS[parseInt(b, 2)]);
}

function validate(phrase) {
  const ws = phrase.trim().split(/\s+/), n = ws.length;
  if (![12, 15, 18, 21, 24].includes(n) || ws.some(w => !IDX.has(w))) return false;
  const bits = ws.map(w => IDX.get(w).toString(2).padStart(11, '0')).join('');
  const cs = n / 3, ent = bits.length - cs;
  const bytes = Buffer.from(bits.slice(0, ent).match(/.{8}/g).map(b => parseInt(b, 2)));
  const h = crypto.createHash('sha256').update(bytes).digest();
  return [...h].map(x => x.toString(2).padStart(8, '0')).join('').slice(0, cs) === bits.slice(ent);
}
// brute force: every word that produces a valid phrase
const brute = prefix => WORDS.filter(w => validate(prefix.join(' ') + ' ' + w));

/* ---- helpers injected into the page ---------------------------------- */
const HELPERS = `const $=id=>document.getElementById(id);
  const wait=async(f,ms=30000)=>{const t=Date.now();while(Date.now()-t<ms){if(f())return 1;
    await new Promise(r=>setTimeout(r,25))}return 0};`;

/* ---- checks ---------------------------------------------------------- */
function sourceChecks() {
  console.log('--- the file itself ---');
  chk('word list is 2048 words', WORDS.length === 2048);
  chk('word list is the official BIP-39 English list',
    crypto.createHash('sha256').update(WORDS.join('\n') + '\n').digest('hex') === WORDLIST_SHA256);
  // a sentinel that appears in the source matches the script tag, not the DOM
  chk('the snapshot sentinels cannot match the page\'s own source',
    !SRC.includes(SNAP_ROLLQ) && !SRC.includes(SNAP_NOTE) && !SRC.includes(SNAP_FP)
    && !SRC.includes(SNAP_CHIP),
    'a planted value also occurs in index.html, so its scrub check proves nothing');
  chk('no Math.random() anywhere', (SRC.match(/Math\.random\s*\(/g) || []).length === 0);
  const csp = (SRC.match(/http-equiv="Content-Security-Policy"[\s\S]*?content="([^"]+)"/) || [])[1] || '';
  // The favicon needs img-src data:. That is inline, not a fetch. What must never
  // appear is a source that can reach the network — a scheme, a host, or a wildcard.
  const reachesNetwork = /https?:|\/\/|\*/.test(csp);
  chk("CSP is default-src 'none' with no network source",
    /default-src 'none'/.test(csp) && !reachesNetwork,
    reachesNetwork ? 'CSP now permits a network origin: ' + csp : '');
  chk('CNAME and .nojekyll survive',
    fs.existsSync(path.join(ROOT, 'CNAME')) && fs.existsSync(path.join(ROOT, '.nojekyll')));
  chk('nothing is loaded from anywhere (no src=)',
    [...SRC.matchAll(/\bsrc\s*=\s*"([^"]+)"/g)].length === 0);
  // The logo is inlined into index.html for the no-network rule, with
  // BIP-39-logo.svg kept as the editable source. Two copies drift; this
  // compares what actually draws the mark, ignoring whitespace and wrapper.
  const logoFile = path.join(ROOT, 'BIP-39-logo.svg');
  if (fs.existsSync(logoFile)) {
    const shape = t => {
      const d = (t.match(/\sd=['"]([^'"]+)['"]/) || [])[1] || '';
      const stops = [...t.matchAll(/stop-color=['"]([^'"]+)['"]/g)].map(m => m[1]).join(',');
      const circle = (t.match(/<circle[^>]*r=['"]([\d.]+)['"]/) || [])[1] || '';
      return JSON.stringify({ d: d.replace(/\s+/g, ' ').trim(), stops, circle });
    };
    const source = shape(fs.readFileSync(logoFile, 'utf8'));
    // scope to the header mark: the favicon's encoded copy sits earlier in the file
    const headerSvg = (SRC.match(/<svg class="mark"[\s\S]*?<\/svg>/) || [''])[0];
    const inHeader = shape(headerSvg);
    // the mark exists three times now: source file, header <svg>, favicon data URI
    const icon = (SRC.match(/<link rel="icon" href="([^"]+)"/) || [])[1] || '';
    const inIcon = shape(decodeURIComponent(icon));
    chk('header logo still matches BIP-39-logo.svg', source === inHeader,
      source === inHeader ? '' : 're-inline the source into index.html');
    chk('favicon still matches BIP-39-logo.svg', source === inIcon,
      source === inIcon ? '' : 're-encode the source into the icon data URI');
  }
  // The fingerprint is written by hand in two places: the footer's markup and the
  // WORDLIST_SHA256 constant the built-in verification compares against. Editing
  // one and not the other would show a value different from the one being used.
  const brief = h => h ? h.slice(0, 8) + '\u2026' + h.slice(-8) : '(not found)';
  const shown = (SRC.match(/id="wlhash"[\s\S]*?>([0-9a-f]{64})<\/button>/) || [])[1];
  const constant = (SRC.match(/WORDLIST_SHA256 = "([0-9a-f]{64})"/) || [])[1];
  const realHash = crypto.createHash('sha256').update(WORDS.join('\n') + '\n').digest('hex');
  chk('the fingerprint shown, the one checked and the real one all agree',
    shown === constant && constant === realHash,
    (shown === constant && constant === realHash) ? ''
      : `footer shows ${brief(shown)}, the code checks ${brief(constant)}, the list hashes to ${brief(realHash)}`);
  const a = SRC.match(/function assess\(words\) \{[\s\S]*?\n\}\n/)[0];
  const h = crypto.createHash('sha256').update(a).digest('hex');
  chk('assess() unchanged (calibration still valid)',
    h.startsWith(ASSESS_SHA256) && a.length === ASSESS_BYTES,
    h.startsWith(ASSESS_SHA256) ? `${a.length} bytes`
      : `changed — run --calibrate, check both sides, then update ASSESS_SHA256 to ${h.slice(0, 16)} / ${a.length}`);
}

async function pageChecks(browser, fileUrl, httpUrl) {
  console.log('\n--- does it get the right answer? ---');
  for (const [label, url] of [['from a file', fileUrl], ['over http', httpUrl]]) {
    const p = await openPage(browser, url);
    // A page broken badly enough can fail to render its own verdict at all.
    // Report that, rather than throwing on the missing element.
    const st = await p.evaluate(`${HELPERS} $('test').click();
      await wait(()=>$('testsum')&&$('testsum').textContent.trim());
      const el=$('testsum');
      return el ? el.textContent.trim() : 'never finished — the page threw before reporting';`);
    chk(`its own verification reads 15 of 15, ${label}`, st === '✓ All 15 checks passed', st);
    const off = p.requests.filter(u => !u.startsWith(url.replace(/\/$/, '')) && !u.startsWith(url));
    chk(`nothing is fetched from anywhere, ${label}`, off.length === 0, off.join(','));
    chk(`no script errors, ${label}`, p.exceptions.length === 0, p.exceptions.join(' | '));
    await p.close();
  }

  const p = await openPage(browser, fileUrl);
  const c = await p.evaluate(`
    const a11=await candidates(Array(11).fill('abandon'));
    const a23=await candidates(Array(23).fill('abandon'));
    return {a11,a23:a23.join(' ')};`);
  const ref11 = brute(Array(11).fill('abandon'));
  chk('abandon x11 matches an independent implementation, word for word',
    JSON.stringify(c.a11) === JSON.stringify(ref11), `${c.a11.length} vs ${ref11.length}`);
  chk('abandon x23 gives the published answer',
    c.a23 === brute(Array(23).fill('abandon')).join(' '), c.a23);

  const EXPECT = { 11: 128, 14: 64, 17: 32, 20: 16, 23: 8 };
  const gen = await p.evaluate(`${HELPERS}
    const out=[];
    for (const o of $('genlen').options) {
      const want=${JSON.stringify(EXPECT)}[o.value];
      for (let k=0;k<6;k++){
        $('clr').click(); await wait(()=>$('out').style.display==='none');
        $('genlen').value=o.value; $('gen').click();
        if(!await wait(()=>$('out').style.display==='block'
          && document.querySelectorAll('#grid .w').length===want
          && $('st').textContent.startsWith('✓'))) return {err:'timed out at '+o.value+' words'};
        const input=$('in').value.trim();
        $('rand').click();
        if(!await wait(()=>$('in').value.trim().split(/\\s+/).length===+o.value+1)) return {err:'pick at random timed out'};
        const full=$('in').value.trim().replace(/\\s+/g,' ');
        if(!full.startsWith(input+' ')) return {err:'completed seed does not start with the words supplied'};
        out.push(full);
      }
    } return {out};`);
  chk('generate, calculate and pick work at all five lengths', !gen.err, gen.err || '');
  // the manual flow's assembled-phrase controls: visible on arrival, the eye
  // hides the whole line including the highlighted last word, copy warns
  const manual = await p.evaluate(`${HELPERS}
    $('clr').click(); await wait(()=>$('out').style.display==='none');
    $('in').value='abandon '.repeat(11).trim(); $('go').click();
    if(!await wait(()=>$('out').style.display==='block'
      && document.querySelectorAll('#grid .w').length===128)) return {err:'grid timeout'};
    document.querySelector('#grid .w').click();
    if(!await wait(()=>$('in').value.trim().split(/\\s+/).length===12)) return {err:'completion timeout'};
    const r={ ctl: $('inctl').style.display!=='none',
              typedStaysVisible: !$('in').classList.contains('shield'),
              qrAvailable: $('inqr').style.display!=='none',
              noteBelow: /box at the top/.test($('randnote').textContent),
              warnNotYet: !/clipboard/i.test($('inhint').textContent) };
    $('peek').click(); r.hides = $('in').classList.contains('shield');
    document.querySelectorAll('#grid .w')[1].click();
    r.staysHidden = $('in').classList.contains('shield');
    $('peek').click(); r.showsAgain = !$('in').classList.contains('shield');
    $('incopy').click(); r.warnAfterCopy = /clipboard/i.test($('inhint').textContent);
    r.noLowerBox = !document.getElementById('full');
    return r;`);
  chk('typed words complete into the one box, visible, with QR and note below',
    !manual.err && manual.ctl && manual.typedStaysVisible && manual.qrAvailable
      && manual.noteBelow && manual.warnNotYet && manual.hides && manual.staysHidden
      && manual.showsAgain && manual.warnAfterCopy && manual.noLowerBox,
    manual.err || JSON.stringify(manual));
  // partial generation is born hidden, like everything the generator makes
  const partial = await p.evaluate(`${HELPERS}
    $('clr').click(); await wait(()=>$('out').style.display==='none');
    $('genlen').value='11'; $('gen').click();
    if(!await wait(()=>$('out').style.display==='block'
      && document.querySelectorAll('#grid .w').length===128)) return {err:'partial timeout'};
    return { blurred: $('in').classList.contains('shield'),
             ctl: $('inctl').style.display!=='none',
             qrHidden: $('inqr').style.display==='none',
             guided: /choose the ending/i.test($('inhint').textContent) };`);
  chk('a generated partial seed arrives blurred, QR withheld until complete',
    !partial.err && partial.blurred && partial.ctl && partial.qrHidden && partial.guided,
    partial.err || JSON.stringify(partial));
  // typing never lifts a blur already engaged: a hidden box edited by hand
  // stays hidden, so a passer-by cannot read what is being entered
  const shieldTyping = await p.evaluate(`${HELPERS}
    $('clr').click(); await wait(()=>$('out').style.display==='none');
    const r={};
    // typed into a fresh box: visible, then the eye hides it, then further
    // typing must keep it hidden
    $('in').value='abandon ability'; $('in').dispatchEvent(new Event('input'));
    r.bornVisible = !$('in').classList.contains('shield');
    $('peek').click();
    r.hides = $('in').classList.contains('shield');
    $('in').value='abandon ability able'; $('in').dispatchEvent(new Event('input'));
    r.typingStaysHidden = $('in').classList.contains('shield')
      && $('inctl').style.display!=='none';
    // a generated seed is born hidden; hand-editing it must not reveal it
    $('clr').click();
    $('genlen').value='11'; $('genfull').click();
    if(!await wait(()=>$('in').classList.contains('shield'))) return {err:'genfull timeout'};
    $('in').value = $('in').value + ' abandon';
    $('in').dispatchEvent(new Event('input'));
    r.editKeepsGeneratedHidden = $('in').classList.contains('shield');
    // and once revealed, typing does not re-hide it
    $('peek').click();
    $('in').value = $('in').value + ' abandon'; $('in').dispatchEvent(new Event('input'));
    r.visibleStaysVisible = !$('in').classList.contains('shield');
    $('clr').click();
    return r;`);
  chk('typing never lifts an engaged blur, nor re-hides a revealed box',
    !shieldTyping.err && shieldTyping.bornVisible && shieldTyping.hides
      && shieldTyping.typingStaysHidden && shieldTyping.editKeepsGeneratedHidden
      && shieldTyping.visibleStaysVisible,
    shieldTyping.err || JSON.stringify(shieldTyping));
  if (gen.out) {
    const bad = gen.out.filter(x => !validate(x));
    chk(`all ${gen.out.length} generated phrases are valid BIP-39 (checked independently)`,
      bad.length === 0, bad.slice(0, 2).join(' | '));
  }

  // the one-press button, driven exactly as a user would press it. The seed
  // lands in the input box, blurred, with the eye and copy controls beside it.
  const one = await p.evaluate(`${HELPERS}
    const out=[];
    for (const o of $('genlen').options) {
      $('clr').click(); await wait(()=>$('out').style.display==='none');
      $('genlen').value=o.value; $('genfull').click();
      if(!await wait(()=>document.querySelectorAll('#grid .w.sel').length===1
        && $('in').classList.contains('shield')
        && $('inctl').style.display!=='none')) return {err:'timed out at '+o.value};
      const rec={ phrase: $('in').value.trim(),
                  blurred: $('in').classList.contains('shield'),
                  note: $('inhint').textContent };
      // the eye reveals, and reveals only when pressed
      $('peek').click(); rec.unblurs = !$('in').classList.contains('shield');
      $('peek').click(); rec.reblurs = $('in').classList.contains('shield');
      // choosing a different ending updates the box, not the block below
      const other=[...document.querySelectorAll('#grid .w')].find(w=>!w.classList.contains('sel'));
      other.click(); rec.rechoose = $('in').value.trim();
      // copying surfaces the clipboard warning
      $('incopy').click(); rec.copyWarn = /clipboard/i.test($('inhint').textContent);
      out.push(rec);
    } return {out};`);
  chk('"Generate complete seed" puts a blurred seed in the box at all 5 lengths', !one.err, one.err || '');
  if (one.out) {
    chk('all one-press seeds are valid BIP-39 (checked independently)',
      one.out.every(x => validate(x.phrase)),
      one.out.filter(x => !validate(x.phrase)).map(x => x.phrase).slice(0, 1).join(''));
    chk('re-choosing an ending updates the box and stays valid',
      one.out.every(x => validate(x.rechoose) && x.rechoose !== x.phrase),
      one.out.filter(x => !validate(x.rechoose)).map(x => x.rechoose).slice(0, 1).join(''));
    const oneBad = one.out.find(x => !x.blurred || !x.unblurs || !x.reblurs
      || !/came from your browser/.test(x.note) || !x.copyWarn);
    chk('blur, eye toggle and copy warning on the one-press seed',
      !oneBad, oneBad ? JSON.stringify(oneBad).slice(0, 140) : '');
  }

  // ---------- SeedQR ----------
  // digits: the page's encoder must agree with an independent one, and the
  // canvas geometry proves Numeric mode — byte mode of 48 digits cannot fit
  // version 2, so a 264px canvas is only reachable encoded as the spec says.
  const sqDigits = ws => ws.map(w => String(IDX.get(w)).padStart(4, '0')).join('');
  const sq = await p.evaluate(`${HELPERS}
    const out = {};
    out.digitsKnown = seedqrDigits([...Array(11).fill('abandon'),'about']);
    out.digitsZoo = seedqrDigits([...Array(23).fill('zoo'),'vote']);
    $('clr').click(); await wait(()=>$('out').style.display==='none');
    $('genlen').value='11'; $('genfull').click();
    if(!await wait(()=>$('in').classList.contains('shield'))) return {err:'genfull timeout'};
    out.seed12 = $('in').value.trim();
    $('inqr').click();
    // Opening is async (it re-checks the checksum first), so for a moment
    // after the click the canvas is still the 1px wipe from the last close.
    if(!await wait(()=>$('qrcanvas').width>1)) return {err:'12-word QR never drew'};
    out.open12 = $('qrveil').style.display!=='none';
    out.blur12 = $('qrbox').classList.contains('shield');
    out.canvas12 = $('qrcanvas').width;
    $('qrpeek').click(); out.reveals = !$('qrbox').classList.contains('shield');
    $('qrclose').click();
    out.closed = $('qrveil').style.display==='none';
    out.wiped = $('qrcanvas').width===1;
    $('inqr').click();
    if(!await wait(()=>$('qrcanvas').width>1)) return {err:'QR never redrew'};
    out.reblurs = $('qrbox').classList.contains('shield');
    dispatchEvent(new KeyboardEvent('keydown',{key:'Escape'}));
    out.escCloses = $('qrveil').style.display==='none';
    $('clr').click(); await wait(()=>$('out').style.display==='none');
    $('genlen').value='23'; $('genfull').click();
    if(!await wait(()=>$('in').classList.contains('shield'))) return {err:'genfull 23 timeout'};
    $('inqr').click();
    if(!await wait(()=>$('qrcanvas').width>1)) return {err:'24-word QR never drew'};
    out.canvas24 = $('qrcanvas').width; $('qrclose').click();
    $('clr').click(); await wait(()=>$('out').style.display==='none');
    $('in').value='abandon '.repeat(11).trim(); $('go').click();
    await wait(()=>document.querySelectorAll('#grid .w').length===128);
    document.querySelector('#grid .w').click();
    await wait(()=>$('inqr').style.display!=='none');
    $('inqr').click();
    if(!await wait(()=>$('qrcanvas').width>1)) return {err:'manual QR never drew'};
    out.manualOpen = $('qrveil').style.display!=='none';
    out.manualBlur = $('qrbox').classList.contains('shield');
    $('qrclose').click();
    return out;`);
  chk('SeedQR digits match an independent encoding', !sq.err
      && sq.digitsKnown === sqDigits([...Array(11).fill('abandon'), 'about'])
      && sq.digitsZoo === sqDigits([...Array(23).fill('zoo'), 'vote'])
      && sq.digitsKnown === '0'.repeat(44) + '0003',
    sq.err || `${String(sq.digitsKnown).slice(0, 12)}…`);
  chk('generated seed valid and its digits are 4 per word', !sq.err
      && validate(sq.seed12) && sqDigits(sq.seed12.split(' ')).length === 48);
  chk('QR is Numeric mode: version 2 at 12 words, version 3 at 24',
      !sq.err && sq.canvas12 === (25 + 8) * 8 && sq.canvas24 === (29 + 8) * 8,
      sq.err || `${sq.canvas12}px / ${sq.canvas24}px, expected 264 / 296`);
  chk('SeedQR modal: blurred open, reveal, wipe on close, re-blur, Esc, manual flow too',
      !sq.err && sq.open12 && sq.blur12 && sq.reveals && sq.closed && sq.wiped
      && sq.reblurs && sq.escCloses && sq.manualOpen && sq.manualBlur,
      sq.err || JSON.stringify(sq).slice(0, 160));

  // ---------- master fingerprint ----------
  // fully independent chain: Node's PBKDF2, HMAC, secp256k1 (via ECDH) and
  // RIPEMD-160 against the page's in-file implementations, plus the published
  // anchor for the all-zeros mnemonic.
  const nodeFp = mnemonic => {
    const seed = crypto.pbkdf2Sync(mnemonic, 'mnemonic', 2048, 64, 'sha512');
    const I = crypto.createHmac('sha512', 'Bitcoin seed').update(seed).digest();
    const e = crypto.createECDH('secp256k1'); e.setPrivateKey(I.slice(0, 32));
    const sha = crypto.createHash('sha256').update(e.getPublicKey(null, 'compressed')).digest();
    return crypto.createHash('ripemd160').update(sha).digest().slice(0, 4).toString('hex');
  };
  const fpr = await p.evaluate(`${HELPERS}
    const out = {};
    out.anchor = await masterFingerprint([...Array(11).fill('abandon'),'about']);
    // the fingerprint shown for a real generated seed
    $('clr').click(); await wait(()=>$('out').style.display==='none');
    $('genlen').value='11'; $('genfull').click();
    if(!await wait(()=>$('in').classList.contains('shield'))) return {err:'genfull timeout'};
    out.seed = $('in').value.trim();
    // the in-box line, no modal needed
    if(!await wait(()=>/^[0-9a-f]{8}$/.test($('infpv').textContent), 8000)) return {err:'box fingerprint never shown'};
    out.boxFp = $('infpv').textContent;
    // re-choosing the ending must change the phrase and refresh the fingerprint
    const other=[...document.querySelectorAll('#grid .w')].find(w=>!w.classList.contains('sel'));
    other.click();
    out.seed2 = $('in').value.trim();
    if(!await wait(()=>/^[0-9a-f]{8}$/.test($('infpv').textContent)
        && $('infpv').textContent!==out.boxFp, 8000)) return {err:'box fingerprint did not refresh'};
    out.boxFp2 = $('infpv').textContent;
    $('inqr').click();
    if(!await wait(()=>$('qrcanvas').width>1)) return {err:'QR never drew'};
    if(!await wait(()=>/^[0-9a-f]{8}$/.test($('qrfp').textContent), 8000)) return {err:'fingerprint never shown'};
    out.shown = $('qrfp').textContent;
    out.modalAgrees = out.shown === out.boxFp2;
    out.unblurred = !$('qrfp').closest('.qrbox');
    $('qrclose').click();
    out.cleared = $('qrfp').textContent==='…';
    // the reserved right padding must cover the control strip in both boxes,
    // or a long first line runs underneath the icons
    const covers = (area, ctl) => {
      const a=area.getBoundingClientRect(), c=ctl.getBoundingClientRect();
      return parseFloat(getComputedStyle(area).paddingRight) >= (a.right - c.left) - 1;
    };
    out.padOk = covers($('in'), $('inctl'));
    out.padWhy = 'input covered: '+out.padOk;
    // editing by hand dismisses the line with the rest of the generated state
    $('clr').click(); await wait(()=>$('out').style.display==='none');
    $('genlen').value='11'; $('genfull').click();
    if(!await wait(()=>$('in').classList.contains('shield'))) return {err:'genfull re-run timeout'};
    $('in').dispatchEvent(new Event('input'));
    out.goneOnEdit = $('infp').style.display==='none';
    return out;`);
  chk('master fingerprint anchor is 73c5da0a and Node agrees', !fpr.err
      && fpr.anchor === '73c5da0a' && nodeFp('abandon '.repeat(11) + 'about') === '73c5da0a',
    fpr.err || fpr.anchor);
  chk('fingerprint shown for a generated seed matches Node independently',
      !fpr.err && fpr.boxFp === nodeFp(fpr.seed),
      fpr.err || `page ${fpr.boxFp}, node ${!fpr.err && nodeFp(fpr.seed)}`);
  chk('text cannot run under the control icons', !fpr.err && fpr.padOk, fpr.err || fpr.padWhy);
  const creep = await p.evaluate(`${HELPERS}
    $('clr').click(); await wait(()=>$('out').style.display==='none');
    const settle = async () => { let y=-1;
      for(let i=0;i<40;i++){ await new Promise(r=>setTimeout(r,100));
        if(Math.abs(scrollY-y)<1) return scrollY; y=scrollY; } return scrollY; };
    const ys=[];
    for (const start of [0, 400]) {
      scrollTo(0, start); await new Promise(r=>setTimeout(r,100));
      for (let i=0;i<2;i++){
        $('genlen').value='11'; $('genfull').click();
        if(!await wait(()=>$('in').classList.contains('shield'))) return {err:'timeout'};
        ys.push({ start, ended: await settle() });
      }
    }
    return {ys};`);
  chk('generating never scrolls the page, from the top or mid-page',
      !creep.err && creep.ys.every(y => Math.abs(y.ended - y.start) < 3),
      creep.err || JSON.stringify(creep.ys));
  chk('in-box fingerprint refreshes on re-choosing and the modal agrees',
      !fpr.err && fpr.boxFp2 === nodeFp(fpr.seed2) && fpr.modalAgrees && fpr.goneOnEdit,
      fpr.err || `box ${fpr.boxFp2}, node ${!fpr.err && nodeFp(fpr.seed2)}, modal agrees ${fpr.modalAgrees}`);
  chk('fingerprint sits outside the blur and clears on close',
      !fpr.err && fpr.unblurred && fpr.cleared, fpr.err || JSON.stringify(fpr).slice(0, 100));

  console.log('\n--- how it looks ---');
  const links = await p.evaluate(
    `return [...document.querySelectorAll('a')].map(a=>({href:a.href,target:a.target,rel:a.rel,w:a.getBoundingClientRect().width}));`);
  // Outbound links must open in a new tab and give the destination nothing.
  // The in-page jump link is a different animal: it stays on the page, so it
  // wants no target and needs no rel.
  const outbound = links.filter(l => /^https:/.test(l.href));
  const inpage = links.filter(l => !/^https:/.test(l.href));
  chk('the three outbound links are safe, the in-page link stays in the page',
    outbound.length === 3 &&
    outbound.some(l => l.href === 'https://github.com/seQRets/My-Seed-Phrase') &&
    outbound.some(l => l.href === 'https://coinos.io/seQRets/receive') &&
    outbound.some(l => l.href === 'https://mypassphrase.app/') &&
    outbound.every(l => l.target === '_blank' && /noopener/.test(l.rel) && /noreferrer/.test(l.rel) && l.w > 40) &&
    inpage.length === 1 && /#inputcard$/.test(inpage[0].href) && inpage[0].target === '',
    `${outbound.length} outbound, ${inpage.length} in-page`);

  await p.evaluate(`${HELPERS} $('in').value='abandon '.repeat(11).trim(); $('go').click();
    await wait(()=>$('out').style.display==='block'&&document.querySelectorAll('#grid .w').length===128);
    $('test').click(); await wait(()=>$('testsum')&&$('testsum').textContent.trim());
    document.querySelectorAll('#testbody details').forEach(d=>d.open=true); return 1;`);
  // 320 is the narrowest phone, 390 the common one, 1440 a desktop. The four
  // widths between them never once failed alone — they only ever repeated what
  // these three already said, at seven times the runtime.
  for (const w of [320, 390, 1440]) {
    await p.setViewport(w, 900);
    const m = await p.evaluate(`
      const de=document.documentElement, vw=de.clientWidth, bad=[];
      document.querySelectorAll('body *').forEach(el=>{const r=el.getBoundingClientRect();
        if(!r.width&&!r.height)return;
        if(r.right>vw+1||r.left<-1){let q=el.parentElement,sc=false;
          while(q&&q!==document.body){const o=getComputedStyle(q).overflowX;
            if(o==='auto'||o==='scroll'){sc=true;break}q=q.parentElement}
          if(!sc)bad.push(el.tagName+'.'+String(el.className).slice(0,24))}});
      const chips=[...document.querySelectorAll('#grid .w')];
      return {vw,sw:de.scrollWidth,over:bad.length,bad:bad.slice(0,3),
        cols:new Set(chips.map(c=>Math.round(c.getBoundingClientRect().left))).size,
        narrowest:Math.min(...chips.map(c=>Math.round(c.getBoundingClientRect().width))),
        wrapped:chips.filter(c=>c.getBoundingClientRect().height>44).length};`);
    // 132px is what a chip needs for the longest word plus the highest index
    chk(`${String(w).padStart(4)}px — no sideways scroll, ${m.cols} column(s), words fit on one line`,
      m.sw <= m.vw && m.over === 0 && m.narrowest >= 132 && m.wrapped === 0,
      `scrollWidth ${m.sw} of ${m.vw}, narrowest chip ${m.narrowest}px, ${m.wrapped} wrapped ${m.bad.join(',')}`);
  }
  await p.setViewport(1280, 900);
  const order = await p.evaluate(`
    const chips=[...document.querySelectorAll('#grid .w')].map(e=>e.firstChild.textContent);
    return { display:getComputedStyle(document.getElementById('grid')).display,
             sorted:JSON.stringify(chips)===JSON.stringify([...chips].sort((a,b)=>IDX.get(a)-IDX.get(b))) };`);
  chk('candidates read top-to-bottom (columns, not a grid)',
    order.sorted && order.display === 'block', JSON.stringify(order));
  chk('no console errors', p.logs.filter(l => /error/i.test(l.type)).length === 0);
  await p.close();
}

/* ---- calibration ------------------------------------------------------ */
// Four things the page does to keep a phrase from outliving the moment it is
// on screen. None of them is visible in the ordinary flow, so none of them is
// covered above, and all four are the kind of thing a later edit removes
// without noticing.
async function guardChecks(browser, base) {
  console.log('\n--- keeping the phrase from outliving the moment ---');
  const p = await openPage(browser, base + '/index.html');
  // a real download would block a headless run
  await p.S('Page.setDownloadBehavior', { behavior: 'deny' }).catch(() => {});

  let r = await p.evaluate(`${HELPERS} return {
    framed: document.documentElement.hasAttribute('data-framed'),
    mainShown: getComputedStyle(document.querySelector('main')).display !== 'none',
    warnHidden: getComputedStyle($('framed')).display === 'none'};`);
  chk('the frame guard leaves the real page alone',
      !r.framed && r.mainShown && r.warnHidden, JSON.stringify(r));

  // Opening a path unfolds a tall body. Without a scroll the buttons stay put
  // and the box they fill drops below the fold, so the two halves of the job
  // end up in different screenfuls.
  await p.setViewport(1280, 1000);
  r = await p.evaluate(`${HELPERS}
    const out=[];
    for (const el of [...document.querySelectorAll('#paths .path')]) {
      scrollTo(0,0);
      await new Promise(z=>setTimeout(z,400));
      const before=Math.round(scrollY);
      el.querySelector('summary').click();
      await new Promise(z=>setTimeout(z,1200));
      const box=$('in').getBoundingClientRect();
      out.push({moved:Math.round(scrollY)>before,
        top:Math.round(el.getBoundingClientRect().top),
        boxInView: box.top<innerHeight && box.bottom>0});
    }
    return out;`);
  chk('opening a path scrolls it to the top, with the seed box in view',
      Array.isArray(r) && r.length === 2
      && r.every(x => x.moved && x.top >= 0 && x.top <= 60 && x.boxInView),
      JSON.stringify(r));
  await p.setViewport(1280, 900);

  await p.goto(base + '/framer');
  await new Promise(z => setTimeout(z, 700));
  r = await p.evaluate(`${HELPERS} const d=$('f').contentDocument;
    await wait(()=>d.getElementById('framed'));
    const g=d.getElementById('framed');
    return {framed:d.documentElement.hasAttribute('data-framed'),
      toolHidden:getComputedStyle(d.querySelector('main')).display==='none',
      warnShown:getComputedStyle(g).display!=='none',
      saysAddress:g.textContent.indexOf('myseedphrase.app')>-1,
      anchors:g.querySelectorAll('a').length};`);
  chk('framed by another site: the tool is withheld, the address given as text',
      r.framed && r.toolHidden && r.warnShown && r.saysAddress && r.anchors === 0,
      JSON.stringify(r));

  await p.goto(base + '/framer?sandbox');
  await new Promise(z => setTimeout(z, 1200));
  let sb = null;
  for (const sid of [...p.childSessions]) {
    try {
      const probe = await p.evalIn(`return {isFrame:window.top!==window.self,
        hasGuard:!!document.getElementById('framed')};`, sid);
      if (!probe || !probe.isFrame || !probe.hasGuard) continue;
      sb = await p.evalIn(`return {
        framed:document.documentElement.hasAttribute('data-framed'),
        toolHidden:getComputedStyle(document.querySelector('main')).display==='none',
        warnShown:getComputedStyle(document.getElementById('framed')).display!=='none'};`, sid);
      break;
    } catch (e) { /* that session is gone or not ours */ }
  }
  chk('a sandboxed frame cannot dodge the guard either',
      !!sb && sb.framed && sb.toolHidden && sb.warnShown,
      sb ? JSON.stringify(sb) : 'no sandboxed frame session found');

  // Hiding is presentation, and a later edit to one selector could undo it
  // silently. Defeat the CSS the way such an edit would — put the tool back on
  // screen — and the entry points must still refuse to do anything.
  await p.goto(base + '/framer');
  await new Promise(z => setTimeout(z, 700));
  r = await p.evaluate(`${HELPERS}
    const d=$('f').contentDocument;
    await wait(()=>d.getElementById('genfull'));
    const st=d.createElement('style');
    st.textContent='html[data-framed] main{display:block !important}'
                  +'html[data-framed] #framed{display:none !important}';
    d.head.appendChild(st);
    const cssDefeated=getComputedStyle(d.querySelector('main')).display!=='none';
    // neither generator may put anything in the box
    d.getElementById('genlen').value='11';
    d.getElementById('genfull').click();
    d.getElementById('gen').click();
    await new Promise(z=>setTimeout(z,500));
    const boxAfterGenerate=d.getElementById('in').value;
    // nor may words typed by hand produce any endings
    d.getElementById('in').value='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon';
    d.getElementById('go').click();
    d.getElementById('rand').click();
    await new Promise(z=>setTimeout(z,700));
    return {cssDefeated, stillFramed:d.documentElement.hasAttribute('data-framed'),
      boxAfterGenerate,
      wordsAfterCalculate:d.getElementById('in').value.split(/[ ]+/).filter(Boolean).length,
      chips:d.querySelectorAll('#grid .w').length,
      qrOpen:d.getElementById('qrveil').style.display==='flex'};`);
  chk('the guard is structural: with its CSS defeated, a framed tool still refuses',
      r.cssDefeated && r.stillFramed && r.boxAfterGenerate === ''
      && r.chips === 0 && r.wordsAfterCalculate === 11 && !r.qrOpen,
      JSON.stringify(r));

  await p.goto(base + '/index.html');
  r = await p.evaluate(`${HELPERS}
    $('genlen').value='11'; $('genfull').click();
    if(!await wait(()=>$('in').classList.contains('shield'))) return {err:'genfull timeout'};
    $('peek').click();
    const revealed=!$('in').classList.contains('shield'), seed=$('in').value;
    $('inqr').click();
    if(!await wait(()=>$('qrcanvas').width>1)) return {err:'QR never drew'};
    dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}));
    await wait(()=>$('in').classList.contains('shield'));
    return {revealed, reblurred:$('in').classList.contains('shield'),
      seedKept:$('in').value===seed, qrClosed:$('qrveil').style.display==='none',
      canvasWiped:$('qrcanvas').width===1};`);
  chk('coming back to the page re-blurs the seed and wipes the QR', !r.err
      && r.revealed && r.reblurred && r.seedKept && r.qrClosed && r.canvasWiped,
      r.err || JSON.stringify(r));

  r = await p.evaluate(`${HELPERS} $('clr').click();
    $('in').value='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon';
    dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}));
    // read the verdict here, before the box is cleared for the next case
    const kept=$('in').value.trim().split(/[ ]+/).length===11;
    const blurred=$('in').classList.contains('shield');
    $('clr').click();
    dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}));
    return {kept, blurred,
      emptyLeftAlone:$('in').value==='' && !$('in').classList.contains('shield')};`);
  chk('a half-typed phrase is blurred on return, never erased',
      r.kept && r.blurred && r.emptyLeftAlone, JSON.stringify(r));

  r = await p.evaluate(`${HELPERS} $('clr').click();
    $('genlen').value='11'; $('genfull').click();
    if(!await wait(()=>$('in').classList.contains('shield'))) return {err:'genfull timeout'};
    $('inqr').click(); $('qrclose').click();          // close mid-open
    await new Promise(z=>setTimeout(z,900));
    const afterClose={veil:$('qrveil').style.display, canvas:$('qrcanvas').width};
    $('inqr').click();
    dispatchEvent(new KeyboardEvent('keydown',{key:'Escape'}));   // escape mid-open
    await new Promise(z=>setTimeout(z,900));
    const afterEsc={veil:$('qrveil').style.display, canvas:$('qrcanvas').width};
    $('inqr').click();
    const drew=await wait(()=>$('qrcanvas').width>1);
    return {afterClose, afterEsc, stillWorks:!!drew && $('qrcanvas').width===264};`);
  chk('closing mid-open stays closed, and the QR still opens afterwards', !r.err
      && r.afterClose.veil === 'none' && r.afterClose.canvas === 1
      && r.afterEsc.veil === 'none' && r.afterEsc.canvas === 1 && r.stillWorks,
      r.err || JSON.stringify(r));

  r = await p.evaluate(`${HELPERS}
    const before=$('qrdlhint').style.display;
    const dim=getComputedStyle($('qrdlhint')).color;
    $('qrdl').click();                                  // first press: warn only
    if(!await wait(()=>$('qrdlhint').style.display==='block', 4000))
      return {err:'no warning on the first press'};
    const warn={msg:$('qrdlmsg').textContent, red:getComputedStyle($('qrdlhint')).color,
      isWarnClass:$('qrdlhint').classList.contains('dlwarn'),
      askedToConfirm:$('qrdlgo').style.display!=='none'};
    $('qrdlgo').click();                                // second press: write it
    if(!await wait(()=>/Saved as/.test($('qrdlmsg').textContent), 4000))
      return {err:'the confirm press never saved'};
    const saved={msg:$('qrdlmsg').textContent, buttonGone:$('qrdlgo').style.display==='none'};
    $('qrclose').click();
    return {before, dim, warn, saved,
      clearedOnClose:$('qrdlhint').style.display==='none'
        && !$('qrdlhint').classList.contains('dlwarn') && $('qrdlmsg').textContent===''};`);
  chk('saving warns in red first, and writes nothing on that press', !r.err
      && r.before === 'none' && r.warn.isWarnClass && r.warn.red !== r.dim
      && r.warn.askedToConfirm && !/Saved as/.test(r.warn.msg)
      && /seedqr\.png/.test(r.warn.msg) && /is the seed/.test(r.warn.msg)
      && /iCloud|OneDrive/.test(r.warn.msg),
      r.err || `${r.warn && r.warn.red} vs dim ${r.dim}`);
  chk('only the second, deliberate press writes the file — and closing forgets it',
      !r.err && r.saved.buttonGone && /seedqr\.png/.test(r.saved.msg)
      && r.clearedOnClose, r.err || JSON.stringify(r.saved));

  // A real scare: a phone camera shows a SeedQR's 48 digits and reports no
  // words, which reads exactly like a broken export. The panel has to say so
  // before someone concludes the tool lost their seed.
  r = await p.evaluate(`${HELPERS}
    const d=document.querySelector('.qrcard details');
    // NB: this string is a template literal, so a lone backslash is eaten -
    // /\s+/ here would strip the letter s. Double it.
    const t=d ? d.textContent.replace(/\\s+/g,' ') : '';
    return {found:!!d, numbers:/numbers/i.test(t), digits:/digits/i.test(t),
      count48:/48/.test(t), areYourWords:/are your words/i.test(t)};`);
  chk('the panel warns that a phone shows numbers, and that they are the words',
      r.found && r.numbers && r.digits && r.count48 && r.areYourWords,
      JSON.stringify(r));

  // The card grows when the warning shows and the disclosure opens. A centred
  // flex item taller than its parent has its top clipped with no way to reach
  // it, which would put the close button off a phone screen.
  await p.setViewport(375, 667);
  r = await p.evaluate(`${HELPERS}
    $('clr').click();
    $('genlen').value='11'; $('genfull').click();
    if(!await wait(()=>$('in').classList.contains('shield'))) return {err:'genfull timeout'};
    $('inqr').click();
    if(!await wait(()=>$('qrcanvas').width>1)) return {err:'QR never drew'};
    $('qrdl').click();
    document.querySelector('.qrcard details').open = true;
    await new Promise(z=>setTimeout(z,250));
    const veil=$('qrveil'), card=document.querySelector('.qrcard');
    const head=document.querySelector('.qrhead').getBoundingClientRect();
    return {tall: card.getBoundingClientRect().height > innerHeight,
      headOnScreen: head.top >= 0,
      closeReachable: $('qrclose').getBoundingClientRect().top >= 0,
      scrollable: veil.scrollHeight > veil.clientHeight};`);
  chk('a card taller than a phone screen can still be scrolled to its close button',
      !r.err && r.tall && r.headOnScreen && r.closeReachable && r.scrollable,
      r.err || JSON.stringify(r));
  await p.setViewport(1280, 900);

  // File → Save Page As serializes the live DOM — the shield class and the
  // visible controls — but not the seed, so a snapshot saved mid-use used to
  // wake up smudging its own placeholder text beside an empty box. The page
  // must heal that state the moment it opens.
  await p.goto(base + '/snapshot');
  r = await p.evaluate(`${HELPERS}
    if(!await wait(()=>document.readyState==='complete')) return {err:'load timeout'};
    const doc = document.documentElement.outerHTML;
    return { healed: !$('in').classList.contains('shield'),
      wrapCleared: !$('inwrap').classList.contains('on'),
      controlsHidden: $('inctl').style.display==='none',
      placeholderCrisp: getComputedStyle($('in'),'::placeholder').textShadow==='none',
      // the derived furniture must be gone from view...
      endingsHidden: $('out').style.display==='none',
      gridEmpty: document.querySelectorAll('#grid .w').length===0,
      statusEmpty: $('st').textContent==='',
      noteEmpty: $('randnote').textContent==='',
      meterHidden: $('meter').style.display==='none',
      // ...and all three secrets must be gone from the FILE, not merely hidden:
      // the note naming the ending, the marked chip that IS that ending, and
      // the fingerprint
      wordScrubbed: !doc.includes(${JSON.stringify(SNAP_NOTE)}),
      chipScrubbed: !doc.includes(${JSON.stringify(SNAP_CHIP)}),
      rollqScrubbed: !doc.includes(${JSON.stringify(SNAP_ROLLQ)}),
      rollCountScrubbed: !/id="dicecount"[^>]*>73 of 100/.test(doc),
      fpScrubbed: !doc.includes(${JSON.stringify(SNAP_FP)}) };`);
  chk('a copy saved mid-use heals its snapshot state on open', !r.err
      && r.healed && r.wrapCleared && r.controlsHidden && r.placeholderCrisp
      && r.endingsHidden && r.gridEmpty && r.statusEmpty && r.noteEmpty
      && r.meterHidden && r.rollCountScrubbed,
      r.err || JSON.stringify(r));
  chk('a saved copy sheds its seed word, fingerprint and dice read-out when opened',
      !r.err && r.wordScrubbed && r.chipScrubbed && r.fpScrubbed && r.rollqScrubbed,
      r.err || `note left: ${!r.wordScrubbed}, chosen chip left: ${!r.chipScrubbed}, `
             + `fingerprint left: ${!r.fpScrubbed}, dice read-out left: ${!r.rollqScrubbed}`);

  await p.close();
}

async function diceChecks(browser, base) {
  console.log('\n--- rolling your own randomness ---');
  const p = await openPage(browser, base + '/index.html');
  const want12 = diceMnemonic(ROLLS51, 12).join(' ');
  const want24 = diceMnemonic(ROLLS100, 24).join(' ');
  let r;

  // 1. the maths, against an implementation that shares no code with the page
  r = await p.evaluate(`${HELPERS}
    const g = async (rolls, target) => {
      $('dicepath').open = true;
      $('rolls').value = ''; $('rolls').dispatchEvent(new Event('input'));
      [...document.querySelectorAll('#dicesizes .size')]
        .find(b => +b.dataset.w === target).click();
      $('rolls').value = rolls; $('rolls').dispatchEvent(new Event('input'));
      if (!await wait(() => !$('dicego').disabled)) return { err: 'button never enabled' };
      $('dicego').click();
      if (!await wait(() => $('in').value.trim().split(/[ ]+/).length === target)) return { err: 'no seed' };
      return { seed: $('in').value.trim(), label: $('dicego').textContent };
    };
    const a = await g(${JSON.stringify(ROLLS51)}, 12);
    const b = await g(${JSON.stringify(ROLLS100)}, 24);
    return { a, b };`);
  chk('dice make the seed an independent implementation makes, at 12 and 24 words',
      !r.a.err && !r.b.err && r.a.seed === want12 && r.b.seed === want24,
      r.a.err || r.b.err || `12w ${r.a.seed === want12}, 24w ${r.b.seed === want24}`);

  // 2. rolls you have not made cannot buy a longer seed
  r = await p.evaluate(`${HELPERS}
    $('dicepath').open = true;
    [...document.querySelectorAll('#dicesizes .size')].find(b => b.dataset.w === '24').click();
    const at = n => { $('rolls').value = ${JSON.stringify(ROLLS100)}.slice(0, n);
      $('rolls').dispatchEvent(new Event('input'));
      return { label: $('dicego').textContent, off: $('dicego').disabled,
               ready: [...document.querySelectorAll('#dicesizes .size.ready')].map(b => b.dataset.w) } };
    const sizes = { r49: at(49), r51: at(51), r75: at(75), r100: at(100) };
    // and the press must honour the label: 51 rolls with 24 words asked for
    // still makes 12, or the gate is only cosmetic
    // clear first: an earlier check leaves a 24-word seed in the box, and
    // waiting for "more than one word" would read that instead of this press
    $('clr').click();
    at(51);
    $('dicego').click();
    await wait(() => $('in').value.trim().split(/[ ]+/).filter(Boolean).length >= 12);
    sizes.madeAt51 = $('in').value.trim().split(/[ ]+/).filter(Boolean).length;
    return sizes;`);
  chk('the rolls you have decide the sizes offered, never the size you asked for',
      r.r49.off && r.r49.ready.length === 0
      && !r.r51.off && r.r51.label === 'Make a 12-word seed' && r.r51.ready.join() === '12'
      && r.r75.label === 'Make a 18-word seed' && r.r75.ready.join() === '12,15,18'
      && r.r100.label === 'Make a 24-word seed' && r.r100.ready.join() === '12,15,18,21,24'
      && r.madeAt51 === 12,
      JSON.stringify(r));

  // 3. it is a finished seed, born hidden, with no ending left to choose
  r = await p.evaluate(`${HELPERS}
    $('clr').click();
    $('dicepath').open = true;
    [...document.querySelectorAll('#dicesizes .size')].find(b => b.dataset.w === '12').click();
    $('rolls').value = ${JSON.stringify(ROLLS51)}; $('rolls').dispatchEvent(new Event('input'));
    if (!await wait(() => !$('dicego').disabled)) return { err: 'button never enabled' };
    $('dicego').click();
    if (!await wait(() => $('in').value.trim().split(/[ ]+/).length === 12)) return { err: 'no seed' };
    await wait(() => $('infpv').textContent !== '…');
    return { hidden: $('in').classList.contains('shield'),
             verified: $('in').classList.contains('okseed'),
             endingsHidden: $('out').style.display === 'none',
             chips: document.querySelectorAll('#grid .w').length,
             fp: $('infpv').textContent, qr: $('inqr').style.display !== 'none' };`);
  chk('a dice seed arrives hidden and complete, with no ending left to pick', !r.err
      && r.hidden && r.verified && r.endingsHidden && r.chips === 0 && r.qr
      && /^[0-9a-f]{8}$/.test(r.fp), r.err || JSON.stringify(r));

  // 4. the gate: patterned rolls write nothing on the first press
  r = await p.evaluate(`${HELPERS}
    $('clr').click();
    $('dicepath').open = true;
    $('rolls').value = '4'.repeat(50); $('rolls').dispatchEvent(new Event('input'));
    const live = $('dicequal').textContent;
    if (!await wait(() => !$('dicego').disabled)) return { err: 'button never enabled' };
    $('dicego').click();
    await new Promise(r => setTimeout(r, 200));
    const first = { box: $('in').value, warn: $('diceweak').style.display,
                    anyway: $('diceanyway').style.display,
                    focused: document.activeElement === $('diceanyway') };
    $('rolls').value = '4'.repeat(51); $('rolls').dispatchEvent(new Event('input'));
    const afterEdit = { warn: $('diceweak').style.display, anyway: $('diceanyway').style.display };
    $('dicego').click(); await new Promise(r => setTimeout(r, 200));
    $('diceanyway').click();
    if (!await wait(() => $('in').value.trim().split(/[ ]+/).length === 12)) return { err: 'second press did nothing' };
    return { live, first, afterEdit, made: $('in').value.trim().split(/[ ]+/).length };`);
  chk('faked rolls are named, write nothing on the first press, and need a second button',
      !r.err && /do not look rolled/.test(r.live) && r.first.box === ''
      && r.first.warn === 'block' && r.first.anyway === 'block' && r.first.focused === false
      && r.afterEdit.warn === 'none' && r.afterEdit.anyway === 'none' && r.made === 12,
      r.err || JSON.stringify(r));

  // 5. and it does not cry wolf on rolls that were actually rolled
  r = await p.evaluate(`${HELPERS}
    const rnd = n => { let s = ''; const b = new Uint8Array(n * 3); crypto.getRandomValues(b);
      let i = 0; while (s.length < n) { const v = b[i++ % b.length]; if (v < 252) s += (1 + v % 6) } return s };
    const out = {};
    for (const n of [50, 75, 100]) { let bad = 0;
      for (let i = 0; i < 1500; i++) if (assessRolls(rnd(n)).flags.length) bad++;
      out[n] = bad / 1500 * 100 }
    return out;`);
  chk('the roll-quality check does not cry wolf on genuine rolls',
      Math.max(...Object.values(r)) < 2,
      Object.entries(r).map(([n, v]) => `${n}: ${v.toFixed(2)}%`).join(', '));

  // 6. every faked pattern is still caught
  r = await p.evaluate(`${HELPERS}
    const fakes = { allOne: '4'.repeat(100), alternating: '12'.repeat(50),
      countUp: '123456'.repeat(17).slice(0, 100), countDown: '654321'.repeat(17).slice(0, 100),
      threeFaces: '123'.repeat(34).slice(0, 100).split('').sort(() => 0.4).join(''),
      block: '415263142536'.repeat(9).slice(0, 100) };
    const out = {};
    for (const k in fakes) out[k] = assessRolls(fakes[k]).flags.length > 0;
    return out;`);
  chk('every faked rolling pattern is still caught',
      Object.values(r).every(Boolean), JSON.stringify(r));

  // 7. the two routes are a choice, not a checklist
  r = await p.evaluate(`${HELPERS}
    const A = $('apppath'), D = $('dicepath');
    A.open = false; D.open = false;
    const atLoad = [A.open, D.open];
    A.querySelector('.pathbtn').click(); await new Promise(r => setTimeout(r, 60));
    const afterGenerate = [A.open, D.open];
    D.querySelector('.pathbtn').click(); await new Promise(r => setTimeout(r, 60));
    const afterRoll = [A.open, D.open];
    return { atLoad, afterGenerate, afterRoll,
      genInApp: A.contains($('genfull')), findInApp: A.contains($('go')),
      rollsInDice: D.contains($('rolls')), boxOutside: !A.contains($('in')) && !D.contains($('in')),
      labels: [...document.querySelectorAll('.pathbtn')].map(b => b.textContent) };`);
  chk('the two routes open one at a time, and each holds its own controls',
      r.atLoad.join() === 'false,false' && r.afterGenerate.join() === 'true,false'
      && r.afterRoll.join() === 'false,true' && r.genInApp && r.findInApp
      && r.rollsInDice && r.boxOutside && r.labels.join() === 'Generate,Roll',
      JSON.stringify(r));

  // 8. the heading survives a phone. A fixed-width button beside a flexible
  // title collapsed it to one word per line at 320px, which overflowed nothing
  // and so passed every check there was.
  await p.setViewport(320, 700);
  r = await p.evaluate(`${HELPERS}
    $('apppath').open = false; $('dicepath').open = false;
    await new Promise(r => setTimeout(r, 120));
    return [...document.querySelectorAll('.pathtitle')].map(e => {
      const s = getComputedStyle(e), h = e.getBoundingClientRect().height;
      return { w: Math.round(e.getBoundingClientRect().width),
               lines: Math.round(h / parseFloat(s.lineHeight || 20)) } });`);
  chk('path headings still read on a 320px screen', r.every(t => t.w >= 120 && t.lines <= 3),
      JSON.stringify(r));
  await p.setViewport(1280, 900);

  await p.close();
}

async function calibrate(browser, fileUrl) {
  console.log('\n--- strength read-out calibration (4,000 draws per length) ---');
  const p = await openPage(browser, fileUrl);
  const r = await p.evaluate(`
    const out={false_alarms:{},patterns:{}};
    for (const L of [11,14,17,20,23]) {
      let flagged=0;
      for (let i=0;i<4000;i++) if (assess(randomWords(L)).flags.length) flagged++;
      out.false_alarms[L]=+(flagged/4000*100).toFixed(3);
    }
    const at=i=>WORDS[i];
    const cases={
      'identical x11':Array(11).fill('abandon'),
      'identical x23':Array(23).fill('zoo'),
      'two alternating':Array.from({length:11},(_,i)=>i%2?'zoo':'abandon'),
      'wordlist order':Array.from({length:11},(_,i)=>at(i*37)),
      'reverse order':Array.from({length:11},(_,i)=>at(i*37)).reverse(),
      'narrow slice':Array.from({length:11},(_,i)=>at(100+i*7)),
      'one first letter':WORDS.filter(w=>w[0]==='s').slice(0,11),
      'first 11 of list':WORDS.slice(0,11),
      'consecutive run':WORDS.slice(900,923),
    };
    for (const [k,v] of Object.entries(cases)) {
      const a=assess(v);
      out.patterns[k]={caught:a.flags.length>0,bits:Math.round(a.bits),ceiling:a.ceiling};
    }
    return out;`);
  console.log('  false alarms on genuine random draws — these should stay near zero:');
  for (const [L, pct] of Object.entries(r.false_alarms))
    console.log(`    ${String(L).padStart(2)} words: ${String(pct).padStart(6)}%`);
  console.log('  hand-picking patterns — every one must be caught:');
  let missed = 0;
  for (const [k, v] of Object.entries(r.patterns)) {
    if (!v.caught) missed++;
    console.log(`    ${v.caught ? 'caught ' : 'MISSED!'} ${k.padEnd(18)} ${v.bits}/${v.ceiling} bits`);
  }
  chk('every hand-picking pattern is still caught', missed === 0, `${missed} missed`);
  const worst = Math.max(...Object.values(r.false_alarms));
  chk('false alarms stay under 2% at every length', worst < 2, `worst ${worst}%`);
  await p.close();
}

/* ---- run -------------------------------------------------------------- */
(async () => {
  const bin = findChrome();
  if (!bin) {
    console.error('Could not find Chrome. Install it, or set CHROME to the binary.');
    process.exit(2);
  }
  sourceChecks();

  const server = http.createServer((req, res) => {
    // two synthetic pages: one that frames the tool the way an attacker would,
    // and one to navigate away to so the back button can bring the tool back
    if (req.url.startsWith('/framer')) {
      const sandbox = req.url.includes('sandbox') ? ' sandbox="allow-scripts"' : '';
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`<!doctype html><title>not this site</title><body style="margin:0">
        <h1>Totally Legit Wallet Helper</h1>
        <iframe id="f" src="/index.html" width="900" height="700"${sandbox}></iframe>`);
    }
    if (req.url.startsWith('/away')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end('<!doctype html><title>away</title><body>elsewhere');
    }
    if (req.url.startsWith('/snapshot')) {
      // index.html the way File → Save Page As writes it mid-use: everything
      // the page derived from a seed serialized in, the seed itself not. Three
      // values matter — SNAP_NOTE, which names an actual word of the seed,
      // SNAP_CHIP, which IS that word, marked as the chosen ending, and
      // SNAP_FP, the wallet's master fingerprint. The page must not carry any
      // of them out of a saved file.
      return fs.readFile(path.join(ROOT, 'index.html'), 'utf8', (err, s) => {
        if (err) { res.writeHead(404); return res.end(); }
        // 127 unremarkable endings and the one the reader chose, marked the way
        // clicking a chip marks it — the seed's own final word, sitting in the
        // document under a class that says it was picked.
        const chips = Array.from({length: 127},
          (_, i) => `<div class="w">cand${i}</div>`).join('') + SNAP_CHIP;
        s = s.replace('<textarea id="in"', '<textarea class="shield" id="in"')
             .replace('<div class="inwrap" id="inwrap">', '<div class="inwrap on fp" id="inwrap">')
             .replace('<div class="inctl" id="inctl" style="display:none">',
                      '<div class="inctl" id="inctl" style="display: flex;">')
             .replace('<div class="card" id="out" style="display:none">',
                      '<div class="card" id="out" style="display: block;">')
             .replace('<div class="h on" id="outlbl"></div>',
                      '<div class="h on" id="outlbl">Word 12 · 128 valid endings</div>')
             .replace('<div class="grid" id="grid"></div>',
                      `<div class="grid" id="grid">${chips}</div>`)
             .replace('<div class="hint" id="randnote" style="display:none"></div>',
                      `<div class="hint" id="randnote" style="display: block;">${SNAP_NOTE}</div>`)
             .replace('<div class="status" id="st"></div>',
                      '<div class="status ok" id="st">✓  Complete 12-word seed in the box above.</div>')
             .replace('<b id="infpv">…</b>', `<b id="infpv">${SNAP_FP}</b>`)
             .replace('<div class="infp" id="infp" style="display:none">',
                      '<div class="infp" id="infp" style="display: block;">')
             .replace('<div class="meter" id="meter" style="display:none">',
                      '<div class="meter" id="meter" style="display: block;">')
             .replace('<div class="hint" id="dicequal"></div>',
                      `<div class="hint bad-c" id="dicequal">\u26a0\ufe0e These rolls do not look rolled \u2014 ${SNAP_ROLLQ}.</div>`)
             .replace('<span class="rollnum" id="dicecount">0</span>',
                      '<span class="rollnum" id="dicecount">73 of 100</span>');
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(s);
      });
    }
    const f = path.join(ROOT, req.url === '/' ? 'index.html' : path.normalize(req.url).replace(/^(\.\.[\/\\])+/, ''));
    fs.readFile(f, (err, data) => {
      if (err) { res.writeHead(404); res.end(); return; }
      res.writeHead(200, { 'Content-Type': f.endsWith('.html') ? 'text/html; charset=utf-8' : 'text/plain' });
      res.end(data);
    });
  });
  // port 0: the OS assigns a free one, so this never collides with a dev
  // server someone already has running on the usual port
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const PORT = server.address().port;

  const browser = await launch(bin);
  try {
    const fileUrl = pathToFileURL(PAGE).href;
    await pageChecks(browser, fileUrl, `http://localhost:${PORT}/`);
    await guardChecks(browser, `http://localhost:${PORT}`);
    await diceChecks(browser, `http://localhost:${PORT}`);
    if (process.argv.includes('--calibrate')) await calibrate(browser, fileUrl);
  } finally {
    browser.proc.kill();
    server.close();
  }
  console.log(`\n${fails === 0 ? `all ${count} checks passed` : `${fails} of ${count} checks FAILED`}`);
  process.exit(fails === 0 ? 0 : 1);
})().catch(e => { console.error('\nverify.js could not run:', e.message); process.exit(2); });
