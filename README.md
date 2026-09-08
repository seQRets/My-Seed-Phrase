# My Seed Phrase

Generate a complete BIP-39 seed phrase — from the browser's random number
generator or from your own dice rolls — or find every valid final word for the
words you already have. Complete seeds can be shown as a standard SeedQR for
wallets that scan a seed in.

A single self-contained HTML file. No build step, no dependencies, never touches the internet —
open it and it works, online or off.

**Live:** <https://myseedphrase.app>

## What it does

A chooser at the top offers **two ways to make a seed**, both landing in the
same box: let the app do it, or roll dice yourself. They are collapsed until you
pick one, and opening one closes the other — they are a choice, not a checklist.

The last word of a seed phrase is not a free choice. It has to carry the final
scraps of the phrase's randomness *plus the whole checksum*, which pins it down
to a fixed, small number of possibilities. Give the page the words you have and
it returns every ending that produces a valid phrase.

| Phrase | You supply | Checksum bits | Valid endings |
|-------:|-----------:|--------------:|--------------:|
| 12 | 11 | 4 | 128 |
| 15 | 14 | 5 | 64 |
| 18 | 17 | 6 | 32 |
| 21 | 20 | 7 | 16 |
| 24 | 23 | 8 | 8 |

**Generate complete seed** produces a wallet-ready phrase in one press: it
draws 11, 14, 17, 20 or 23 words from the browser's random number generator,
the one built for security work (`crypto.getRandomValues`), works out every
valid ending, and picks one uniformly. That is standard BIP-39 generation
reached from the other end — for 24 words, 23 uniform words carry 253 bits and
the uniform pick among 8 endings supplies the last 3, the same 256 bits as
"generate the entropy, append the checksum." **Generate partial seed** stops
before the ending, so you can watch the checksum narrow the choices and pick
one yourself.

### Rolling your own randomness

Path 2 is dice. The browser's random number generator is a good one — it is the
CSPRNG your operating system provides — and nothing here suggests otherwise.
What using it does mean is trusting that the copy of this page you are running
is the one that was published. **Dice remove even that question**, because the
randomness is yours rather than the page's.

Pick a target size and the page says how many rolls it needs; the shorter sizes
unlock as the rolls arrive. The button always offers the largest size the rolls
justify, never the size you asked for, because a longer seed made from too few
rolls looks stronger than it is.

| Seed | Rolls needed | Randomness supplied |
|---:|---:|---:|
| 12 words | 50 | 129.2 bits |
| 15 words | 62 | 160.3 bits |
| 18 words | 75 | 193.9 bits |
| 21 words | 87 | 224.9 bits |
| 24 words | 100 | 258.5 bits |

A die has six faces, which is not a power of two, so rolls cannot be mapped to
bits without either bias or discarding draws. The digits are hashed instead:
`SHA-256` of the ASCII rolls, which is the common convention for dice entropy.
The leading bytes become the entropy and the checksum is appended as the
standard specifies. A wallet that derives entropy from dice the same way will
reproduce the same seed from the same rolls, and that some hardware wallets can
import a seed from dice at all is the reason many people want to roll their
own. Note what hashing does *not* do: it spreads the randomness over 256
bits without adding any. Fifty rolls carry 129 bits whether hashed or not,
which is exactly why the longer sizes stay shut until the rolls are there.

**There is no ending to pick in this flow, and that is not an omission.** The
rolls supply every entropy bit, so the final word — which carries the last few
bits *and* the checksum they imply — is already decided. Offering the endings
list here would overwrite those bits with browser randomness and destroy both
the reproducibility and the reason for rolling in the first place.

A longer seed is a **different** seed, not an upgrade: carrying on from 50 rolls
to 100 shares not one word with what came before. The page says so the moment it
could matter.

### The roll-quality check

Rolls can be typed, and typed rolls can be invented. Hashing hides that
completely — `444…` and a real sequence produce output that looks equally
random, so the entropy read-out further down reports a flawless phrase either
way. The only place the difference is still visible is the rolls themselves, so
`assessRolls()` reads them before they are hashed.

It takes the tightest of four upper bounds on the work left to a guesser: how
lopsided the six faces are, the shortest block the whole string repeats, the
distribution of gaps between one roll and the next, and the theoretical ceiling.

| What you type | Reported | Reason given |
|---|---:|---|
| `444444…` | 0 of 129 bits | every roll is the same number |
| `121212…` | 5 of 258 | the same 2 rolls repeat over and over |
| `123456` ×17 | 3 of 258 | the same 6 rolls repeat over and over |
| three faces only | 157 of 258 | only 3 of the six faces ever come up |
| a 12-roll block repeated | 31 of 258 | the same 12 rolls repeat over and over |
| loaded die, 70% sixes | 158 of 258 | one face comes up far more often than the others |

Calibrated the way the entropy meter was, over 4,000 genuine sequences at each
length: false alarms are **0.10% at 50 rolls and 0% at 75 and above**.

Its *flags* gate a generate, never its bit count. Over 50 rolls the count reads
low from sample size alone — genuine rolls measure as little as 0.85 of what the
seed formally needs — so testing it against that requirement would stop honest
rolls at the shortest length every time. Nothing dangerous slips past: for no
flag to fire, all six faces must appear with no repeating block, no run and no
skew, which already puts the count above 0.85 of the ceiling.

Flagged rolls follow the same two-press gate as the download button. The first
press writes nothing: it names what is wrong, gives the honest number, and waits
for a separate *Make it anyway* button that is deliberately not focused. Editing
the rolls withdraws the acknowledgement.

### Shared behaviour

Everything happens in one seed field. Anything the generator produces —
a complete seed or a partial one — lands in the input box **blurred**, so it is
not readable over your shoulder; words you type yourself stay visible, and the
blur state carries through when you complete them. An eye control reveals and
hides, a copy control copies — with the usual warning that the clipboard can be
read by anything running on the machine. The valid endings are listed below
with the picked word marked; clicking a different one swaps the ending in the
box above, and a note beneath the list says so. Editing the box by hand
dismisses the blur and its controls. The seed's **BIP-32 master
fingerprint** (assuming an empty passphrase) appears both under the generated
seed in the input box and beneath the QR, unblurred —
a fingerprint identifies a wallet but cannot open it. After the device scans,
it should show the same eight characters; a mismatch means it read a different
seed.

A third control shows the seed as a **standard SeedQR** — each word's wordlist
position as four digits, concatenated and encoded as a numeric-mode QR, the
format many hardware wallets — SeedSigner, Krux, Jade, Specter DIY and the
Keystone 3 Pro, among others — scan to import a seed without typing it on the
device. The QR opens in a modal, blurred until deliberately
revealed (a QR is readable by any camera in the room, not just the one you
mean), and the drawing is wiped when the modal closes. QR encoding is
`kazuhikoarase/qrcode-generator` (MIT), embedded verbatim — the same embed the
sister project [seQRets/Passphrase](https://github.com/seQRets/Passphrase)
uses. "QR Code" is a registered trademark of DENSO WAVE INCORPORATED.

Click any candidate to assemble the full phrase, or **Pick at random** to have
one chosen for you. That pick uses the same generator, never `Math.random` —
but it only contributes the last few bits (7 for a 12-word phrase, 3 for a
24-word one). The words you supply carry the rest, so a random ending cannot
rescue a badly chosen prefix.

The page opens light for everyone; the toggle at the top right switches to dark
and the choice is remembered in `localStorage`. Your system light/dark setting is
deliberately not consulted: everyone gets the same page until they say otherwise.

## Running it safely — step by step

For any phrase holding real funds: save the page, disconnect, then open it.

The page never sends anything anywhere, and it tells your browser to refuse if
it ever tried — nothing is fetched from the internet at all, not a typeface, not
an image, not a line of code. (In technical terms: a `Content-Security-Policy`
meta tag set to `default-src 'none'`, with one exception — `img-src data:`, which
allows the favicon that is written into the page itself. `data:` is inline, not a
fetch, so no internet source is permitted by any directive.) But that only makes
*this page* safe, not your browser or your computer. A badge at the top tells you
whether you are currently online.

If your phrase holds real money, do not just click the live link and start
typing. Work through this once; it takes about ten minutes.

### First, the part most people get wrong: browser extensions

A browser extension can read everything on every page you open — including the
words you type into this one and any phrase it generates for you. Nothing this
page does stops it. **Nothing any web page can do stops it.** An extension is
part of your browser, not part of the page.

This is not hypothetical. Extensions get sold, get taken over, and get updated
silently. A password manager, an ad blocker, a dark-mode theme, a coupon finder
— any of them can read your seed phrase out of the page.

**Private browsing is not a reliable defence against this**, and the details
differ by browser:

| Browser | Extensions in private windows |
|---|---|
| Chrome / Edge | Off by default, but each extension has an *Allow in Incognito* switch that many people turn on |
| Firefox | Off by default, same per-extension *Run in Private Windows* opt-in |
| **Safari** | **Run in Private Browsing by default** |

So on a Mac, opening a Private Window in Safari gives you no protection from
extensions at all. Use a browser profile that has **no extensions installed**.
That is unconditionally safe; private browsing on top of it is a bonus, not the
control you are relying on.

### Step 1 — Download the file, while still online

Download `myseedphrase.html` from the
[latest release](https://github.com/seQRets/My-Seed-Phrase/releases/latest).
Every release publishes the fingerprint of the file alongside it. Check the one
you downloaded against it before you open it:

```bash
# macOS
shasum -a 256 ~/Downloads/myseedphrase.html

# Linux
sha256sum ~/Downloads/myseedphrase.html
```

```powershell
# Windows (PowerShell)
Get-FileHash $HOME\Downloads\myseedphrase.html -Algorithm SHA256
```

If what you get is not the value published on the release page, stop — do not
open the file.

That tells you the file is the one published. It cannot tell you the published
one is correct; step 5 is what checks that.

### Step 2 — Get a browser with nothing installed in it

Pick whichever is easier. Do this **before** you disconnect.

- **A fresh profile in a browser you already have** (no download needed):
  - Chrome/Edge: profile icon, top right → **Add** → *Continue without an account*
  - Firefox: type `about:profiles` in the address bar → **Create a New Profile**
- **Or a second browser** you do not use day to day — install Firefox if you
  normally use Chrome, or vice versa.

Either way you get a browser with zero extensions and no sign-in. Do not sign
in to it, and do not install anything into it.

### Step 3 — Disconnect the computer

- **macOS:** Control Centre → Wi-Fi **off**. Unplug any Ethernet or dock cable.
- **Windows:** Action Centre → **Airplane mode** on. Unplug Ethernet.
- **Linux:** the connection menu → turn networking off, or `nmcli networking off`

Turn off phone tethering and Bluetooth too, if you use them.

### Step 4 — Open the file

Open a private window in the extension-free browser — <kbd>Cmd/Ctrl</kbd> +
<kbd>Shift</kbd> + <kbd>N</kbd> in Chrome, Edge and Safari, <kbd>Cmd/Ctrl</kbd>
+ <kbd>Shift</kbd> + <kbd>P</kbd> in Firefox — then drag `myseedphrase.html` onto the
window, or press <kbd>Cmd/Ctrl</kbd> + <kbd>O</kbd> and pick it.

### Step 5 — Let the page confirm your setup

Two checks before you type anything real:

1. The badge near the top should read **"Offline — safe to generate"** in green. If
   it still says *Online*, something is still connected — go back to step 3.
2. Press **Verify this page**. It must say **15 of 15 checks passed**. That
   confirms the calculator gets the right answer on example phrases whose
   correct answers are published in the BIP-39 standard, and that its built-in
   word list has not been altered. It checks the *page* — it can tell you
   nothing about your computer.

Both work with no internet. Everything on the page does.

### Step 6 — When you are finished

- **Do not use the copy buttons** for a real phrase. Write it down by hand.
- Close the private window, then **quit the browser completely**
  (<kbd>Cmd</kbd> + <kbd>Q</kbd> on macOS). Closing a tab does not clear memory;
  quitting does.
- Reconnect only after the browser has fully quit.
- Do not screenshot the phrase. Screenshots sync to the cloud.

## What this page cannot protect you from

Honest limits, none of which are fixable in a web page:

- **Your clipboard.** Copying a phrase makes it readable by every program running
  on your computer. Apps that keep a clipboard history save their own copy to
  disk, and a Mac passes the clipboard to your iPhone and iPad. The page warns
  you at the point of use. Write it down by hand.
- **Browser extensions.** Nothing a web page can do keeps an extension out. Any
  extension allowed to run on a page can read a generated phrase straight off it.
- **Memory.** A web page cannot reliably erase what it has held. The phrase stays
  in the page, in the text box's undo history, and in the browser's memory until
  the tab is closed — and possibly in a file on disk, if your computer ran short
  of memory and parked some of it there.
- **Your dice rolls.** The numbers are the seed one step earlier: anyone who has
  them can work out every word, on any computer, for ever. The page gives them
  the same blur the seed box gets and clears everything worked out from them,
  but the paper you rolled onto is outside its reach. Destroy it once the words
  are written down and checked.
- **A copy you save while a phrase is on screen.** File → Save Page As writes
  what is on the screen to disk — including the ending word this page chose and
  your wallet's fingerprint. Opening that file again clears both, but a backup, a
  cloud sync or a text editor reads the file, not the page. Save the page
  *before* you generate anything, never after.
- **A hosted copy.** Loading this over the web means trusting whatever is served
  to you on that visit. Download the file, check it, and run it offline for
  anything real.
- **The machine itself.** An offline page on a compromised computer is not safe.

## Verify before you trust it

Don't take the above on faith. Two checks, both quick:

**1. Press "Verify this page".** It works out the endings for nine example
phrases whose correct answers are published in the BIP-39 standard, and confirms
this page produces each one — with the right number of options and no
duplicates. It then re-derives a seed from a fixed dice roll sequence and checks
it against the checksum maths above, hashes the built-in word list and compares
it against the official file, and checks that a real cryptographic RNG is
present. It should read **15 of 15 checks passed**.

By default it shows six lines — the calculations, the phrases it generates, the
fingerprint derivation, seeds made from dice, the word list, the random number
generator — each either pass or fail. *Show all 15 checks* expands the full
breakdown for anyone who wants it, and opens by itself if anything failed.

The dice check is one you can reproduce yourself. The vector is `123456`
repeated nine times, and its entropy is a plain SHA-256 of those digits:

```bash
printf "123456%.0s" {1..9} | shasum -a 256
# edceb2d86ed94b3b67b707e8721ca00fd0d2fc48fe77bd51f04c07c97abb2413
```

Feed those first 16 bytes to any BIP-39 tool and you get the twelve words this
page must produce. Unlike the randomness — which no page can prove honest about
itself — the dice route is deterministic, so it can be pinned to a vector, and
it is.

That wordlist check is the one verification that survives someone tampering with
a hosted copy: swapping a single word in the embedded list drops the result to
14 of 15 and prints a different hash, and lower the more the example phrases
lean on that word — 13 of 15 for `about`, 9 of 15 for `abandon`.

The tenth check is a regression test. A tempting way to write this calculation
is to compare `idx.toString(2)` against a zero-padded 11-bit string —
JavaScript drops leading zeros, so only indices ≥ 1024 ever produce an
11-character string, every word before `length` (index 1024) silently becomes
unreachable, and you are shown half the real answers, all from the back of the
wordlist. "Verify this page" checks that results reach below index 1024.

**2. Check the wordlist.** The embedded list is the official BIP-39 English
wordlist, verbatim:

```
curl -s https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt | shasum -a 256
# 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda
```

Hashing uses the browser's native `crypto.subtle` — no hand-rolled SHA-256. The
master fingerprint shown under the SeedQR needs two primitives the browser does
not provide, secp256k1 and RIPEMD-160; both are implemented in the file — the
one place it rolls its own — and **Verify this page** holds them to the
published test vectors, including BIP-32 test vector 1 and the all-zeros
mnemonic's well-known fingerprint `73c5da0a`.

## The entropy meter

Below the input box is a read-out — labelled *How hard these words are to guess*
— of how much entropy your words carry.

**It cannot measure entropy directly, and neither can anything else.** Entropy
is a property of the *process* that chose the words, not of the words
themselves — a genuine random draw can look terrible, and a hand-picked phrase
can look fine. Anything claiming to score the randomness of a specific string
is lying to you.

What it does instead is look for the fingerprints of hand-picking, and ask: if
an attacker noticed this pattern and searched only phrases matching it, how
much work would be left? It checks for words in wordlist order, repetition
beyond what chance explains, words drawn from one narrow stretch of the list,
too few distinct first letters, and neighbouring words. The result is an *upper
bound* on your entropy — never a proof that it is high.

Calibration, measured over 4,000 trials per phrase length:

| | 11 | 14 | 17 | 20 | 23 words |
|---|---|---|---|---|---|
| False alarms on genuine random draws | 0.10% | 0.17% | 0.17% | 0.28% | 1.07% |

Every hand-picking pattern tested is flagged: eleven identical words (11/121
bits — an attacker still has to guess *which* word), two words alternating
(22/121), the first 11 words of the list (24/121), words confined to a
150-word window (90/121), and picking off the top 64 (73/121). A random
selection that was merely *sorted* scores 99/121 — correctly, since sorting
costs about log2(11!) ≈ 25 bits and no more.

Each finding names one root cause rather than every consequence of it.
Eleven identical words trip the repetition, ordering, range, first-letter and
neighbour checks all at once; reporting all five would be noise, so it reports
"every word is the same" and stops.

Note that a single repeated word is **not** flagged. In 23 draws from 2048 a
repeat happens about 12% of the time by chance; treating that as suspicious
would cry wolf on one good phrase in eight.

## How the randomness works

Both random paths use `crypto.getRandomValues` — the browser's CSPRNG. There is
no `Math.random()` call anywhere in the file.

Neither path uses modulo or rejection sampling, because neither needs to. The
wordlist is 2048 = 2¹¹ entries, so eleven raw bits index it directly:

```js
const buf = new Uint16Array(count);
crypto.getRandomValues(buf);
return [...buf].map(v => WORDS[v & (WORDS.length - 1)]);   // low 11 bits
```

Masking a power-of-two range is exactly uniform, with no biased branch and no
loop that could silently never run. Candidate counts are also powers of two
(8/16/32/64/128), so the picker masks the same way. Both functions **assert**
their power-of-two precondition and throw rather than generate if it fails.

Measured over 200,000 generated words (2.2 million bits):

| Test | Result | |
|---|---|---|
| Uniformity over 2048 indices | χ² = 2117.8, df = 2047 (p<.01 ≈ 2201) | pass |
| Per-bit balance, all 11 bits | max deviation 0.20 percentage points | pass |
| Serial correlation, adjacent words | r = −0.0016 | pass |
| Runs test, LSB stream | z = −0.17 | pass |
| Independence of separate calls | 0/500 positions matched | pass |

Generate → calculate → pick produces phrases that validate against an
independent implementation: 60/60 across all five lengths. The construction is
sound because a prefix of a uniform bit string is uniform — 11 random words are
121 uniform bits, and picking uniformly among the 128 candidates supplies the
remaining 7, for the full 128 bits a 12-word phrase should carry.

## Development

There is no build step. Edit `index.html` and reload.

### Checking a change

```bash
node verify.js
```

`verify.js` drives the page in headless Chrome and asserts on it. It needs
Node 22 or later and Google Chrome, and nothing else — no install step, no
dependencies, in keeping with the rest of this repository. Set `CHROME` if the
binary is somewhere unusual.

It also refuses any Content-Security-Policy that names an internet origin, and
checks that the logo — which exists three times over, as `BIP-39-logo.svg`, as
the inline mark in the header, and as the favicon's data URI — is the same
artwork in all three.

It is deliberately not the page marking its own homework. The expected answers
come from a separate BIP-39 implementation built on Node's `crypto` in the same
file, so the two have to agree independently. It checks the word list hash, that
no `Math.random` has crept in, that the page still loads nothing from anywhere
over both `file://` and HTTP, that generated phrases validate, and that nothing
overflows or wraps between 320px and 1440px.

The dice flow gets the same treatment: a second independent implementation
derives the seed from a fixed roll vector and the two must agree at 12 and 24
words. It also checks that the roll count decides the size offered — both the
button's label *and* what pressing it actually makes, which are not the same
thing and were not the same thing once — that a dice seed arrives hidden with no
ending to pick, that faked rolls write nothing on the first press, that the
quality check neither cries wolf nor misses a faked pattern, that the two routes
open one at a time, and that the path headings still read at 320px.

Every check here was confirmed to fail against deliberately broken code before
being kept. Three did not, and were rewritten: one read a button's label instead
of its effect, one read a stale seed an earlier check had left in the box, and
one planted a sentinel string that also appears in the page's own source, so it
matched the `<script>` tag and could only ever pass. A check that cannot fail is
worse than no check, so `verify.js` now asserts that no planted sentinel occurs
in `index.html`.

```bash
node verify.js --calibrate
```

adds the check the strength read-out needs: 4,000 random draws at each phrase
length to confirm genuine randomness almost never trips a warning, and every
hand-picking pattern still does. Run it whenever you touch `assess()` — a plain
`node verify.js` will fail until you do, because it tripwires on that function's
hash.

Opening the file directly works in current Chrome, Firefox, and Safari
(`file://` is a secure context, so `crypto.subtle` is available). If your
browser disagrees, the page says so; serve it instead:

```
python3 -m http.server 8000
```

## Deploying

Any static host. For GitHub Pages: **Settings → Pages → Source: Deploy from a
branch → `main` / `(root)`**.

### Custom domain

Add the domain under **Settings → Pages → Custom domain**. That writes a
`CNAME` file into the repository root — **commit it**. If a later push does not
contain it, the custom domain silently unbinds and the site falls back to
`username.github.io`.

At your DNS provider, for an apex domain (`example.com`) create four A records:

```
185.199.108.153
185.199.109.153
185.199.110.153
185.199.111.153
```

For a subdomain (`www.example.com`) create one CNAME record pointing at
`USERNAME.github.io`. Setting up both, with `www` redirecting to the apex, means
either form reaches the site.

Then tick **Enforce HTTPS**. GitHub issues a free Let's Encrypt certificate for
every public Pages site, custom domains included — nothing to buy, no plan to
upgrade. A `username.github.io` site is served over HTTPS from the start; on a
custom domain the checkbox stays greyed out until the certificate has been
issued, usually within the hour.

If it stays greyed out, the certificate is failing to issue. Almost always one
of these:

- **Cloudflare proxying.** The orange cloud is on by default and hides your DNS
  from GitHub, so the challenge used to issue the certificate never completes.
  Set every record pointing at GitHub to *DNS only* (grey cloud), and leave it
  grey until the certificate has been issued.
- **A CAA record.** If the domain has any CAA records at all, one of them must
  name `letsencrypt.org`, or no certificate can be issued.
- **Stray records.** Any extra A or CNAME on the same name pointing elsewhere
  will fail the check.

Worth getting right rather than leaving for later: over plain HTTP anyone between
you and the server can substitute their own copy of this page — which here means their
own word list, or their own generator.

Verify with:

```
dig +short EXAMPLE.COM
```

### Choosing a domain, for this kind of tool

Seed-phrase tools are a standing typosquatting target: attackers register
lookalike domains and serve a version that quietly sends the phrase somewhere.
Two consequences worth weighing before you buy.

Prefer a name that is hard to mistype over one that is merely short. Every
plausible misspelling is a domain someone else can register and point at a
malicious copy of this page.

Say what the tool is for. A name containing `bip39` or `seed` tells a visitor
they are in the right place; a generic one gives them nothing to check against,
which is exactly the confusion typosquatting depends on.

## Reporting a problem

Security contact details are published at
[`/.well-known/security.txt`](https://myseedphrase.app/.well-known/security.txt)
per [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116). Preferred route is a
[private vulnerability report](https://github.com/seQRets/My-Seed-Phrase/security/advisories/new)
on this repository; `security@seqrets.app` also reaches us.

There is no backend, no database and no internet call, so the findings that
matter most are a fault in the checksum or entropy calculations, anything that
causes the page to make an internet request, and anything that weakens the
randomness used to generate words.

The `Expires` field in that file has to be renewed before **1 August 2027** —
an expired `security.txt` is treated as invalid.

## Provenance and licence

Written from the BIP-39 specification, which is itself MIT licensed. The
wordlist is taken from [`bitcoin/bips`](https://github.com/bitcoin/bips)
(MIT), not from any third-party implementation.

Copyright © 2026 Toothjockey LLC. Released under the MIT Licence — see
[LICENSE](LICENSE). MIT means anyone may use, modify and redistribute this,
including commercially, provided the copyright notice travels with it.
