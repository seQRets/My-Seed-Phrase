# My Seed Phrase

The app lives in this directory (GitHub: seQRets/My-Seed-Phrase — renamed from
BIP-39_Checksum, old slug redirects). Live at https://myseedphrase.app via
GitHub Pages (main, /root). Copyright Toothjockey LLC, MIT.

## What this is

A BIP-39 tool with two flows sharing ONE seed field (the top textarea):
generate a complete seed in one press, or supply 11/14/17/20/23 words and it
returns every valid final word — choosing an ending (chip click or "Pick at
random", top-right of the endings card) completes the seed in the top box.
Any complete-length phrase gets a live verdict: green border when the checksum
verifies, red with a plain-words reason when it does not. Complete seeds show a
BIP-32 master fingerprint (in-box and under the QR) and export as a standard
SeedQR (numeric mode) in a blurred modal, which can also save a ~2000px PNG.
Seeds you typed yourself get the same eye, copy and QR controls. An entropy
read-out ("How hard these words are to guess") flags hand-picked words.

## Architecture

index.html is the entire site (~164 KB): wordlist, CSS, JS, an embedded
kazuhikoarase/qrcode-generator (MIT, verbatim), and in-file secp256k1 +
RIPEMD-160 (see invariants). No build, no dependencies, no backend.
verify.js (repo root) is the external test harness — single file, no deps.
Other files: README.md, SECURITY.md, LICENSE, CNAME, .nojekyll,
BIP-39-logo.svg (source of the inlined header mark + favicon),
.well-known/security.txt, .gitignore, CLAUDE.md, .githooks/pre-push.

## Invariants — do not break

1. Zero network. CSP is default-src 'none' with exactly one addition,
   img-src data: (the favicon). verify.js fails any CSP naming a network
   origin. The page makes one request: itself. Inline SVG/data: only.
2. No Math.random() anywhere. crypto.getRandomValues with power-of-two
   masking; randomWords()/randomIndex() assert the precondition and throw.
3. Wordlist byte-identical to official BIP-39 English:
   sha256(WORDS.join("\n")+"\n") =
   2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda.
4. assess() is byte-identical (sha fe7d49ab746ea176…, 2670 bytes) — verify.js
   tripwires on it. If you change it deliberately: run node verify.js
   --calibrate, confirm false alarms stay near zero AND every hand-picking
   pattern is caught, then update the pinned hash. Never skip this.
5. The ONLY hand-rolled crypto is secp256k1 + RIPEMD-160 for the display-only
   master fingerprint (no browser API exists). Both are vector-pinned by the
   page's own self-test (RIPEMD vectors, secp G, BIP-32 vector 1 → 3442193e,
   abandon×11+about → 73c5da0a). Never add more hand-rolled primitives.
6. RELEASE COUPLING: every index.html change requires a new tagged release
   (vX.Y.Z) publishing the file + its SHA-256 — README step 1 tells users to
   STOP on hash mismatch, so an unreleased edit breaks honest users. Since
   v1.5.1 the footer prints the version (<div class="r">vX.Y.Z · RUNS
   OFFLINE</div>), so a release bumps THREE things: the tag, the published
   hash, and that in-page string. Bump the string FIRST — changing it changes
   the file and therefore the hash you publish. It is the only place the
   version appears. Notes: a one-line summary, "## New"/"## Fixed" in plain
   English, "still passes 14 of 14", then "## Verify your download" with the
   shasum block. Current release: v1.6.7.
7. Blur rule: anything the generator produces is born hidden (complete AND
   partial seeds); typed words are born visible, but typing NEVER lifts a blur
   already engaged — a box hidden when typing began stays hidden, so a
   passer-by cannot read the entry; state carries through completion;
   the eye flips it. QR + fingerprint appear only when the phrase is complete.
   The QR modal always opens blurred, reveal is never sticky, canvas wiped on
   close. Fingerprints are never blurred (identify, can't open). Coming back
   via the back button re-blurs whatever is in the box and wipes the QR —
   nothing is ever erased, because a phrase being copied down must not vanish.
   A copy saved with File → Save Page As serializes the live DOM but not the
   seed, so the page reconciles with the box's actual content at load — an
   empty box sheds any serialized state. Reconciling is not enough on its own:
   everything derived from a seed is written into the document, including the
   note naming the chosen ending (a real seed word) and the master
   fingerprint, and hidden text is still text in a saved file. scrubDerived()
   therefore CLEARS those values rather than hiding them, and runs both on
   Clear and at load. verify.js plants a seed word and a fingerprint in its
   /snapshot page and fails if either survives the page opening. Never add a
   place where a seed-derived value is written into the DOM without adding it
   to scrubDerived().
   Modal layout: fingerprint sits directly under the QR (outside .qrbox, so the
   blur never covers it), the download warning directly under that, then two
   sentences with the longer explanation folded into a <details>. The card is a
   panel, not a page — keep it short. The disclosure MUST keep saying that a
   phone shows numbers rather than words, and that those numbers are the words:
   a scanned SeedQR reads as 48 unexplained digits and looks exactly like a
   broken export, which cost a real user an evening. .qrveil scrolls and .qrcard uses
   margin:auto, because a centred flex item taller than the screen has its top
   clipped unreachably, which puts the close button off a phone.
8. CNAME (myseedphrase.app) and .nojekyll must never be deleted.
9. Candidate list reads top-to-bottom then left-to-right (CSS columns:9rem,
   not a grid). No horizontal overflow 320–1440px. Tooltips are pinned to the
   viewport below 560px: the bubble is nearly screen-width and its trigger
   moves, so it cannot hang off the trigger.
10. Copy register: plain English for a scared seed-phrase holder, not an
    engineer. No "network request/entropy bits/hash/CSP" in user-facing copy;
    a bit is "one yes-or-no answer"; honest about limits, never reassuring
    marketing. Auditor-facing README sections (calibration, randomness
    internals) keep their precision. No keyboard shortcuts (removed
    deliberately). Minimal repo: ask before adding any file.
11. Anything that puts the seed somewhere it outlives the tab must say so, in
    the register of the clipboard warning. Copying may warn after the fact —
    a clipboard entry fades — but saving must not: the download button writes
    nothing on the first press. It shows the warning in red (--red-ink, not
    the dim .hint colour), names the file, says the picture IS the seed, warns
    that downloads folders are often synced to iCloud or OneDrive, and waits
    for a second press on "Save it anyway". That button is deliberately NOT
    focused, so a reflexive second Enter cannot save the file. Closing the
    modal forgets the acknowledgement, like every other reveal here.
12. The page refuses to be framed. frame-ancestors only works as a real HTTP
    header and GitHub Pages cannot send one, so a pre-paint script checks
    window.top !== window.self, fails closed, and withholds the tool. The
    warning carries NO link — a frame can be sandboxed so links cannot escape,
    and an address you type yourself is the one that cannot lie.
    The guard is structural, not only a stylesheet: a FRAMED const gates
    calculate(), openSeedQR(), pickAtRandom() and both generate handlers, so a
    selector edit that stops the hiding cannot hand back a working tool. Note a
    cross-origin parent can NOT strip the page's CSS or read its DOM — that is
    not the threat. The threat is our own future edit. Framed with scripting
    off the guard cannot fire at all, but nothing runs either, so the tool is
    inert rather than working.

## How to verify + release

    node verify.js            # 56 checks: drives real Chrome headless, checks
                              # the page against an INDEPENDENT BIP-39 +
                              # fingerprint implementation, both origins,
                              # layout 320/390/1440, blur semantics,
                              # no-scroll-on-generate, links, frame guard
                              # (including a sandboxed frame), blur-on-return,
                              # close-mid-open, the two-press download gate,
                              # modal reachable on a short screen, and the
                              # frame guard holding with its CSS defeated, and
                              # the panel explaining a SeedQR's digits
    node verify.js --calibrate  # only when assess() changes

Page self-test must read 14 of 14 (file:// and http).
Release: bump the footer version → commit → push → poll Pages build FOR THAT
COMMIT (not just "built") → live hash == local → tag with hash in message →
gh release create vX.Y.Z index.html --notes-file … → re-download asset +
fresh-clone verify.js.

verify.js runs page code through template literals, so a backslash in a regex
there is eaten by the literal before JS ever sees it: /\s+/ becomes /s+/ and
silently strips the letter s instead of whitespace. Double them (/\\s+/), or
sidestep it with a character class like /[ ]+/. This has bitten twice.

Run node verify.js before tagging, always. v1.5.2 shipped with 7 of its own
checks failing; six were the harness lagging behind new features, one was a
real bug that reached users.

.githooks/pre-push runs verify.js and refuses the push if it fails, but only
when the push carries index.html or verify.js — a docs-only push is not worth
90 seconds. A tag push checks everything the tag carries, so cutting a release
always verifies. Override with --no-verify. It checks the files on disk, not
the commit being pushed, and says so when the working tree is dirty.

The hook is tracked, but git will NOT enable it on its own: a clone that ran
hooks straight out of the box would be remote code execution. So each clone
needs, once:

    git config core.hooksPath .githooks

Check `git config core.hooksPath` on a machine before trusting that the hook is
live. The flip side of tracking it: a git pull can now change a script that
runs on your machine at push time. Read the diff on that file like any other.

## Standing items

- Neither myseedphrase.app nor bip39checksum.com may ever lapse. The
  path-preserving 301 from the old domain was verified working (root,
  /.well-known/, www) on 2 Sep 2026.
- security.txt Expires: renew before 1 Aug 2027 (keep <1 yr per RFC 9116).
  Its contact rides on seqrets.app, which must stay registered for the same
  reason. Same season: seqrets.com (held by DropCatch, expires 2 Aug 2027)
  may drop — ~$59 backorder if wanted.
- Sister app: seQRets/Passphrase at mypassphrase.app (footer links to it);
  consider a reciprocal link there.
- Real-device test DONE (2 Sep 2026): a generated SeedQR was scanned by a
  hardware wallet, imported, and the master fingerprint shown on-device matched
  the one on the page. The end-to-end claim the whole SeedQR feature rests on
  is confirmed against real hardware, not just against verify.js.
- Footer: Source on GitHub · ₿ Donate (coinos.io/seQRets/receive) ·
  ↗ mypassphrase.app — verify.js pins all three exactly, plus the in-page
  "Find my last word" jump link.
- URL.revokeObjectURL fires immediately after the download click. That favours
  the secret's lifetime over an old Safari quirk that can produce an empty
  file. Deliberate; revisit only if a real empty-download report arrives.

Design: dark-first + light theme (toggle persists), Bitcoin orange #F7931A
(#9C5206 for small text on light), system fonts only, ≥4.5:1 for new colors.

Local preview: .claude/launch.json defines "checksum" (python3 http.server on
port 8899).
