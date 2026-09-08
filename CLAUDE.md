# My Seed Phrase

The app lives in this directory (GitHub: seQRets/My-Seed-Phrase — renamed from
BIP-39_Checksum, old slug redirects). Live at https://myseedphrase.app via
GitHub Pages (main, /root). Copyright Toothjockey LLC, MIT.

## What this is

A BIP-39 tool with THREE independent panels, each doing one job and each owning
its own seed field. There is deliberately no shared box: a seed made in one
panel never appears in another. Under the safety guide sits "What do you want to
do?" and three collapsed <details> behaving as an accordion, since they are a
choice rather than a checklist. In order:

  1 "Make a new seed"  (tab: Create)  #makepath  — length select + Generate,
    result in #gseed. Draws entropy whole (crypto.getRandomValues -> makeSeed ->
    entropyToWords), so it touches none of panel 3's machinery and shows no
    endings: someone who pressed Generate wanted a seed, not a lesson.
  2 "Roll your own randomness" (tab: Roll) #dicepath — the dice flow, result in
    #dseed.
  3 "Finish a seed you already have" (tab: Finish) #finishpath — the older
    machinery: #in takes words IN as well as putting them out, with the verdict,
    the endings grid (#out, inside the panel) and the strength meter.

Panels 1 and 2 share resultField(prefix), a small component giving each field
its own blur/eye, copy, QR and fingerprint. Their textareas are readonly: they
only ever show a seed, so there is no hand-editing one. Panel 3 keeps its own
older code because its field does a different job.

INVARIANT 7 NOW GOVERNS THREE FIELDS. scrubDerived() is the load-time scrub and
reaches all three; each panel's own Clear (#gclr, #diceclr, #clr -> scrubFinish)
must reach ONLY its own panel. Wiring a panel's Clear to scrubDerived() empties
the other two, which is exactly the bug this layout exists to avoid; verify.js
asserts it.

Path 2 (dice): choose a target size, type rolls, and the ladder unlocks as the
rolls arrive — 50/62/75/87/100 rolls for 12/15/18/21/24 words, being
ceil(bits / log2 6). The button always offers the largest size the rolls
justify and never the size merely asked for. Rolls are hashed (SHA-256 of the
ASCII digits, the common dice-entropy convention, so a wallet deriving it the
same way reproduces the same seed), the leading bytes become the
entropy, and entropyToWords() appends the checksum. THERE IS NO ENDING TO PICK
in this flow and never should be: the rolls supply every entropy bit, so the
last word is already determined. Offering the endings card here would overwrite
the last 7 bits with browser randomness and destroy both reproducibility and
the reason someone chose dice. assessRolls() reads the rolls before they are
hashed — see invariant 13.

## Architecture

index.html is the entire site (~205 KB): wordlist, CSS, JS, an embedded
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
4b. The page self-test covers what CAN be pinned. The dice route is
   deterministic, so it is held to a vector (rolls "123456"x9, sha256
   edceb2d8…, "…chimney bullet") and cross-checked against candidates(), the
   path the standard's own examples already verify. Randomness cannot be
   covered this way and is not: a copy with an honest wordlist and honest
   arithmetic but a rigged generator still reads 15 of 15, which is why step 5
   of the in-page guide says so and points at the download hash instead.
   Aim that limit correctly. crypto.getRandomValues is the OS CSPRNG and is
   sound — never write copy implying the generator itself is doubtful, which
   v1.6.8 and v1.6.9 did ("you cannot check its randomness", right under the
   Generate button). The unprovable thing is FILE PROVENANCE: that this copy is
   the published one. Say that, and point at the fingerprint that settles it.
   Dice are a complement to path 1, not an indictment of it.
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
   English, "still passes 15 of 15", then "## Verify your download" with the
   shasum block. Current release: v1.8.1.
7. Blur rule: anything the generator produces is born hidden (complete AND
   partial seeds); typed words are born visible, but typing NEVER lifts a blur
   already engaged — a box hidden when typing began stays hidden, so a
   passer-by cannot read the entry; state carries through completion;
   the eye flips it. QR + fingerprint appear only when the phrase is complete.
   The QR modal always opens blurred, reveal is never sticky, canvas wiped on
   close. Fingerprints are never blurred (identify, can't open). Coming back
   via the back button re-blurs whatever is in the box and wipes the QR, and
   erases nothing — the eye puts it back. Closing a panel is different and does
   erase: folding one shut with its own tab button, or opening another panel,
   runs that panel's own Clear (clearMake / clearRoll / clearFinish, the same
   functions its Clear button is wired to, so the two can never drift apart).
   The owner asked for this twice; a blurred seed left in a folded-away panel is
   still a seed on screen for whoever opens the tab next. It is a real trade: a
   stray press on a tab button destroys a seed someone is half way through
   copying out, and 100 dice rolls with it, so the copy under a generated seed
   and the Q&A both say so plainly. Do not quietly soften this back to blurring.
   Setting .open fires each panel's own toggle event, so the open branch only
   sets .open = false on the others and the close branch does all the wiping —
   one code path. Toggle is queued, not synchronous: a test that opens two panels
   inside one task lets the first handler close the second, so the harness ticks
   between opens.
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
   to scrubDerived() — the entropy bar was one such place, carrying the last
   seed's band and score in an inline style until v1.6.8.
   Note the limit the scrub cannot cross. Save Page As writes the live DOM, so
   the file created at that moment holds whatever was on screen: the chosen
   ending, the note naming it, the fingerprint, and the marked chip in the
   endings grid. The scrub runs when that file is next OPENED, not when it is
   written, and a backup, a cloud sync or a text editor reads the bytes rather
   than the render. So say "sheds them on opening", never "a saved copy carries
   none". verify.js plants all three carriers in /snapshot — the note, the
   marked chip and the fingerprint — and matches each as a whole element or
   sentence, never as a bare word: every BIP-39 word is in the embedded list,
   so a bare-word search can only ever pass. The same trap bit the dice
   read-out: the first sentinel planted for it was a sentence the page's own
   script contains as a string literal, so it matched the <script> tag and the
   check could only ever pass. Plant a sentence the page BUILDS at runtime, and
   note the source-collision check that now guards every sentinel.
   The dice flow adds its own derived nodes — the roll count, the quality
   read-out, the stale and repeat-generation warnings — all cleared by
   scrubDice(), which scrubDerived() calls. The rolls themselves never reach a
   saved file, because a textarea's value is not part of the document.
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
9. The dice route defaults to a 12-word seed / 50 rolls — 100 rolls is too
   big an opening ask, and the longer seeds still unlock as you keep rolling.
   That default lives in THREE places which must agree: the "on" class in the
   size buttons, `let diceTarget`, and the `setDiceTarget(n)` init call. The
   init call wins, so changing only the first two looks right in the file and
   does nothing on the page.
   The generate selector states the OUTCOME ("12-word seed"), never the
   arithmetic — its option VALUES stay 11/14/17/20/23, which is what every
   calculation and every check reads, so the labels are free to change but the
   values are not. Both generate buttons relabel from the selector via
   setGenLabels() off CFG, so they cannot drift out of step with it. The Q&A
   refers to them as "the shorter one" / "the longer one" rather than by a
   fixed name, since the names now move.
   "Verify this page" sits inside step 4 of the six steps, where the
   instruction to press it is, with its results card directly under the steps
   rather than below the seed card.
9a. Scrolling: each panel keeps its field directly under its own buttons, so
    pressing one needs no scrolling at all and the page must NOT move. The one
    exception is panel 3's endings, which appear below its field: asking for them
    scrolls to them (revealResults anchors on #out). Opening a panel must move
    nothing either. verify.js asserts all three.
9b. Never name a particular hardware wallet in user-facing copy, in the README,
    or in release notes for the dice route. The only permitted framing is that
    support for dice entropy in wallets is an incentive for many people to roll
    their own. Describe SHA-256-of-the-digits as the common convention, never as
    a named product's, and state interoperability conditionally ("a wallet that
    derives it the same way"). The reason for that hedge CHANGED on 8 Sep 2026:
    the convention is now confirmed against real hardware (see Standing items),
    so the hedge is no longer about an untested claim. It is because one device
    is not a survey and another wallet may take dice a different way. Keep the
    conditional phrasing; do not upgrade it to a promise about wallets in
    general. The SeedQR wallet list in the README is the exception to the naming
    rule: it predates this and rests on its own real-device test.
10. Candidate list reads top-to-bottom then left-to-right (CSS columns:9rem,
   not a grid). No horizontal overflow 320–1440px. Tooltips are pinned to the
   viewport below 560px: the bubble is nearly screen-width and its trigger
   moves, so it cannot hang off the trigger. Opening a path scrolls it to the
   top of the view (scroll-margin-top on .path keeps it off the edge), because
   the body unfolds tall enough to push the seed box below the fold and leave
   the buttons and the box they fill in different screenfuls. Called straight
   out, NOT in requestAnimationFrame: scrollIntoView flushes layout itself, and
   a frame callback queued while the tab is hidden fires whenever the tab is
   next looked at, jerking the page then. prefers-reduced-motion turns the
   page's smooth scrolling off.
11. Copy register: plain English for a scared seed-phrase holder, not an
    engineer. No "network request/entropy bits/hash/CSP" in user-facing copy;
    a bit is "one yes-or-no answer"; honest about limits, never reassuring
    marketing. Auditor-facing README sections (calibration, randomness
    internals) keep their precision. No keyboard shortcuts (removed
    deliberately). Minimal repo: ask before adding any file.
    WORDS BELONG IN THE Q&A AND TOOLTIPS, NOT THE INTERFACE, unless they are
    needed at the moment of action. v1.7.3 cut the prose on screen roughly in
    half (708 -> 387 words in the working state) by moving every explanation of
    WHY into the Q&A, which already carried most of it, and leaving the
    interface to say only what a thing IS. Before adding a sentence to the
    interface, ask whether it is a Q&A answer wearing a disguise. Two things
    that stay: warnings at the moment of exposure, and any gloss for a term the
    UI itself shows.
    A warning must not assume a step the interface never gave. The dice warning
    said "destroy the paper once the words are written down" while nothing on
    screen had told anyone to write the rolls on paper; that half moved to the
    Q&A, where the workflow is actually described.
12. Anything that puts the seed somewhere it outlives the tab must say so, in
    the register of the clipboard warning. Copying may warn after the fact —
    a clipboard entry fades — but saving must not: the download button writes
    nothing on the first press. It shows the warning in red (--red-ink, not
    the dim .hint colour), names the file, says the picture IS the seed, warns
    that downloads folders are often synced to iCloud or OneDrive, and waits
    for a second press on "Save it anyway". That button is deliberately NOT
    focused, so a reflexive second Enter cannot save the file. Closing the
    modal forgets the acknowledgement, like every other reveal here.
13. The page refuses to be framed. frame-ancestors only works as a real HTTP
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

13. The roll string IS the seed, one step earlier. Anyone holding it re-derives
    every word for ever, on any machine, so it gets what the seed box gets: its
    own blur and eye, re-blurred by anything that brings the page back, never
    erased, and everything worked out from it scrubbed by scrubDice(). Say so in
    the copy before they start typing, not after — people jot dice results on
    paper as if they were scratch working.
    assessRolls() is the only place a faked roll can still be caught. Hashing
    whitens completely: "444…" and a real sequence produce output that looks
    equally random, so assess() downstream reports a flawless phrase either way.
    It takes the tightest of four upper bounds — face distribution, shortest
    repeating block, gap distribution between consecutive rolls, and the ceiling
    — and its FLAGS, not its bit count, gate a generate. Never gate on the bits:
    over 50 rolls the count reads low from sample size alone (genuine rolls
    measure as little as 0.85 of what the seed formally needs), so testing it
    against the requirement stops honest rolls at the shortest length every
    time. Calibrated like assess(): ~0% false alarms at every length, every
    faked pattern caught. Changing it means re-running both halves.
    A flagged generate follows the download gate — first press writes nothing,
    names what is wrong, and waits for a separate "Make it anyway" button that
    is deliberately NOT focused; editing the rolls withdraws the
    acknowledgement.
    A longer seed is a DIFFERENT seed, not an upgrade: rolling on from 50 to 100
    shares not one word with what came before. The copy must kill that
    assumption on sight, because someone who assumes otherwise ends up holding
    two seeds and trusting the wrong one.

## How to verify + release

    node verify.js            # 69 checks: drives real Chrome headless, checks
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

Page self-test must read 15 of 15 (file:// and http).
Release: bump the footer version → commit → push → poll Pages build FOR THAT
COMMIT (not just "built") → live hash == local → tag with hash in message →
gh release create vX.Y.Z index.html#myseedphrase.html --notes-file … (the asset is
named for the app; the repo file stays index.html because Pages serves it at
the domain root) → re-download asset +
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
- Sister app: seQRets/My-Passphrase at mypassphrase.app (renamed from
  seQRets/Passphrase; the old slug 301s). Reciprocal linking is DONE, verified
  in both files on 8 Sep 2026: this footer links to https://mypassphrase.app and
  that footer links to https://myseedphrase.app. Do not add another — verify.js
  asserts an exact outbound-link count here, so a second one fails the harness.
- Real-device test DONE (2 Sep 2026): a generated SeedQR was scanned by a
  hardware wallet, imported, and the master fingerprint shown on-device matched
  the one on the page. The end-to-end claim the whole SeedQR feature rests on
  is confirmed against real hardware, not just against verify.js.
- Real-device test DONE for dice (8 Sep 2026): 52 throws made a 12-word seed
  here, the same throws were entered into a Krux wallet, which asks for them as
  plain 1-6 digits, and both the seed AND the master fingerprint matched. The
  SHA-256-of-the-digits convention is confirmed against real hardware, not just
  against verify.js. One device is not a survey, though: other wallets may take
  dice a different way, which is why the copy stays conditional. Krux is named
  HERE only — 9b still bars naming a wallet in the page, the README or release
  notes for the dice route.
- SIX outbound links, all pinned by verify.js: GitHub, Download, Donate,
  mypassphrase.app, step 1's asset link (the same href as the Download button,
  pinned twice on purpose) and step 1's link to the README anchor that carries
  the hash-checking commands. NO in-page links: the "Find my last word" jump
  went in v1.7.15, because the seed box it pointed down at is now the first
  thing under the guide. verify.js asserts inpage.length === 0.
  Footer row, in order: GitHub, Download, Donate (coinos.io/seQRets/receive),
  mypassphrase.app. The Download button and step 1's inline "Download the latest
  release" are the SAME href (releases/latest/download/myseedphrase.html, the
  asset itself, never the releases page), and verify.js requires that href
  exactly twice so the two cannot drift apart. Renaming the asset means changing
  both, the README, and the pin.
- URL.revokeObjectURL fires immediately after the download click. That favours
  the secret's lifetime over an old Safari quirk that can produce an empty
  file. Deliberate; revisit only if a real empty-download report arrives.

Design: light ships as the default for everyone and the toggle pins dark (it
persists; the OS preference is deliberately not read), Bitcoin orange #F7931A
(#9C5206 for small text on light), system fonts only, ≥4.5:1 for new colors.

Type scale: --fs-2xs .62 / --fs-xs .72 / --fs-sm .82 / --fs-md .95 / --fs-lg
1.15 / --fs-xl 1.35 rem, identical to the sister app so the two read as one
family. Reach for a token, not a number. Three things sit outside it on purpose:
the clamp() headings, which are fluid; relative em on glyphs and icons, which
should track whatever they sit beside; and the fixed px on the seed box (15px)
and the candidate chips (14px, index 11px), where a monospace grid has to stay
predictable — those are what invariant 9 measures at 320px, so moving them means
re-running the layout checks and expecting them to matter.

Local preview: .claude/launch.json defines "checksum" (python3 http.server on
port 8899).
