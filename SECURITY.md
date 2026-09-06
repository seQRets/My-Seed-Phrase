# Security Policy

## Reporting a vulnerability

**Please don't open a public issue for a security problem.**

Report it privately:

1. **[Open a private security advisory](https://github.com/seQRets/My-Seed-Phrase/security/advisories/new)** — preferred
2. Or email **security@seqrets.app**

Machine-readable contact details are published at
[`/.well-known/security.txt`](https://myseedphrase.app/.well-known/security.txt),
per [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116).

Include what you did, what happened, what you expected instead, and your browser
and version. For a calculation fault, the exact words you entered are the most
useful thing you can send.

You should get an acknowledgement within a week.

## Before you report

Press **Verify this page** on the affected site. If it doesn't say *14 of 14
checks passed*, include that — a failure there is significant on its own, and
tells us whether the copy you loaded matches what was published.

## Scope

This project is one self-contained HTML file. There is no backend, no database,
no accounts, no cookies and no internet calls, so the surface is narrow and the
things that matter are specific.

**In scope**

- Wrong results from the checksum or candidate-word calculation
- Anything that causes the page to make an internet request
- Anything weakening the randomness behind *Generate at random* or *Pick at random*
- Anything that could alter the embedded BIP-39 word list without the built-in
  verification catching it
- Injection through the input field
- Anything that causes an entered phrase to be stored, logged, or leave the page

**Out of scope**

- Browser extensions being able to read the page. This is documented, is true of
  every web page, and cannot be fixed from inside one — it's why the guidance is
  to run the file offline in a browser profile with no extensions installed.
- A compromised machine, keylogger, or screen recorder
- Scanner output about headers that don't apply to a static page under
  `default-src 'none'`
- Missing features that would require a backend
- Denial of service against GitHub Pages

## Supported versions

The published page at <https://myseedphrase.app> and the current `main` branch.
There are no releases or version branches to support.
