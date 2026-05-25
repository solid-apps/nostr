# nostr

Your **Nostr control center**, on your Solid pod — the bridge between your Nostr
keys and your WebID. A build-free [solid-app](https://github.com/solid-apps):
plain HTML + one `app.js`, served from `/public/apps/nostr/`.

It does the unglamorous-but-essential plumbing that makes the rest of the
Nostr-native apps (and `did:nostr` agents) run on a *stable* identity:

## Identity bridge (the point of the app)

Your pod authenticates a signed **NIP‑98** request and tries to resolve it to
**your WebID** — but only if your profile *declares* the key as a
`verificationMethod` referenced from `authentication`. Without that, every
request stays an anonymous `did:nostr:<pubkey>`.

The **Identity** tab reads your `profile/card.jsonld`, shows a green/red
checklist, and **fixes it in one click** — writing the key in exactly the
multibase form JSS decodes (`f` + `e701` + `02` + hex, `@type: Multikey`) plus
the `authentication` backlink. This matches `javascript-solid-server`'s own
`buildOwnerVerificationMethod`, so the server accepts it.

## Keys

- The **64‑char hex** public key *is* your identity. `npub`/`nsec` are bech32
  *display* sugar over the same bytes — computed lazily, never the source of truth.
- **Generate** a keypair in-browser (`@noble/secp256k1`), or **import** an `nsec`
  / hex secret. Reveal a held secret (hex + `nsec`) on demand.
- Keys you generate/import are stored in `/private/nostr/keys.jsonld`
  (owner‑only, behind the pod's auth ladder) — one of several valid homes for a
  key (a NIP‑07 extension is another; this app reads the signed‑in key too).

## Apps & relays

- **Apps** — the relay-backed apps in the suite (plaza, timeline, hub, charlie,
  messages), which work over a real network today regardless of pod reachability.
- **Relays** — your NIP‑65 relay list, saved to your pod, with a connectivity test.

## Dependencies

Deliberately lean, lazy-loaded, and **not** nostr-tools:
`@noble/secp256k1` (keygen) and `@scure/base` (bech32 for `npub`/`nsec`).

## License

[AGPL-3.0-only](LICENSE).
