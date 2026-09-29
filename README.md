# Princess-Roll

A private, two-person encrypted chat with a shared D20, written in Rust and
compiled to WebAssembly. There is no server: the page is static, the two
browsers talk directly to each other, and nothing about either of you is stored
anywhere.

- **Two secret codes.** One makes you *Daddy*, the other *Princess*.
- **Direct peer-to-peer.** WebRTC data channel, encrypted again underneath by
  the app itself.
- **A challenge and a threshold.** Daddy sets both. Princess rolls against them.
- **A provably fair die.** Neither side can steer the number.

---

## Privacy: what is and is not protected

Stated plainly, because a vague privacy claim is worth nothing.

**Protected**

- No accounts, no names, no identifiers. Roles are the only labels.
- The only thing stored is the sound level, under one `localStorage` key.
  No messages, files, codes or identifiers are written anywhere; closing the
  tab is the whole of the erase procedure.
- Messages are sealed with AES-256-GCM under a key that exists only in memory,
  and again by WebRTC's own DTLS beneath that.
- The pairing file that ships with the page is ciphertext. It says nothing about
  who either of you is.
- Invite and reply codes are encrypted, so whatever you paste them through — SMS,
  a chat app, anything — cannot read them.
- No requests leave the page except to public STUN servers while connecting.
  No analytics, no fonts, no CDN.

**Not protected, and cannot be**

- **You learn each other's public IP address.** That is what a direct connection
  is. Hiding it would require relaying all traffic through a TURN server, which
  means running a server, which this design does not do.
- **A weak secret code is the whole ballgame.** `pairing.bin` is publicly
  downloadable and can be attacked offline forever. Argon2id makes each guess
  cost about a second, and that is the only thing standing between a guessable
  code and a stranger in your chat. Use the generated codes.
- Neither of you is protected from the other. This is a two-person tool.

---

## Setting it up

### 1. Choose your codes

```bash
cargo run --bin setup
```

Offers to generate two 125-bit codes, or takes your own (typed twice, never
echoed). It writes `web/pairing.bin` and nothing else. **Your codes never touch
disk, this repository, or the network** — only a random pairing secret wrapped
twice under Argon2id does.

Losing a code means re-running setup. There is no recovery, by design.

### 2. Build and run it locally

```bash
./build.sh     # compiles to docs/
./serve.sh     # http://localhost:8080
```

`serve.sh` uses Python's `http.server` because it resolves `.wasm` to
`application/wasm`, which WebAssembly's streaming loader requires.

To reach it from another device on your network:

```bash
./serve.sh 8080 0.0.0.0        # then http://<this-machine-ip>:8080
```

Note that a LAN address is **not a secure context**, so `navigator.clipboard`
is unavailable there. The Copy buttons fall back to `execCommand`, which works
over plain HTTP; the text is also left selected so you can copy it yourself.

### 3. Connect

1. Both open the page and enter their secret code.
2. Daddy clicks **Create invite code** and sends the string to Princess.
3. Princess pastes it, clicks **Accept invite**, and sends her reply back.
4. Daddy pastes the reply and clicks **Connect**.
5. Both screens show a four-syllable **safety phrase**. Compare it out loud
   once. If the phrases match, nobody is in the middle.

The paste dance happens once per session.

---

## Deploying

Pushing to `main` triggers `.github/workflows/deploy.yml`, which runs the test
suite, builds the WASM, and publishes to GitHub Pages. `web/pairing.bin` must be
committed or the build fails with a clear error — it is ciphertext, so
committing it to a public repository is safe.

### Custom domain

The site is configured for **princess-roll.danieljpost.dev** via `web/CNAME`.
Two things must be done once, outside this repository:

**1. DNS** — at whatever hosts `danieljpost.dev`, add:

| Type  | Name             | Value                      | TTL  |
|-------|------------------|----------------------------|------|
| CNAME | `princess-roll`  | `danieljpost-dev.github.io.` | 3600 |

A subdomain must be a `CNAME`; `A` records are only for an apex domain. Mind the
trailing dot if your registrar expects a fully-qualified value.

**2. GitHub Pages** — after the first successful workflow run:

```bash
# Enable Pages, building from the workflow rather than a branch
gh api -X POST repos/danieljpost-dev/Princess-Roll/pages \
  -f build_type=workflow

# Point it at the custom domain
gh api -X PUT repos/danieljpost-dev/Princess-Roll/pages \
  -f cname=princess-roll.danieljpost.dev

# Once GitHub's DNS check passes, force HTTPS
gh api -X PUT repos/danieljpost-dev/Princess-Roll/pages \
  -F https_enforced=true
```

Or do the same in **Settings → Pages** in the browser. The certificate takes a
few minutes after the DNS check passes.

---

## Tests

Tests are an opt-in Cargo feature and are **not compiled by default**:

```bash
cargo test --features tests     # runs the suite
cargo test                      # compiles, runs zero tests
```

Nothing test-related can reach a release artifact, because `build.sh` and the
deploy workflow never pass `--features`.

---

## How it works

### Unlocking

`pairing.bin` holds one random 32-byte pairing secret, wrapped twice — once
under each code — with Argon2id (64 MiB, 3 passes) over a shared salt. Entering
a code runs Argon2 once, then tries both wraps; the AEAD tag verifies against
exactly one of them, which is how the page learns your role without storing any
hint about it.

### Session keys

Each side generates an ephemeral X25519 keypair and sends the public half inside
its invite or reply. The session key is

```
HKDF(ikm = X25519(mine, theirs), salt = pairing_secret, info = "…" ‖ daddy_pub ‖ princess_pub)
```

Folding the pairing secret in as the HKDF salt means someone who intercepts both
codes still cannot derive a session key. The safety phrase is a second check
rather than the only one.

### A die nobody can steer

Daddy's client publishes `SHA256(nonce)` *before* Princess can roll. She reveals
hers, which starts the round; he then opens his, and her client checks it
against the commitment it already holds. The result derives from both nonces by
rejection sampling — modulo would quietly bias the low faces.

Neither side can predict or bias the outcome, and a mismatched commitment is
reported and the roll discarded.

### A die that lands where it was told

The number is agreed before anything moves, so the animation is choreography,
not physics. The tumble axis, turn count and arc come from a shared animation
seed — both screens see the identical throw — and the path eases into a slerp
that seats the agreed face toward the camera at exactly `t = 1`. It always lands
correctly: no retries, no snapping, no relabelled faces.

### The die itself

Twelve vertices from the golden ratio, twenty faces, split into sixty vertices
for flat shading. Opposite faces sum to 21, found by pairing antipodes rather
than hard-coding a table. The numbers are drawn into a canvas at startup and
uploaded as one texture atlas, with 6 and 9 underlined. No asset files.

---

## Layout

```
src/
  crypto.rs     Argon2id, AES-GCM, HKDF, unbiased dice sampling
  pairing.rs    the wrapped pairing file and role resolution
  protocol.rs   session keys, counter-nonce framing, message types
  signal.rs     encrypted invite/reply codes
  dice.rs       icosahedron, fair rolls, landing choreography
  render.rs     WebGL2 renderer and number atlas
  audio.rs      synthesised success and failure stings
  rtc.rs        WebRTC peer and the paste handshake
  app.rs        state machine and DOM wiring
  bin/setup.rs  one-time code configuration (native only)
web/            index.html, style.css, CNAME, pairing.bin
```

## Licence

MIT.
