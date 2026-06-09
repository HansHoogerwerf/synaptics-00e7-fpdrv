# Synaptics 06cb:00e7 USB protocol notes

Working notes derived from a series of Windows-VM USB captures (now persisted
under `captures/` in this repo; see `captures/README.md` for the catalogue).
The phase split below is what `tools/decode_capture.py` produces from each
pcap.

**Two distinct flows** are observed in the captures and described here:

- **Connect** — what happens when a host already has the sensor's pairing
  data decryptable on its side (`captures/try-3.pcapng` is the canonical
  example). Goes straight from cleartext init queries → `GET_CERTIFICATE_EX`
  → TLS handshake.
- **Pair** — what happens on first contact with a sensor whose stored blob
  the host cannot decrypt (`captures/try-6.pcapng` — fresh Windows install in
  a different VM, so different machine DPAPI keys). Inserts an extra
  cleartext pair handshake (`0x3f`, `0x93`) between `GET_CERTIFICATE_EX` and
  the TLS handshake.

## USB endpoint layout

`lsusb -t` shows the sensor on a single interface at full speed (12 Mbit/s,
USB 2.0 root hub). It exposes three endpoints, all on interface 0:

| Endpoint | Direction | Transfer type | Role |
|---|---|---|---|
| `0x01` | OUT (host → sensor) | Bulk | Command channel |
| `0x81` | IN  (sensor → host) | Bulk | Response channel |
| `0x83` | IN  (sensor → host) | Interrupt | Asynchronous event channel |

The control pipe (`0x00`/`0x80`) carries only standard USB enumeration
(`GET_DESCRIPTOR DEVICE/CONFIGURATION`); no protocol traffic goes through
control transfers.

The Bulk OUT/IN pair carries two distinct framing layers in different
phases of the session:

- **Pre-pair cleartext**: each URB carries one Synaptics command request or
  response, no extra framing.
- **Post-pair**: each URB carries one TLS 1.2 record (`17 03 03 …`) wrapping
  the same Synaptics command format.

## Phase 1 — Pre-pair cleartext commands

Captured frames 138–177 in `try-3.pcapng`. All payloads observed in this
phase are listed below in capture order. Direction `H>S` is bulk OUT,
`S>H` is bulk IN.

### Command grammar (inferred)

Two distinct command shapes observed:

1. **Single-byte commands** — host writes one byte; sensor responds on
   bulk IN. Used for queries that take no arguments.

2. **Multi-byte commands** — host writes `cmd_id (1) | args …`. The
   `0x8e` family in particular carries a 1-byte sub-op after the ID, then a
   16-byte zero-padded parameter block.

Responses on bulk IN are length-prefixed with a small leading header.
The first four bytes of every IN payload observed are `00 00` followed by
either a length or a status word — not yet conclusively decoded.

### Observed commands (chronological order in `try-3.pcapng`)

| Cmd byte | Args | Direction example | Response example | Inferred name |
|---|---|---|---|---|
| `01` | — | `01` (1 B) | 38 B response, starts `00 00 a2 df e6 5e c3 6a 31 …`  | `GET_VERSION` — body includes a 7-byte serial-shaped field |
| `8e <sub>` | 15 B zero pad | `8e 09 00 02 00 00 …` | 26 B status block | Subops observed: `09`, `1a`, `2f`. Subop `1a` returns a 78-byte block that matches the structure of the "startinfo" already named in synaTudor DLL traces, so `8e 1a` is `GET_STARTINFO` |
| `af` | `01 00 00 00` (LE u32) | `af 01 00 00 00` | 10 B response `00 00 5f eb 3d b6 01 ff ff ff` | Status query |
| `19` | — | `19` (1 B) | 64 B response (`00 00 00 03 01 02 00 00 …`) then a 4 B trailer `00 00 00 00` | `GET_VERSION_EX` — body contains version triple `01 02 00 00` and serial `3d 97 5a f5` |
| `3e` | — | `3e` (1 B) | 52 B response (capability bitmap, `ff ff ff ff …` regions) | Capabilities query |
| `40 02 00 ffff 00 00 00 00 00 10 00 00` | 13 B literal | as shown | **4096 B** main response + 8 B trailer of `ff` | `GET_CERTIFICATE_EX` — fetches the sensor's stored host-pairing TLV blob |

The exact byte-level meaning of the `0x40 02 …` request arguments is not
yet decoded; the `0xffff` looks like a "give me everything" selector and
the `0x1000` (4096) like a max-length hint.

### Response framing

Empirically every cleartext IN response starts with `00 00` (likely an
error/status word of 0=ok), followed by a 16-bit little-endian length, then
the payload. Two visible examples:

```
frame 145 (resp to GET_VERSION):
  00 00  a2 df e6 5e c3 6a 31  00 0a 01 01 41 01 c1 00  00 1a dc 4d …
  ^^^^   ^^^^^^^^^^^^^^^^^^^   body
  status

frame 153 (resp to 8e 1a "startinfo"):
  00 00 48 00 00 00 44 00  1a 00 ab c2 02 00 be c0  02 00 5b 1b …
  ^^^^^             ^^^^^   body
  status            length=0x44 (=68) — matches body length
```

That gives a working envelope hypothesis: `status_u16 | length_u16 | …
payload …`. Confirming this should be the first parser test in the
from-scratch driver.

## Phase 2 — The 4 KB pairing-data blob (frame 175 of `try-3.pcapng`)

`tools/decode_capture.py` writes the response of `GET_CERTIFICATE_EX` to
`sensor_cert.bin` (4104 bytes incl. trailer). The blob is **not X.509** —
no `30 82 …` DER SEQUENCE wraps the whole structure.

Observed structure:

```
00 00 00 10               // env header: status=0, len_hi=0x10 (?)
00 00 00 00               // padding / version bytes
01 00 04 00               // block_type=1, sub_type=4
67 ab dd 72  10 24 f0 ff  // 16-byte GUID/UUID #1
4e 0b 3f 4c  2f c1 3b c5
ba d4 2d 0b  78 51 d4 56
d8 8d 20 3d  15 aa a4 50
00 10 00 00               // next-record length
00 20 0f c0               // next-record header
00 fc 06 a1  23 e3 a4 0c  // 32-byte hash / signature
98 f3 67 89  43 c4 3b 43
1a a3 36 51  59 7d 6f 81
42 13 b5 af  92 a0 dc 95  d2 32
0b 01 00 00               // length=0x0000010b (267) of next chunk
00 00 00 00  00 e6 05 00
…
d0 8c 9d df  01 15 d1 11  // -+ MICROSOFT DPAPI PROVIDER GUID #1
8c 7a 00 c0  4f c2 97 eb  // -+ {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
01 00 00 00  7c be 5b 4e  f8 5e 56 4e  aa f7 f6 21  6e 9f 7d 68
…  (DPAPI-encrypted payload)
d0 8c 9d df  01 15 d1 11  8c 7a 00 c0  4f c2 97 eb   // second DPAPI blob
…
ff ff ff ff … (padding to 4 KB)
```

So this is a Synaptics-defined TLV container holding (at minimum) **two
DPAPI-encrypted records**. DPAPI is a Windows-only API; the sensor itself
cannot decrypt these blobs. The shape is "opaque host-pairing data the
sensor stores on the host's behalf" — the previous Windows owner wrote
these via DPAPI and the sensor returns them on `GET_CERTIFICATE_EX`.

Implications for the from-scratch driver:

- The blob is **per-host**, not per-sensor identity. We don't need to
  recover the DPAPI keys to reproduce a fresh pair — we just need to
  generate our own pairing data, encrypt it with a host-side key of our
  choice (does not need to be DPAPI; libtudor already implements a stand-in),
  and write it back to the sensor via the corresponding `SET_*` command.
- The fact that this 4 KB blob came back **after** the Linux-side unpair
  cleared host-side pairing means `tudor_unpair` does not clear the
  sensor's stored blob — only the host-side `tudor_get_pdata_fnc` callback
  table. The sensor still hands back the previous Windows owner's data.
  To fully unpair we'd need either a different IOCTL or a `VCSFW_CMD_*`
  that writes a zero/empty blob.
- Two DPAPI records suggests two distinct secrets per host pairing —
  candidates: PSK (used in the TLS-like handshake) + identity certificate
  private key.

## Phase 2b — Cleartext pair handshake (only in fresh-pair flow)

**Replay test result (2026-05-17):** Sending the exact 401 bytes of try-6
frame 280 verbatim from a different Linux host yields a **byte-identical**
802-byte response from the sensor (first 802 of the 805 bytes captured in
try-6 frames 283+285; the trailing 3-byte status `3d 73 02` is tied to the
host's *next* request, not this one). This proves:

- The sensor has **no replay protection** at Phase 2b.
- The sensor has **no host-identity binding** at this layer — the captured
  hashes came from a different Windows install and our Linux host got
  accepted with them.
- The sensor's response is **byte-deterministic** for given request bytes
  (the ~70-byte sensor signature included). Either RFC 6979 deterministic
  ECDSA or the sensor's "signature" portion isn't a fresh signature at all
  but static device identity bytes.

The from-scratch driver in `src/pair.c` implements:

- `fp_pair_begin()` — `0x3f 02`
- `fp_pair_request()` — builds the 401-byte `0x93` payload with the layout
  documented below, signs with a P-256 key, transports and reads response
- `fp_pair_attempt()` — runs both with placeholder material (random token,
  fresh keypair, fixed-string hashes); sensor rejects with status `0x0403`
- `fp_pair_replay_try6()` — replays the captured try-6 bytes verbatim;
  sensor accepts with status `0x0000`
- `fp_tls_replay_try6()` — pair-replay + captured ClientHello (frame 288);
  sensor responds with ServerHello whose **random field is real per-session
  randomness**, only the framing bytes match the capture

**TLS handshake replay test result (2026-05-17):** Sending the captured
ClientHello yields a 66-byte ServerHello with the version+framing bytes
(`03 83 00`) byte-identical to try-6 frame 291, but the **32-byte random
field is completely different on every call**. The sensor has a real RNG
that it uses for the TLS-like handshake. (It deliberately did NOT apply
that RNG in the Phase 2b pair response — supporting the deterministic
ECDSA / static-identity hypothesis there.)

Concrete consequence: **pure-replay-attack cannot drive Phase 3**. The
from-scratch driver must complete a real TLS handshake, which requires
computing the **PSK** that ECDHE_PSK_AES_256_CBC_SHA384 mixes into key
derivation. We still don't know the PSK derivation function. This is the
load-bearing open question for the next session.

### Response field layout (precise, derived 2026-05-17)

Built from a byte-by-byte walk of the 802-byte deterministic response.
`tools/analyze_pair_response.py` exercises this layout and tests
hypotheses against it.

```
offset  size  field
   0     2    status_u16 (LE, 0x0000 = OK)
   2     4    echoed host_token
   6    32    echoed host_hash1
  38    36    zero pad
  74    32    echoed host_hash2
 106    36    zero pad
 142     4    TLV metadata: type=0x0002 len=0x0020 (LE u16 each)
 146    32    type-2 sensor-injected field
 178   224    zero pad (rest of echo half)
 402     4    sensor_token (= echoed host_token)
 406    32    sensor_hash1 (not a valid P-256 X-coord)
 438    36    zero pad
 474    32    sensor_identity_hash (IS a valid P-256 X-coord)
 506    36    zero pad
 542     4    TLV metadata: type=0x0000 len=0x0048 = 72
 546    72    sensor DER ECDSA signature (P-256, SHA-256)
 618   184    trailing zeros
```

### Empirical findings from response analysis

- **TLV metadata format** is consistent for length-prefixed fields:
  `<type_u16 LE><length_u16 LE><value>`. Sigs use type=0; the
  sensor-injected 32-byte field uses type=2.
- **`host_hash1` and `sensor_identity_hash` are valid P-256 X-coordinates**.
  Each yields a valid point with two possible y-values. This strongly
  suggests these fields are **EC public keys**, not arbitrary hashes —
  consistent with an ECDH-style key exchange embedded in what looks like
  a hash-only protocol.
- **`host_hash2`, `sensor_hash1`, and the type-2 extra field are NOT
  valid P-256 X-coordinates** — these are either arbitrary hashes /
  derived values, or X-coords on a different curve.
- **The host's ECDSA signature does NOT verify** against `host_hash1`
  interpreted as a pubkey for any common message hypothesis
  (host_token, host_hash1, host_hash2, concatenations, SHA-256 of
  those). Either the message includes data we can't observe
  (device-bound state), or `host_hash1` being a valid X-coord is
  coincidence.
- **`r` and `s` are identical across replay** (RFC 6979 deterministic
  ECDSA or fixed-`k`), confirming the byte-determinism of the response.

### ServerHello.random IS the sensor's ECDH X-coordinate (hypothesis verified 2026-05-17)

For `TLS_ECDHE_PSK_*` ciphers, RFC 4279 §3 specifies that the server
sends its ephemeral ECDH parameters in a `ServerKeyExchange` message.
We never see one in our captures — the server's flight contains only
`ServerHello + CertificateRequest + ServerHelloDone`.

The reason: **the sensor packs its ECDH public X-coordinate into the
32 random bytes of `ServerHello.random`.** Verified:

- Captured try-3 `ServerHello.random` =
  `00052ed957b8ccbf6411af8f2466f406f11e85d374993d57b6ad8db901ad1496`
  is a **valid P-256 X-coordinate** when interpreted big-endian. The
  recovered Y is
  `8825fbfc418ce416e7e3cb868ee49c4dd483cc570e76c5b33d895d9f619b9015`.
- Captured try-6 `ServerHello.random` is also a valid X.
- Earlier `fpdrv tls-replay` showed `ServerHello.random` varies per
  session — consistent with an ephemeral ECDH keypair being generated
  fresh by the sensor each handshake.

Implementation: `fp_crypto_p256_point_from_x(x_be, y_parity, pub_out)`
recovers the full 64-byte (X || Y) point. Y has a 1-bit ambiguity from
the curve equation; the from-scratch driver tries `y_parity = 0` first
and, on Finished-MAC failure, retries with `y_parity = 1`.

This makes the protocol's "non-standard handshake" RFC-compliant after
all — it just **steganographically encodes** the ECDH public key into
the field standard TLS uses for randomness, saving the bytes a
`ServerKeyExchange` message would cost.

### Synaptics protocol quirks discovered while porting python-validity (2026-05-17)

- **ServerHello uses TLS version byte `0x0383`** instead of the standard
  `0x0303`. Any strict TLS parser will reject it. Our parser accepts any
  `0x03 XX` form. python-validity is strict on 0x0303 because the
  Validity sensors use the standard value; only our newer 06cb:00e7
  sends 0x0383.
- **ClientHello extensions length field is encoded as `(real_len - 2)`**.
  python-validity has a `WHY?!` comment about this. We mirror the quirk
  to match the DLL's bytes byte-for-byte.
- **A single TLS Handshake record can carry multiple handshake messages**.
  Captured frame 183 has ServerHello + CertificateRequest + ServerHelloDone
  concatenated in one record. Our parser splits via `fp_tls_split_handshake`.
- **`fpdrv selftest` includes byte-for-byte KAT** of our ClientHello
  builder against captured try-3 frame 180 — proves we generate the
  exact same wire bytes the DLL does, given the same client_random.

### Open: PSK derivation

If `host_hash1` and `sensor_identity_hash` are genuinely the ECDH pubkey
X-coordinates, then a fresh-pair driver implementation would:

1. Generate ephemeral host private scalar `d_h`
2. Compute host pubkey point `P_h = d_h * G`, take `P_h.x()` as
   "host_hash1" in the request
3. Generate `host_hash2` (purpose unknown — maybe a session nonce, maybe
   another EC point)
4. Sign (some message) with the host's long-term identity key (which is
   distinct from the ephemeral ECDH key)
5. Submit; sensor responds with `sensor_identity_hash` (sensor's static
   pubkey X), allowing host to reconstruct `P_s`
6. Compute shared secret = `(d_h * P_s).x()` (32 bytes)
7. Derive PSK via some KDF over the shared secret + nonces

The remaining unknowns: what's signed, what `host_hash2` carries, the
KDF used to go from shared secret to PSK. None are answerable from
response inspection alone.



Observed only in `captures/try-6.pcapng` (fresh-install Windows VM with no
prior pairing). Inserted between Phase 2 and Phase 3. In the connect flow
(try-3) this entire phase is skipped — the host proceeds directly from
`GET_CERTIFICATE_EX` to `ClientHello`.

After the host reads the 4 KB blob and determines it cannot decrypt it (or
that it doesn't recognise the embedded host-identity), it re-runs the Phase 1
init queries one more time, then emits two new cleartext commands:

### Command `0x3f` — pair-begin signal

```
H>S  3f 02                      cmd=0x3f, arg=0x02
S>H  00 00                      status=OK, no body
```

Two bytes in, two bytes out. The `02` argument hasn't been varied; it might
be a sub-op selector or a fixed marker.

### Command `0x93` — pair request (host's side of the mutual challenge)

```
H>S  payload of 401 bytes:

  byte  0       93                          cmd ID
  bytes 1..4    3f 5f 17 00                 4-byte session token (random per pair)
  bytes 5..36   4e d2 de fd 4e c2 49 c4     32-byte context hash #1
                be 45 7f 3f 61 e4 9c 18     (probably H(session_token || init query
                6c 45 a0 0c a3 30 bb 69      responses) — proves host has seen
                be 72 5c d2 b2 6f 4a b8      the same setup the sensor did)
  bytes 37..    00 00 ...                   zero padding to fixed offset
  bytes 68..99  50 cd d7 7b 01 77 85 a3     32-byte context hash #2
                8f 82 a1 4a e3 88 9c af     (probably host's identity hash)
                a7 62 95 cf ab 4b 92 99
                4b f0 41 d9 13 f3 77 19
  bytes 100..   00 00 ...                   zero padding to fixed offset
                00 00 48 00                 length prefix (0x48 = 72 bytes)
                30 46 02 21 00 d3 50 52     72-byte DER-encoded ECDSA signature:
                52 d4 09 45 0a 8a b5 a5      SEQUENCE { INTEGER(33) r,
                61 c0 6e 7f 3f 7d ea f8                 INTEGER(33) s }
                4f 92 d4 3c 40 4e 77 2a     The signature is on P-256 (consistent
                86 3a b7 ba 3c 02 21 00      with the ECDHE_P256 cipher negotiated
                8d f1 f3 c8 7f 37 f5 8a      in Phase 3) and is presumably over
                b0 89 77 9c 8d 8f 4b bc      the two preceding context hashes.
                47 d4 b4 5e 6f ae 8a 95
                2c ff 6d 50 8b 25 da f4
  bytes 256..400  00 ...                    zero padding to 400 bytes
```

### Sensor's pair response

```
S>H  (768 bytes; first chunk)
  bytes 0..1   00 00                       status=OK
  bytes 2..5   3f 5f 17 00                 same session token echoed
  bytes 6..    {same 32-byte context hash  echoed from request
                #1 as host sent}
  ...          {same 32-byte context hash  echoed
                #2 as host sent}
  ...          00 00 ...                   padding
  bytes 384+   {new 4-byte token start}    sensor's portion begins
               d8 c5 ee 13 b0 56 e5 51     sensor's 32-byte context hash #1
               ac a3 e2 1d 76 73 b3 30      (analogous to host's hash #1 but
               3f 2e 90 5b c3 c4 74 07      from the sensor side)
               6d a9 b3 28 61 48 98 f2
               ...
               ac 7a af 69 81 0d 4f 9f     sensor's 32-byte context hash #2
               1e f1 e7 5e 36 24 2d 11     (sensor's identity hash)
               6b 36 e0 66 93 4d 39 79
               07 be c5 1d d8 5e bc c6
               ...
               00 00 48 00                 length prefix
               30 46 02 21 00 f4 19 02     72-byte DER ECDSA signature, sensor's

S>H  (34 bytes; trailing zeros — boundary artifact of bulk transfer)

S>H  (3 bytes)
  bytes        3d 73 02                    final status / counter
```

So the pair handshake is a **mutual challenge-response with EC signatures**.
Each side sends two 32-byte context hashes (one nonce-like, one
identity-like) and a DER ECDSA signature; the other side mirrors and
counter-signs. After this exchange both sides have enough material to derive
the PSK that Phase 3's TLS handshake will use.

The PSK is **not** sent on the wire. It is derived locally on each side from
the exchanged hashes plus per-side private material that was never
transmitted (presumably factory-burned into the sensor, and stored under
DPAPI on the host side after the pair completes).

After `0x93`'s exchange and before Phase 3 begins, the encrypted appdata
section likely contains a "write the new pairing blob to me" command from
host to sensor — this is what causes the sensor's stored blob (frame 175 of
try-3 vs frame 243 of try-6) to be different bytes. We have not yet decoded
that write command; it lives entirely inside Phase 4's encrypted traffic.

## Phase 3 — Custom TLS-like handshake

Captured frames 180–187. Uses TLS 1.2 record framing
(`16/14 03 03 LL LL …`) with a leading 4-byte length prefix
(`44 00 00 00`) only on host→sensor records. The cipher suite negotiated
is `0xc02e` = `TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384`, but the message
sequence diverges from RFC 5489.

Observed sequence:

```
frame 180  H>S  ClientHello                         44 00 00 00 | 16 03 03 00 49 | …
frame 183  S>H  ServerHello (cipher 0xc02e)         16 03 03 00 3d | …
frame 184  H>S  "Certificate" (custom payload)      44 00 00 00 | 16 03 03 02 2d | 0b 00 01 98 …
                + host's ChangeCipherSpec           14 03 03 00 01 01
                + host's encrypted Finished         16 03 03 00 28 …
frame 187  S>H  sensor's ChangeCipherSpec           14 03 03 00 01 01
                + sensor's encrypted Finished       16 03 03 00 28 …
frame 188+      application data only (17 03 03 …)
```

The host's "Certificate" message (frame 184) is **not** an X.509 chain. Its
408-byte body has the structure:

```
00 01 90                      cert_list_len = 0x190 = 400
  00 01 90                    cert(0) length = 400
    32 bytes                  context hash (probably H(ClientHello..ServerHello))
    32 bytes 00…              zero padding
    32 bytes                  second context hash (probably full handshake transcript so far)
    32 bytes 00…              zero padding
    02 20 00                  length prefix 0x220 ?
    32 bytes                  opaque (PSK identity? nonce?)
    00 00 01                  flags / length
    00 04 10 42               length prefix 0x41 = 65
    65 bytes                  EC point: 0x04 | X(32) | Y(32) — host's ECDH public key on P-256
    0f 00 00 48               length prefix 0x48 = 72
    30 46 02 21 00 …          DER ECDSA signature: SEQUENCE{INTEGER r(33), INTEGER s(33)}
       02 21 00 …
```

Read this as: **`{H(transcript_so_far), opaque, host_pubkey_P256, ECDSA(host)}`**
— a host-attestation envelope that combines what would normally be
`ClientKeyExchange` (ECDH) + a custom client-cert proof of possession into
one message. The signature is over the preceding context so the sensor can
verify the host both possesses its private key and has seen the correct
handshake state.

The sensor does not send a parallel "Certificate" of its own. We never
observed a server-side key share on the wire — that means the sensor's
contribution to the ECDH must be either inside `ServerHello.random` (which
the host treats specially) or carried within the encrypted Finished. The
former is more likely given the sensor's `ServerHello` random is
`00 05 2e d9 …` — the leading `00 05` and trailing `00 0e 00 00` look
structured rather than random.

The session key is then derived from `{ECDH_shared, PSK}` using the
SHA-384-based TLS 1.2 PRF (because the suite name ends in SHA384), and
all subsequent traffic is AES-256-CBC + HMAC-SHA384 wrapped (because the
suite is the `_CBC_` variant, not the `_GCM_` variant — note: this
contradicts the earlier libtudor comment in `[[project-synatudor-session-2]]`
that called the bulk crypto "AES-GCM". For this particular sensor +
firmware + driver combo the wire confirms CBC+HMAC, not GCM).

## Phase 4 — Encrypted application data

Captured frames 188 through end of pcap. All packets have the shape
`17 03 03 LL LL  …ciphertext…  …MAC…` on bulk OUT/IN with a leading
`44 00 00 00` length prefix on OUT only.

`tools/decode_capture.py` writes one line per record to
`encrypted.txt` so we can correlate timing of records with finger-touch
events for future analysis. The bodies are unreadable without the session
key (which we don't need to recover — re-pairing gives us a fresh one).

## Open questions for the next session

1. **Where does the sensor's ECDH public key live in Phase 3?** Either
   inside `ServerHello.random` or inside the encrypted Finished. The Phase
   2b mutual-challenge exchange now shows ECDSA signatures and context
   hashes, but does NOT contain the ECDH public-key share itself — so the
   ECDH still happens inside Phase 3. Need to compare `ServerHello.random`
   bytes across try-3 and try-6 to test whether `00 05 …` is structured.
2. **What's the second DPAPI blob in the pairing TLV?** Working hypothesis:
   one is the PSK, one is the host's signing private key. Now that we have
   try-6's blob (4906 bytes vs try-3's 4104 bytes), diff the two — the
   delta should reveal which TLV records are newly written by a fresh pair.
3. **How does the host write a new pairing blob to the sensor?** Almost
   certainly inside Phase 4's encrypted traffic, immediately after the
   handshake completes. To capture it cleartext we'd need to either
   decrypt the post-pair encrypted records (only possible if we extract
   the PSK from DPAPI — see open question #5) or coerce the pair flow to
   use a NULL cipher. Both are research-level.
4. **What clears the sensor-side blob?** The `tudor_unpair` IOCTL doesn't
   (try-3 → try-4 confirmed). Candidate paths: `VCSFW_CMD_RESET_OWNERSHIP`
   in synaTudor sources, or an `OnAppRequest` selector we haven't tried.
   We now have a workable workaround (fresh VM = re-pair), so this is
   lower priority for the from-scratch driver — we don't need to ever
   clear the sensor side because we'll just overwrite the blob with our
   own on each pair.
5. **Decode the `0x40 02 00 ffff …` argument bytes.** If the `0xffff` is a
   "give me everything" selector, smaller selectors likely return
   individual TLV records.
6. ~~**Decode response framing conclusively.**~~ **Resolved 2026-05-16** by
   `src/parser.c` against live sensor responses. Two distinct envelopes:
   - **Universal**: every cleartext response starts with `status_u16`
     (LE). `0x0000` = OK. Anything else is a command-specific error.
   - **0x8e family extra framing**: after the universal status, 0x8e
     responses carry `total_size_u32 | inner_size_u16 | subop_echo_u16
     | payload_bytes`. The total counts everything from itself onward;
     inner_size counts the payload only. The subop_echo confirms which
     sub-op the response is for.
   - Other commands (`0x01`, `0x19`, `0xaf`, `0x3e`, `0x40`) are
     `status_u16 | command_specific_body` with no further length
     header — body length is implicit from the URB.
7. **Decode the `0x93` pair-request structure conclusively.** Confirm
   field offsets are fixed (compare try-6 against a second fresh-pair
   capture from a third Windows install) and identify what private-key
   material on each side feeds the ECDSA signatures and the eventual PSK
   derivation.
8. **What does the sensor's 3-byte status `3d 73 02` (frame 317 in try-6)
   mean?** Looks like a sequence number or result code. Need a second
   pair capture to see whether the value is stable or varies.

## How to regenerate this analysis

To re-decode an existing pcap:

```
python3 tools/decode_capture.py captures/try-N.pcapng captures/try-N-decoded
```

Outputs in each decoded folder:

- `cleartext.txt` — Phases 1 and 2b cleartext commands
- `handshake.txt` — Phase 3 TLS handshake records
- `encrypted.txt` — Phase 4 record timing
- `sensor_cert.bin` — the bytes returned by `GET_CERTIFICATE_EX`

The decoder is deliberately format-agnostic — it classifies URBs only by
shape, not by command. Any new firmware / softpaq version will produce the
same kind of output, ready for hand-annotation.

## How to take a new capture

Connect-mode capture (sensor already paired with current Windows install):
just record `usbmon1` with Wireshark and trigger an enrollment.

Fresh-pair capture: this is the tricky one. Driver uninstall, new Windows
user, and pairing data unpair from Linux do **not** force a re-pair (we
tested all three — see `captures/try-4`, `try-5`). The only reliable way is
a Windows install on a different machine identity:

1. Create a new VM (`win10-fpcapture-2` or similar), fresh Win10/11 22H2.
2. Install HP softpaq SP144091 (Synaptics 6.0.118.1110), pinned URL:
   `https://ftp.hp.com/pub/softpaq/sp144001-144500/sp144091.exe`.
3. Pass through `06cb:00e7` via `<hostdev>`.
4. Start Wireshark on the host (`usbmon1`, no capture filter) BEFORE first
   fingerprint enrollment in the VM.
5. Enroll a finger inside the VM. The capture will contain the Phase 2b
   pair commands.

Note: the existing Linux-side `tudor_unpair` does NOT clear the sensor's
NVRAM blob, so the new VM will still see the old blob via
`GET_CERTIFICATE_EX` — but the host can't decrypt it, which is what
triggers the pair.
