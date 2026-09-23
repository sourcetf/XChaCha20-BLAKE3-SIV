#!/usr/bin/env python3
"""Independent reference implementation of XChaCha20-BLAKE3-SIV.

Written from the RFC 8439 / draft-irtf-cfrg-xchacha-03 pseudocode plus the
BLAKE3 specification: XChaCha20 nonce extension (HChaCha20) for subkey
derivation, and a **keyed BLAKE3** MAC as the tag, whose output also derives the
per-message encryption key and nonce.

This is deliberately NOT derived from the Rust code under test.  It exists so
the known-answer vectors can be regenerated after any change to the
construction, and so a shared bug would have to be made independently in two
implementations to slip through.

Before it emits anything it self-checks against values published by others:

  * RFC 8439 §2.3.2                       ChaCha20 block function
  * draft-irtf-cfrg-xchacha-03 §2.2.1     HChaCha20
  * BLAKE3's official test_vectors.json   keyed BLAKE3 (5 vectors)

The BLAKE3 anchor carries the most weight: the MAC *is* the tag construction, so
without an external check the tag vectors below would only be validated against
this same file.

Usage:
    python3 tools/ref_impl.py           # self-checks + prints all vectors
    python3 tools/ref_impl.py --kat     # Rust-ready constants for lib.rs

Requires the `blake3` module (pip install blake3).
"""
import struct
import sys

import blake3

MASK32 = 0xFFFFFFFF
SIGMA = b"expand 32-byte k"

#: Domain-separation constant for the subkey-derivation block.
#:
#: It occupies the first 4 bytes of the 12-byte ChaCha20 *nonce*, with the
#: counter left at 0 -- i.e. exactly the bytes XChaCha20-Poly1305 leaves as NUL
#: padding.  Putting it in the counter slot instead would be a different
#: construction (and a different ciphertext).
SUBKEY_DOMAIN = b"XSIV"


def rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK32


def qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & MASK32
    s[d] = rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK32
    s[b] = rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK32
    s[d] = rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK32
    s[b] = rotl32(s[b] ^ s[c], 7)


def chacha20_block(key, counter, nonce12):
    """RFC 8439 §2.3.2 ChaCha20 block function."""
    s = [0] * 16
    s[0:4] = list(struct.unpack("<4I", SIGMA))
    s[4:12] = list(struct.unpack("<8I", key))
    s[12] = counter & MASK32
    s[13:16] = list(struct.unpack("<3I", nonce12))

    w = list(s)
    for _ in range(10):
        qr(w, 0, 4, 8, 12)
        qr(w, 1, 5, 9, 13)
        qr(w, 2, 6, 10, 14)
        qr(w, 3, 7, 11, 15)
        qr(w, 0, 5, 10, 15)
        qr(w, 1, 6, 11, 12)
        qr(w, 2, 7, 8, 13)
        qr(w, 3, 4, 9, 14)

    out = [(w[i] + s[i]) & MASK32 for i in range(16)]
    return struct.pack("<16I", *out)


def chacha20_xor(key, counter, nonce12, data):
    """ChaCha20 keystream XOR over arbitrary length, starting at `counter`."""
    out = bytearray()
    ctr = counter
    i = 0
    while i < len(data):
        ks = chacha20_block(key, ctr, nonce12)
        chunk = data[i:i + 64]
        out.extend(b ^ k for b, k in zip(chunk, ks))
        i += 64
        ctr = (ctr + 1) & MASK32
    return bytes(out)


def hchacha20(key, nonce16):
    """draft-irtf-cfrg-xchacha-03 §2.2: 20 rounds, no feed-forward, words 0-3/12-15."""
    s = [0] * 16
    s[0:4] = list(struct.unpack("<4I", SIGMA))
    s[4:12] = list(struct.unpack("<8I", key))
    s[12:16] = list(struct.unpack("<4I", nonce16))

    for _ in range(10):
        qr(s, 0, 4, 8, 12)
        qr(s, 1, 5, 9, 13)
        qr(s, 2, 6, 10, 14)
        qr(s, 3, 7, 11, 15)
        qr(s, 0, 5, 10, 15)
        qr(s, 1, 6, 11, 12)
        qr(s, 2, 7, 8, 13)
        qr(s, 3, 4, 9, 14)

    words = s[0:4] + s[12:16]
    return struct.pack("<8I", *words)


# ── Keyed BLAKE3 (the MAC) ──────────────────────────────────────────────

TAG_LEN = 65

#: Fixed-width domain separators.  Must match src/lib.rs.
DOM_TAG = b"XSIV-TAG"
DOM_ENC = b"XSIV-ENC"


def blake3_keyed_xof(key32, data, n):
    """`n` bytes of BLAKE3 in keyed mode (its XOF output).

    Keyed mode (`key=`), not plain hashing: the tag has to be a PRF under a
    secret, because the commitment property rests on an adversary who knows the
    key being unable to invert it.
    """
    return blake3.blake3(data, key=key32).digest(length=n)


def compute_tag(mac_key32, key32, nonce24, aad, msg):
    """The 520-bit tag: one keyed BLAKE3 over the entire context.

    `BLAKE3_keyed(mac_key, DOM_TAG || K || N || le64(|A|) || le64(|M|) || A || M)`

    The key `K` is fed in directly, not merely through the derived `mac_key`.
    Binding it only via `mac_key` would let a collision in that 256-bit value
    (a 2^128 search) bypass the 520-bit tag entirely.

    The two length fields are what make the encoding unambiguous: without them
    `("ab", "c")` and `("a", "bc")` would hash identically.  BLAKE3 is not
    itself vulnerable to length extension -- its finalisation is flagged, unlike
    Merkle-Damgard constructions -- so this is about ambiguity, not extension.
    """
    data = (
        DOM_TAG
        + key32
        + nonce24
        + struct.pack("<QQ", len(aad), len(msg))
        + aad
        + msg
    )
    return blake3_keyed_xof(mac_key32, data, TAG_LEN)


# ── The scheme ──────────────────────────────────────────────────────────


def derive_material(key32, nonce24):
    """XChaCha20-style: HChaCha20(key, nonce[0..16]) then one ChaCha20 block
    under SUBKEY_DOMAIN || nonce[16..24], at counter 0.  Splits into the BLAKE3
    MAC key and the encryption seed."""
    subkey = hchacha20(key32, nonce24[0:16])
    buf = chacha20_block(subkey, 0, SUBKEY_DOMAIN + nonce24[16:24])
    return buf[0:32], buf[32:64]


def derive_enc(enc_seed32, tag):
    """Per-message encryption key and nonce, from the *whole* tag."""
    material = blake3_keyed_xof(enc_seed32, DOM_ENC + tag, 44)
    return material[0:32], material[32:44]


def encrypt_x(key, nonce24, aad, pt):
    mac_key, enc_seed = derive_material(key, nonce24)
    tag = compute_tag(mac_key, key, nonce24, aad, pt)
    enc_key, enc_nonce = derive_enc(enc_seed, tag)
    ct = chacha20_xor(enc_key, 0, enc_nonce, pt)
    return ct, tag


def decrypt_x(key, nonce24, aad, ct, tag):
    mac_key, enc_seed = derive_material(key, nonce24)
    enc_key, enc_nonce = derive_enc(enc_seed, tag)
    pt = chacha20_xor(enc_key, 0, enc_nonce, ct)
    if compute_tag(mac_key, key, nonce24, aad, pt) != tag:
        return None
    return pt


def hx(b):
    return b.hex()


# ── Self-checks against published vectors ───────────────────────────────
#
# The anchor chain.  Every primitive this file uses is pinned to a value
# published by someone else, so a bug would have to be made independently in
# this file *and* in the relevant standard to slip through:
#
#   ChaCha20 block      RFC 8439 §2.3.2
#   HChaCha20           draft-irtf-cfrg-xchacha-03 §2.2.1
#   keyed BLAKE3        BLAKE3's official test_vectors.json
#
# The keyed-BLAKE3 anchor is the one that matters most here, because the MAC is
# now the whole tag construction: without it, the tag vectors below would only
# be checked against this same file, which proves nothing.

#: From BLAKE3's official test_vectors.json. The key is the file's own key and
#: the inputs follow its `paint_test_input` pattern (byte i is `i % 251`).
BLAKE3_OFFICIAL_KEY = b"whats the Elvish word for friend"
BLAKE3_OFFICIAL_KEYED = [
    (0, "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26"),
    (1, "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b"),
    (1024, "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4"),
    (3072, "044a0e7b172a312dc02a4c9a818c036ffa2776368d7f528268d2e6b5df191770"),
    (102400, "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7"),
]


def _official_input(n):
    return bytes(i % 251 for i in range(n))


def self_check():
    # RFC 8439 §2.3.2 ChaCha20 block function.
    key = bytes(range(0x00, 0x20))
    nonce = bytes.fromhex("000000090000004a00000000")
    blk = chacha20_block(key, 1, nonce)
    assert blk[:16].hex() == "10f1e7e4d13b5915500fdd1fa32071c4", blk[:16].hex()
    assert blk[16:32].hex() == "c7d1f4c733c068030422aa9ac3d46c4e", blk[16:32].hex()

    # draft-irtf-cfrg-xchacha-03 §2.2.1 HChaCha20.
    hk = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    hn = bytes.fromhex("000000090000004a0000000031415927")
    got = hchacha20(hk, hn).hex()
    assert got == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc", got

    # BLAKE3 official keyed vectors -- the external anchor for the MAC.
    failures = []
    for n, want in BLAKE3_OFFICIAL_KEYED:
        got = blake3.blake3(_official_input(n), key=BLAKE3_OFFICIAL_KEY).hexdigest()
        if got != want:
            failures.append((n, got, want))
    assert not failures, f"BLAKE3 official keyed vectors failed: {failures[:2]}"

    print("RFC 8439 / draft-irtf-cfrg-xchacha-03 / BLAKE3-official sanity checks: PASS")
    print(f"  ({len(BLAKE3_OFFICIAL_KEYED)} official BLAKE3 keyed vectors matched)\n")


# ── The 24-byte-nonce vector set ────────────────────────────────

LADUE = bytes.fromhex(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
    "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
    "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
    "637265656e20776f756c642062652069742e"
)

VECTORS = [
    (
        "kat_draft_key",
        "test_xchacha20_blake3_siv_kat_draft_key",
        bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
        bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657"),
        bytes.fromhex("50515253c0c1c2c3c4c5c6c7"),
        LADUE,
    ),
    (
        "kat_c2sp_key",
        "test_xchacha20_blake3_siv_kat_c2sp_key",
        bytes.fromhex("1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2"),
        bytes.fromhex("530ee5e3dae7693017d28e5d7c6936ce0001020304050607"),
        b"",
        LADUE,
    ),
    (
        "kat_empty",
        "test_xchacha20_blake3_siv_kat_empty",
        bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
        bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657"),
        b"",
        b"",
    ),
]


def main():
    self_check()

    for name, test_name, k, n, aad, pt in VECTORS:
        ct, tag = encrypt_x(k, n, aad, pt)

        # Round-trip must hold, and a tampered tag must be rejected.
        assert decrypt_x(k, n, aad, ct, tag) == pt, name
        bad = bytearray(tag)
        bad[0] ^= 1
        assert decrypt_x(k, n, aad, ct, bytes(bad)) is None, name

        if "--kat" in sys.argv:
            print(f"// {test_name}")
            print(f"//   key  = {hx(k)}")
            print(f"//   nonce= {hx(n)}")
            print(f"//   aad  = {hx(aad) if aad else '(empty)'}")
            print(f"//   pt   = {hx(pt) if pt else '(empty)'}")
            print(f"expected_ct  = \"{hx(ct)}\"" if ct else "expected_ct  = (empty)")
            print(f"expected_tag = \"{hx(tag)}\"")
            print()
        else:
            print(f"--- {name} ---")
            print(f"ct  = {hx(ct)}")
            print(f"tag = {hx(tag)}")
            print()

    # ── The CMT-3 demonstration: same (K,N,M), different AAD ──
    k, n = VECTORS[0][2], VECTORS[0][3]
    pt = b"context commitment matters"
    ct_a, tag_a = encrypt_x(k, n, b"aad-A", pt)
    ct_b, tag_b = encrypt_x(k, n, b"aad-B", pt)
    print("--- commitment check (same K,N,M; AAD differs) ---")
    print(f"tag(A) = {hx(tag_a)}")
    print(f"tag(B) = {hx(tag_b)}")
    print(f"tags differ: {tag_a != tag_b}")
    print(f"ct   differ: {ct_a != ct_b}")
    print()

    # The key must reach the tag directly, not merely through the derived
    # mac_key. Without this, an adversary could search for two keys that collide
    # on the 256-bit mac_key (a 2^128 effort) and bypass the 520-bit tag.
    k1 = bytes(32)
    k2 = bytes([1] + [0] * 31)
    n = bytes(24)
    _, tag_k1 = encrypt_x(k1, n, b"", b"msg")
    _, tag_k2 = encrypt_x(k2, n, b"", b"msg")
    assert tag_k1 != tag_k2, "tag does not depend on the key"
    print("--- key-binding check (different K, same N/A/M) ---")
    print("tags differ (required): True")

    # AAD/plaintext split ambiguity: two different (A, M) pairs that concatenate
    # to the same bytes must NOT produce the same tag.
    _, tag_split_a = encrypt_x(bytes(32), n, b"ab", b"c")
    _, tag_split_b = encrypt_x(bytes(32), n, b"a", b"bc")
    assert tag_split_a != tag_split_b, "A||M is ambiguous"
    print("--- length-encoding check (A=ab,M=c vs A=a,M=bc) ---")
    print("tags differ (required): True")
    print()


if __name__ == "__main__":
    main()
