#!/usr/bin/env python3
"""Independent reference implementation of XChaCha20-Poly1305-SIV (with CTX).

Written from the RFC 8439 / draft-irtf-cfrg-xchacha-03 pseudocode plus the
c2sp.org ChaCha20-Poly1305-SIV specification, then extended with the CTX
context-commitment transform: the tag XORs in a domain-separated BLAKE3
commitment to the associated data.

This is deliberately NOT derived from the Rust code under test.  It exists so
the known-answer vectors can be regenerated after any change to the tag, and so
a shared bug would have to be made independently in two implementations to slip
through.  Before it emits anything it self-checks against published vectors:

  * RFC 8439 §2.3.2                        ChaCha20 block function
  * RFC 8439 §2.5.2                        Poly1305
  * draft-irtf-cfrg-xchacha-03 §2.2.1      HChaCha20
  * c2sp.org ChaCha20-Poly1305-SIV TV1/6   the base 16-byte-nonce construction

Because the c2sp.org vectors pin `encrypt16`, the shared prefix of the 24-byte
construction (subkey derivation by ChaCha20 block, Poly1305 over the padded
input, the tag block, the encryption-key block) is anchored to an external
standard rather than to this file.

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

#: BLAKE3 `derive_key` context string for the CTX commitment term.
#:
#: This string IS part of the wire format: changing it changes every tag.  It is
#: hardcoded and application-specific, which is what BLAKE3 requires of a
#: `derive_key` context.
COMMITMENT_CONTEXT = "XChaCha20-Poly1305-SIV context commitment v1"

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


# ── Poly1305 (RFC 8439 §2.5) ────────────────────────────────────────────

P1305 = (1 << 130) - 5


def poly1305_mac(key32, msg):
    r = int.from_bytes(key32[0:16], "little")
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key32[16:32], "little")

    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block + b"\x01", "little")  # append hibit
        acc = ((acc + n) * r) % P1305
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, "little")


def poly1305_aead(key32, aad, plaintext):
    """RFC 8439 §2.8: pad16(aad) || pad16(pt) || le64(len_aad) || le64(len_pt)."""
    def pad16(x):
        if len(x) % 16 == 0:
            return b""
        return b"\x00" * (16 - (len(x) % 16))

    mac_data = aad + pad16(aad) + plaintext + pad16(plaintext)
    mac_data += struct.pack("<QQ", len(aad), len(plaintext))
    return poly1305_mac(key32, mac_data)


# ── The CTX commitment term ─────────────────────────────────────────────


def context_commitment(aad):
    """BLAKE3 in `derive_key` mode, bound to COMMITMENT_CONTEXT.

    `derive_key` and not `hash`: BLAKE3's plain hash mode carries no context, so
    `BLAKE3(aad)` as computed here would be bit-identical to what any other
    protocol computing `BLAKE3(aad)` would produce.  The CTX transform XORs this
    value into the tag, so freedom from cross-protocol collisions is exactly what
    the commitment needs; `derive_key` gives the term a domain of its own (the
    context key is folded in and the block is flagged DERIVE_KEY_MATERIAL), and
    it makes "the wrong mode was used" detectable by a single vector.
    """
    return blake3.blake3(aad, derive_key_context=COMMITMENT_CONTEXT).digest()


# ── The scheme ──────────────────────────────────────────────────────────


def derive_subkeys_x(key, nonce24):
    """XChaCha20-style: HChaCha20(key, nonce[0..16]) then one ChaCha20 block
    under SUBKEY_DOMAIN || nonce[16..24] (the domain constant sits in the
    *nonce*, at counter 0 -- not in the counter slot)."""
    subkey = hchacha20(key, nonce24[0:16])
    sub_nonce = SUBKEY_DOMAIN + nonce24[16:24]
    buf = chacha20_block(subkey, 0, sub_nonce)
    return buf[0:32], buf[32:64]


def encrypt_x(key, nonce24, aad, pt):
    poly_key, tag_key = derive_subkeys_x(key, nonce24)

    p = poly1305_aead(poly_key, aad, pt)
    inner = chacha20_block(tag_key, int.from_bytes(p[0:4], "little"), p[4:16])[0:32]
    # CTX context-commitment transform.
    tag = bytes(a ^ b for a, b in zip(inner, context_commitment(aad)))

    enc_key = chacha20_block(
        tag_key, int.from_bytes(tag[0:4], "little"), tag[4:16]
    )[32:64]
    ct = chacha20_xor(enc_key, 0, tag[16:28], pt)
    return ct, tag


def decrypt_x(key, nonce24, aad, ct, tag):
    poly_key, tag_key = derive_subkeys_x(key, nonce24)

    enc_key = chacha20_block(
        tag_key, int.from_bytes(tag[0:4], "little"), tag[4:16]
    )[32:64]
    pt = chacha20_xor(enc_key, 0, tag[16:28], ct)

    p = poly1305_aead(poly_key, aad, pt)
    inner = chacha20_block(tag_key, int.from_bytes(p[0:4], "little"), p[4:16])[0:32]
    computed = bytes(a ^ b for a, b in zip(inner, context_commitment(aad)))
    if computed != tag:
        return None
    return pt


def encrypt16(key, nonce16, aad, pt):
    """c2sp.org base construction (no CTX), for the standard KAT vectors."""
    sub_ctr = int.from_bytes(nonce16[0:4], "little")
    subkeys = chacha20_block(key, sub_ctr, nonce16[4:16])
    poly_key, tag_key = subkeys[0:32], subkeys[32:64]

    p = poly1305_aead(poly_key, aad, pt)
    tag = chacha20_block(tag_key, int.from_bytes(p[0:4], "little"), p[4:16])[0:32]
    enc_key = chacha20_block(
        tag_key, int.from_bytes(tag[0:4], "little"), tag[4:16]
    )[32:64]
    ct = chacha20_xor(enc_key, 0, tag[16:28], pt)
    return ct, tag


def hx(b):
    return b.hex()


# ── Self-checks against published vectors ───────────────────────────────


def self_check():
    # RFC 8439 §2.3.2 ChaCha20 block function.
    key = bytes(range(0x00, 0x20))
    nonce = bytes.fromhex("000000090000004a00000000")
    blk = chacha20_block(key, 1, nonce)
    assert blk[:16].hex() == "10f1e7e4d13b5915500fdd1fa32071c4", blk[:16].hex()
    assert blk[16:32].hex() == "c7d1f4c733c068030422aa9ac3d46c4e", blk[16:32].hex()

    # RFC 8439 §2.5.2 Poly1305.
    pk = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
    got = poly1305_mac(pk, b"Cryptographic Forum Research Group").hex()
    assert got == "a8061dc1305136c6c22b8baf0c0127a9", got

    # draft-irtf-cfrg-xchacha-03 §2.2.1 HChaCha20.
    hk = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    hn = bytes.fromhex("000000090000004a0000000031415927")
    got = hchacha20(hk, hn).hex()
    assert got == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc", got

    # c2sp.org ChaCha20-Poly1305-SIV Test Vectors 1 and 6, so the base
    # construction is pinned to the published values rather than to itself.
    k = bytes.fromhex("1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2")
    n = bytes.fromhex("530ee5e3dae7693017d28e5d7c6936ce")
    ct, tag = encrypt16(k, n, b"", b"")
    assert ct == b"", ct.hex()
    got = tag.hex()
    assert got == "85ebd6b3a2dbad07d4811283aaf9777acff58bdab40939a13237be73d3ddd73a", got

    aad = bytes.fromhex("2891ec111a27c55b3a6757ff173ef9cfc02bb682bcee4aaa317715b0b7895a58")
    pt = bytes.fromhex("aeadc48d4a2ea7ee06f9f41a6fbcd651ac5df158860e14af1fb0ebbe0a04bab2")
    ct, tag = encrypt16(k, n, aad, pt)
    got = ct.hex()
    assert got == "10287f0d994ca8b920dcede7ce86a29a055ac8e1c0ca14fe651bb363a2af7e03", got
    got = tag.hex()
    assert got == "9283515c1a67bf9234494025356684abae8325ad5a2f7ce275ac7fa49d88d735", got

    print("RFC 8439 / draft-irtf-cfrg-xchacha-03 / c2sp.org sanity checks: PASS\n")


# ── The 24-byte-nonce vectors (with CTX) ────────────────────────────────

LADUE = bytes.fromhex(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
    "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
    "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
    "637265656e20776f756c642062652069742e"
)

VECTORS = [
    (
        "kat_draft_key",
        "test_xchacha20_poly1305_siv_kat_draft_key",
        bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
        bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657"),
        bytes.fromhex("50515253c0c1c2c3c4c5c6c7"),
        LADUE,
    ),
    (
        "kat_c2sp_key",
        "test_xchacha20_poly1305_siv_kat_c2sp_key",
        bytes.fromhex("1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2"),
        bytes.fromhex("530ee5e3dae7693017d28e5d7c6936ce0001020304050607"),
        b"",
        LADUE,
    ),
    (
        "kat_empty",
        "test_xchacha20_poly1305_siv_kat_empty",
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
    print("--- CMT-3 check (same K,N,M; AAD differs) ---")
    print(f"tag(A) = {hx(tag_a)}")
    print(f"tag(B) = {hx(tag_b)}")
    print(f"tags differ: {tag_a != tag_b}")
    print(f"ct   differ: {ct_a != ct_b}")
    print()

    # The commitment term must NOT equal the bare hash of the same AAD, or the
    # derive_key domain separation is not in effect.
    aad = b"aad-A"
    bare = blake3.blake3(aad).digest()
    dk = context_commitment(aad)
    print("--- commitment mode check ---")
    print(f"BLAKE3(aad)         = {hx(bare)}")
    print(f"derive_key(aad)     = {hx(dk)}")
    print(f"distinct (required): {bare != dk}")


if __name__ == "__main__":
    main()
