#!/usr/bin/env python3
"""Generate the differential-test vector fixture for the Rust test suite.

Emits `tests/vectors_differential.txt`: a set of (message length, AAD length)
pairs whose ciphertext and tag are produced by the **independent** reference
implementation in `tools/ref_impl.py` — not by the Rust code under test.

The message and AAD bytes are deterministic functions of their lengths, so the
fixture only needs to store the lengths; `tests/differential_reference.rs`
reconstructs the inputs with the same formula and compares.

The reference implementation is self-checked (against the RFC 8439 / XChaCha draft
vectors and BLAKE3's official keyed vectors) *before* anything is emitted, so a fixture
cannot be produced by a reference implementation that has drifted -- the docstring said
so before the call existed, and a direct run of this script was the one path that
skipped it (`verify.sh` runs `ref_impl.py` first, which is not something this script can
rely on).

The crate's own KATs are deliberately *not* in that list: they are generated from this
same reference, so comparing against them would be circular and would check nothing the
external vectors above do not. The claim that they were checked is what this docstring
used to make; the list now names only anchors published by someone else.

Usage:
    python3 tools/gen_test_vectors.py            # write the fixture
    python3 tools/gen_test_vectors.py --check    # verify it is current
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "tests", "vectors_differential.txt")

# Fixed key/nonce: the fixture stays small, and the point of these vectors is
# length coverage, not key diversity (the KATs and the property tests cover
# keys).
KEY = bytes((i * 17 + 3) % 256 for i in range(32))
NONCE = bytes((i * 29 + 5) % 256 for i in range(24))


#: (message length, AAD length) pairs.
#:
#: The lengths straddle every internal boundary that still exists:
#:   * ChaCha20 64-byte block           (63/64/65, 127/128/129)
#:   * SSE2 / NEON 256-byte SIMD width  (255/256/257)
#:   * AVX2 512-byte SIMD width         (511/512/513)
#:   * BLAKE3 chunk boundary (1024), plus 2048 multiples, +-1
#: plus empty and single-byte messages, and AADs larger, smaller and equal in
#: size to the message -- the tag encodes both lengths, so their relative
#: magnitude matters.
#:
#: (79/80/81, 1) are retained from v0.2, when the tag head was 80 bytes; that
#: boundary is gone (the head is 48 bytes now), so they are extra nearby coverage
#: rather than a boundary witness. They stay because the committed fixture holds
#: their vectors; dropping them would mean regenerating tests/vectors_differential.txt.
PAIRS = [
    (0, 0), (0, 1), (0, 15), (0, 16), (0, 17), (0, 64), (0, 257),
    (1, 0), (1, 15), (1, 16), (1, 255), (1, 256),
    (2, 0),
    (15, 0), (16, 0), (17, 0),
    (31, 32), (32, 31), (33, 33),
    (63, 0), (64, 0), (65, 0),
    (63, 63), (64, 64), (65, 65),
    (79, 1), (80, 1), (81, 1),
    (127, 0), (128, 0), (129, 0),
    (191, 193), (192, 192), (193, 191),
    (255, 0), (256, 0), (257, 0),
    (255, 255), (256, 256), (257, 257),
    (511, 0), (512, 0), (513, 0),
    (1023, 0), (1024, 0), (1025, 0),
    (1025, 300), (2048, 0), (2049, 0),
]


def pt_for(n):
    return bytes((i * 37 + 11) % 256 for i in range(n))


def aad_for(n):
    return bytes((i * 91 + 7) % 256 for i in range(n))


def load_ref():
    spec = importlib.util.spec_from_file_location("ref", os.path.join(HERE, "ref_impl.py"))
    ref = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ref)
    # This is what makes the docstring's claim true. It checks the reference against
    # the published vectors (RFC 8439, draft-irtf-cfrg-xchacha-03, BLAKE3's official
    # file) before a single vector is emitted, and it raises on the first mismatch.
    # `verify.sh` runs `ref_impl.py` before this script, but the
    # script is also run directly, and that path used to produce a fixture from a
    # reference implementation nothing had anchored.
    ref.self_check()
    return ref


#: (message length, AAD length) pairs whose expected output is stored as a *digest*
#: instead of in full.
#:
#: A megabyte of ciphertext is two megabytes of hex, which is why the fixture above
#: stops at 2 KiB. Thirty-two bytes of digest per row buys the sizes that fixture
#: cannot reach -- in particular above `TAG_CONCAT_LIMIT`, where `derive_tag` goes
#: back to three `update` calls, so the two fixtures together witness both shapes
#: against the reference implementation rather than only against each other.
#:
#: The digest is BLAKE3 over `ciphertext || tag`, *hashing* rather than keyed: it is
#: a comparison device, so it must not be the same construction whose output it is
#: checking.
DIGEST_PAIRS = [
    # The contiguous-buffer switch is on `head.len() + aad.len() + msg.len()` against
    # `TAG_CONCAT_MIN..=TAG_CONCAT_LIMIT` (2048..=65536), and `head` is
    # `8 + NONCE_LEN + 16` = 48 bytes. So the message lengths that straddle the window
    # are 2000 and 65488, not 2048 and 65536 -- an earlier version of this list said
    # the latter and was wrong by the head's 48 bytes. Both boundaries are here, on
    # each side, so the switch itself is witnessed against the reference rather than
    # only against the crate's own two call shapes.
    (1_999, 0),      # 48 + 1999 = 2047: below the window, three calls
    (2_000, 0),      # 48 + 2000 = 2048: the bottom of the window, one call
    (2_048, 0),      # inside the window
    (65_488, 0),     # 48 + 65488 = 65536: the top of the window, still one call
    (65_489, 0),     # 48 + 65489 = 65537: one byte past it, three calls again
    (65_536, 0),     # also past it (48 + 65536 = 65584), a second three-call witness
    (100_000, 64),
    (1_000_000, 12_345),
    (1_048_576, 0),  # 1 MiB
]

OUT_LARGE = os.path.join(ROOT, "tests", "vectors_differential_large.txt")


def build_digests():
    """The large-size fixture: `msg_len aad_len blake3(ciphertext || tag)`."""
    ref = load_ref()
    digest = __import__("blake3")
    lines = [
        "# Large-message differential test vectors for XChaCha20-BLAKE3-SIV.",
        "#",
        "# Generated by tools/gen_test_vectors.py from tools/ref_impl.py. The expected",
        "# output is a digest rather than the ciphertext, because a megabyte of",
        "# ciphertext is two megabytes of hex: BLAKE3(ciphertext || tag), plain hashing,",
        "# computed by the same independent reference. Replayed by",
        "# tests/differential_reference.rs::differential_large_vectors_match_reference.",
        "# Do not edit by hand; re-run the generator.",
        "#",
        "# key   = " + KEY.hex(),
        "# nonce = " + NONCE.hex(),
        "#",
        "# plaintext[i] = (i * 37 + 11) % 256",
        "# aad[i]       = (i * 91 +  7) % 256",
        "#",
        "# <msg_len> <aad_len> <blake3(ciphertext || tag)_hex>",
        "",
    ]
    for n, a in DIGEST_PAIRS:
        ct, tag = ref.encrypt_x(KEY, NONCE, aad_for(a), pt_for(n))
        assert ref.decrypt_x(KEY, NONCE, aad_for(a), ct, tag) == pt_for(n), (n, a)
        lines.append(f"{n} {a} {digest.blake3(ct + tag).hexdigest()}")
    return "\n".join(lines) + "\n"


def build():
    ref = load_ref()
    lines = [
        "# Differential test vectors for XChaCha20-BLAKE3-SIV.",
        "#",
        "# Generated by tools/gen_test_vectors.py from tools/ref_impl.py, which is",
        "# an independent implementation written from the RFC 8439 /",
        "# draft-irtf-cfrg-xchacha-03 pseudocode and the BLAKE3 specification.",
        "# It self-checks against published RFC, HChaCha20 and official-BLAKE3",
        "# vectors before emitting anything.",
        "# Do not edit by hand; re-run the generator.",
        "#",
        "# key   = " + KEY.hex(),
        "# nonce = " + NONCE.hex(),
        "#",
        "# plaintext[i] = (i * 37 + 11) % 256",
        "# aad[i]       = (i * 91 +  7) % 256",
        "#",
        "# <msg_len> <aad_len> <ciphertext_hex> <tag_hex>",
        "#",
        "# An empty ciphertext is written as `-` (an empty field would collapse",
        "# under whitespace splitting and shift the tag into the wrong column).",
        "# The tag is always TAG_LEN (65) bytes, so it is never empty.",
        "",
    ]
    for n, a in PAIRS:
        ct, tag = ref.encrypt_x(KEY, NONCE, aad_for(a), pt_for(n))
        # The fixture must be self-consistent before it is written.
        assert ref.decrypt_x(KEY, NONCE, aad_for(a), ct, tag) == pt_for(n), (n, a)
        assert len(tag) == ref.TAG_LEN, (n, a)
        lines.append(f"{n} {a} {ct.hex() or '-'} {tag.hex()}")
    return "\n".join(lines) + "\n"


def main():
    for path, text, count in ((OUT, build(), len(PAIRS)),
                              (OUT_LARGE, build_digests(), len(DIGEST_PAIRS))):
        if "--check" in sys.argv:
            with open(path) as fh:
                if fh.read() == text:
                    print(f"{path} is current ({count} vectors)")
                    continue
            print(f"{path} is STALE -- re-run without --check")
            sys.exit(1)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)
        print(f"wrote {path} ({count} vectors)")


if __name__ == "__main__":
    main()
