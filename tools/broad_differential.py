#!/usr/bin/env python3
"""Broad differential test: thousands of random vectors, this crate vs the reference.

`tools/gen_test_vectors.py` pins the internal *length boundaries* with a fixture
that lives in the repository.  This covers what such a fixture cannot: random
keys, nonces and message bytes, at random lengths.  A fixture that reconstructs
its inputs as a function of their lengths — which is what keeps it small enough to
commit — can never exercise an arbitrary key or an arbitrary byte.

It pushes the vectors through `examples/xsiv_stdin.rs` rather than storing them,
so nothing is added to the repository; the reference outputs come from
`tools/ref_impl.py`, the same independent implementation the committed fixture
comes from.

    python3 tools/broad_differential.py [count] [seed] [--features <list>]

`--features` is passed to cargo, which is how the two BLAKE3 backends are
compared: the same vectors must produce the same bytes with BLAKE3's C/assembly
kernels (the default) and with `--features pure`.

Requires the `blake3` module (pip install blake3).  Exits non-zero on the first
mismatch it reports, printing the vector that produced it.

The mix is deliberate: most vectors are small (0-48 bytes, where the scalar tail
and the 64-byte ChaCha20 block boundary live), a slice is exactly at the sizes the
SIMD dispatch switches on, and ~5% are sizes that push the tag through BLAKE3's
contiguous-input call shape rather than the three-update one.
"""
import importlib.util
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

#: Lengths the SIMD dispatch switches on, plus the BLAKE3 chunk boundary.
BOUNDARY_LENGTHS = [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
                    191, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2048]


def load_ref():
    spec = importlib.util.spec_from_file_location("ref", os.path.join(HERE, "ref_impl.py"))
    ref = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ref)
    return ref


def vectors(count, seed):
    """Yield `(key, nonce, aad, msg)` tuples, deterministically."""
    rng = random.Random(seed)
    for i in range(count):
        key = bytes(rng.getrandbits(8) for _ in range(32))
        nonce = bytes(rng.getrandbits(8) for _ in range(24))

        roll = rng.random()
        if roll < 0.05:
            # Long enough to take the tag's contiguous path (>= 2048 - 80 bytes).
            msg_len = rng.randrange(2048, 4096)
            aad_len = rng.randrange(0, 64)
        elif roll < 0.25:
            msg_len = rng.choice(BOUNDARY_LENGTHS)
            aad_len = rng.choice(BOUNDARY_LENGTHS)
        else:
            msg_len = rng.randrange(0, 49)
            aad_len = rng.randrange(0, 49)

        aad = bytes(rng.getrandbits(8) for _ in range(aad_len))
        msg = bytes(rng.getrandbits(8) for _ in range(msg_len))
        yield key, nonce, aad, msg


def run_crate(pairs, features):
    """Feed the vectors to the crate, return its outputs."""
    lines = [
        "{} {} {} {}".format(
            key.hex(), nonce.hex(), aad.hex() or "-", msg.hex() or "-"
        )
        for key, nonce, aad, msg in pairs
    ]
    cmd = ["cargo", "run", "--release", "--quiet", "--example", "xsiv_stdin"]
    if features:
        cmd += ["--features", features]
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        input="\n".join(lines) + "\n",
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.exit(f"the crate's own tool failed:\n{proc.stderr}")
    out = [line for line in proc.stdout.splitlines() if line.strip()]
    assert len(out) == len(lines), f"{len(out)} outputs for {len(lines)} vectors"
    return out


def main():
    argv = sys.argv[1:]
    features = None
    if "--features" in argv:
        i = argv.index("--features")
        features = argv[i + 1]
        del argv[i:i + 2]
    count = int(argv[0]) if argv else 4000
    seed = int(argv[1]) if len(argv) > 1 else 20260925

    ref = load_ref()
    pairs = list(vectors(count, seed))
    got = run_crate(pairs, features)

    mismatches = []
    contiguous = 0
    for (key, nonce, aad, msg), line in zip(pairs, got):
        want_ct, want_tag = ref.encrypt_x(key, nonce, aad, msg)
        want = f"{want_ct.hex() or '-'} {want_tag.hex()}"
        if 80 + len(aad) + len(msg) >= 2048:
            contiguous += 1
        if line.strip() != want:
            mismatches.append((key, nonce, aad, msg, line.strip(), want))

    print(f"vectors:            {count} (seed {seed}, features {features or 'default'})")
    print(f"contiguous tag:     {contiguous}")
    print(f"mismatches:         {len(mismatches)}")
    for key, nonce, aad, msg, got_line, want_line in mismatches[:3]:
        print(f"  key={key.hex()} nonce={nonce.hex()}")
        print(f"    aad_len={len(aad)} msg_len={len(msg)}")
        print(f"    got  {got_line[:120]}")
        print(f"    want {want_line[:120]}")

    if mismatches:
        sys.exit(1)
    print("all vectors match the independent reference implementation")


if __name__ == "__main__":
    main()
