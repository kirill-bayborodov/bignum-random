#!/usr/bin/env python3
"""Run AES-256 CTR_DRBG use-df PR=false CAVP-style records."""
from __future__ import annotations

import ctypes
import re
import sys
from pathlib import Path

KEY_BYTES = 32
BLOCK_BYTES = 16
MAX_CASES = 4096


class Context(ctypes.Structure):
    _fields_ = [
        ("key", ctypes.c_uint8 * KEY_BYTES),
        ("v", ctypes.c_uint8 * BLOCK_BYTES),
        ("reseed_counter", ctypes.c_uint64),
        ("initialized", ctypes.c_uint8),
    ]


def cbuf(data: bytes):
    return (ctypes.c_uint8 * len(data)).from_buffer_copy(data) if data else None


def call(lib, name, *args):
    fn = getattr(lib, name)
    rc = fn(*args)
    if rc != 0:
        raise RuntimeError(f"{name} failed with status {rc}")


def parse_cases(path: Path):
    cases = []
    section = None
    current = {}
    for raw in path.read_text(encoding="ascii").splitlines() + [""]:
        line = raw.strip()
        if line.startswith("[") and line.endswith("]") and ("use df" in line or "no df" in line):
            section = line
            current = {}
            continue
        if line.startswith("[") and line.endswith("]"):
            line = line[1:-1]
        if not line:
            if "EntropyInput" in current and section == "[AES-256 use df]":
                cases.append(current)
                current = {}
            continue
        if " = " in line:
            key, value = line.split(" = ", 1)
            current.setdefault(key, []).append(value)
    return cases


def unhex(values, key):
    value = values.get(key, [""])[0]
    return bytes.fromhex(value) if value else b""


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} LIBRARY VECTOR_RSP", file=sys.stderr)
        return 2
    lib = ctypes.CDLL(sys.argv[1])
    lib.bignum_ctr_drbg_instantiate.argtypes = [ctypes.POINTER(Context), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
    lib.bignum_ctr_drbg_reseed.argtypes = [ctypes.POINTER(Context), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
    lib.bignum_ctr_drbg_generate.argtypes = [ctypes.POINTER(Context), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
    cases = parse_cases(Path(sys.argv[2]))
    if not cases:
        raise RuntimeError("no AES-256 use-df cases found")
    passed = 0
    for case in cases[:MAX_CASES]:
        ctx = Context()
        entropy = unhex(case, "EntropyInput")
        nonce = unhex(case, "Nonce")
        personalization = unhex(case, "PersonalizationString")
        if len(entropy) != 32 or len(nonce) != 16:
            raise RuntimeError(f"bad parsed lengths COUNT={case.get('COUNT', ['?'])[0]} entropy={len(entropy)} nonce={len(nonce)} keys={sorted(case)}")
        call(lib, "bignum_ctr_drbg_instantiate", ctypes.byref(ctx), cbuf(entropy), len(entropy), cbuf(nonce), len(nonce), cbuf(personalization), len(personalization))
        additions = case.get("AdditionalInput", [""])
        while len(additions) < 2:
            additions.append("")
        output = (ctypes.c_uint8 * 64)()
        if "EntropyInputPR" in case:
            pr_entropy = case["EntropyInputPR"]
            for index in range(2):
                entropy_pr = bytes.fromhex(pr_entropy[index])
                extra = bytes.fromhex(additions[index]) if additions[index] else b""
                call(lib, "bignum_ctr_drbg_reseed", ctypes.byref(ctx), cbuf(entropy_pr), len(entropy_pr), cbuf(extra), len(extra))
                call(lib, "bignum_ctr_drbg_generate", ctypes.byref(ctx), output, 64, None, 0)
        else:
            if "EntropyInputReseed" in case:
                reseed_entropy = unhex(case, "EntropyInputReseed")
                reseed_additional = unhex(case, "AdditionalInputReseed")
                call(lib, "bignum_ctr_drbg_reseed", ctypes.byref(ctx), cbuf(reseed_entropy), len(reseed_entropy), cbuf(reseed_additional), len(reseed_additional))
            for addition in additions[:2]:
                extra = bytes.fromhex(addition) if addition else b""
                call(lib, "bignum_ctr_drbg_generate", ctypes.byref(ctx), output, 64, cbuf(extra), len(extra))
        expected = bytes.fromhex(case["ReturnedBits"][0])
        got = bytes(output)
        if got != expected:
            raise AssertionError(f"COUNT {case.get('COUNT', ['?'])[0]} mismatch: {got.hex()} != {expected.hex()}")
        passed += 1
    mode = "PR=true" if "EntropyInputPR" in cases[0] else "PR=false"
    print(f"AES-256 use-df {mode} vectors: PASS ({passed} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
