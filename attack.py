# =============================================================================
# attack.py  —  Brute-force and cryptanalysis attacks on S-AES-CFB
# =============================================================================
#
# S-AES has a 16-bit key space → only 65,536 possible keys.
# This makes exhaustive key search (brute-force) trivially feasible.
#
# Attack strategies implemented here:
#
#   1. Known-plaintext brute-force
#      Given one (plaintext, ciphertext, IV) triple, try all 65,536 keys.
#      Correct key identified when S-AES-CFB(plaintext, candidate) == ciphertext.
#
#   2. Ciphertext-only attack (with known plaintext pattern)
#      If the attacker knows the plaintext starts with a known header
#      (e.g. "Hello" or a magic byte sequence), filter candidates by
#      checking only the first block.
#
#   3. Meet-in-the-middle conceptual note
#      S-AES is only 2 rounds, so MITM can be used on double-S-AES.
#      Not applicable to single S-AES but documented for the report.
#
# Performance note:
#   65,536 S-AES encryptions take < 1 second in Python.
#   No optimisation (lookup tables, etc.) is needed.
# =============================================================================

import time
import struct
from saes  import saes_encrypt
from cfb   import (cfb_encrypt_blocks, cfb_decrypt_blocks,cfb_encrypt_bytes,  cfb_decrypt_bytes,HEADER_FORMAT, HEADER_SIZE)

KEY_SPACE = 65536     # 2^16


# ---------------------------------------------------------------------------
# Attack 1 — Known-plaintext brute-force (block level)
# ---------------------------------------------------------------------------

def brute_force_known_plaintext(plaintext_block: int,
                                ciphertext_block: int,
                                iv: int,
                                verbose: bool = True):
    """
    Recover the 16-bit key given one (plaintext, ciphertext, IV) triple.

    In CFB mode, the first block satisfies:
        C[0] = P[0] XOR S-AES_encrypt(IV, key)
    Rearranging:
        S-AES_encrypt(IV, key) = P[0] XOR C[0]

    So we compute the target keystream value and search for the key that
    produces it.

    Args:
        plaintext_block  : int  — 16-bit first plaintext block
        ciphertext_block : int  — 16-bit first ciphertext block
        iv               : int  — 16-bit IV used during encryption
        verbose          : bool — print progress

    Returns:
        list[int]  — all keys that satisfy the equation (usually just one)
    """
    target_keystream = plaintext_block ^ ciphertext_block

    if verbose:
        print(f"[*] Known-plaintext brute-force attack")
        print(f"    PT block : {plaintext_block:#06x}")
        print(f"    CT block : {ciphertext_block:#06x}")
        print(f"    IV       : {iv:#06x}")
        print(f"    Target keystream = PT XOR CT = {target_keystream:#06x}")
        print(f"    Searching {KEY_SPACE:,} keys ...")

    start    = time.perf_counter()
    matches  = []

    for candidate_key in range(KEY_SPACE):
        if saes_encrypt(iv, candidate_key) == target_keystream:
            matches.append(candidate_key)

    elapsed = time.perf_counter() - start

    if verbose:
        print(f"    Done in {elapsed:.4f}s")
        if matches:
            for k in matches:
                print(f"    Key found: {k:#06x}  ({k:016b})")
        else:
            print("    No key found.")

    return matches


# ---------------------------------------------------------------------------
# Attack 2 — Known-plaintext brute-force (byte level, full message)
# ---------------------------------------------------------------------------

def brute_force_bytes(known_plaintext: bytes,
                      ciphertext: bytes,
                      iv: int,
                      verbose: bool = True):
    """
    Recover the key from a known (plaintext, ciphertext, IV) pair at byte level.

    Uses only the first two bytes (one block) of the known plaintext to derive
    the target keystream, then verifies on the full message.

    Args:
        known_plaintext : bytes — plaintext bytes (at least 2 bytes)
        ciphertext      : bytes — ciphertext bytes produced by cfb_encrypt_bytes
        iv              : int   — IV used during encryption
        verbose         : bool  — print progress

    Returns:
        list[int]  — candidate keys confirmed against the full message
    """
    if len(known_plaintext) < 2 or len(ciphertext) < 2:
        raise ValueError("Need at least 2 bytes of known plaintext/ciphertext")

    # First block target
    p0 = (known_plaintext[0] << 8) | known_plaintext[1]
    c0 = (ciphertext[0]      << 8) | ciphertext[1]
    target_keystream = p0 ^ c0

    if verbose:
        print(f"[*] Known-plaintext brute-force (byte level)")
        print(f"    Known PT  : {known_plaintext[:16]}...")
        print(f"    First block target keystream: {target_keystream:#06x}")
        print(f"    Searching {KEY_SPACE:,} keys ...")

    start      = time.perf_counter()
    candidates = []

    for candidate_key in range(KEY_SPACE):
        if saes_encrypt(iv, candidate_key) == target_keystream:
            candidates.append(candidate_key)

    # Verify each candidate against the full message
    confirmed = []
    for k in candidates:
        recovered = cfb_decrypt_bytes(ciphertext, k, iv, len(known_plaintext))
        if recovered == known_plaintext:
            confirmed.append(k)

    elapsed = time.perf_counter() - start

    if verbose:
        print(f"    Done in {elapsed:.4f}s")
        if confirmed:
            for k in confirmed:
                print(f"    Key confirmed: {k:#06x}  ({k:016b})")
        else:
            print("    No key confirmed.")

    return confirmed


# ---------------------------------------------------------------------------
# Attack 3 — Ciphertext-only (known plaintext header)
# ---------------------------------------------------------------------------

def brute_force_known_header(ciphertext: bytes,
                             iv: int,
                             known_header: bytes,
                             verbose: bool = True):
    """
    Recover the key when only the ciphertext is available but the plaintext
    starts with a known pattern (magic bytes, file header, greeting, etc.).

    This is the most realistic attack scenario. Many file formats start with
    fixed bytes (PDF: %PDF, PNG: \\x89PNG, text files often start with
    known words).

    Args:
        ciphertext    : bytes  — full ciphertext
        iv            : int    — IV (prepended to ciphertext in our file format)
        known_header  : bytes  — the known first N bytes of the plaintext
        verbose       : bool   — print progress

    Returns:
        list[int]  — confirmed candidate keys
    """
    if len(known_header) < 2:
        raise ValueError("Need at least 2 header bytes")

    if verbose:
        print(f"[*] Ciphertext-only attack with known header")
        print(f"    Known header: {known_header}")
        print(f"    Searching {KEY_SPACE:,} keys ...")

    start      = time.perf_counter()
    confirmed  = []
    header_len = len(known_header)

    # Fast path: use the first block to filter candidates (< 1s),
    # then verify the full header for the handful that pass.
    p0        = (known_header[0] << 8) | (known_header[1] if header_len > 1 else 0)
    c0        = (ciphertext[0]   << 8) | (ciphertext[1]   if len(ciphertext) > 1 else 0)
    target_ks = p0 ^ c0

    for candidate_key in range(KEY_SPACE):
        if saes_encrypt(iv, candidate_key) != target_ks:
            continue
        # Verify full header to eliminate false positives
        recovered = cfb_decrypt_bytes(ciphertext, candidate_key, iv,
                                      original_length=header_len)
        if recovered == known_header:
            confirmed.append(candidate_key)

    elapsed = time.perf_counter() - start

    if verbose:
        print(f"    Done in {elapsed:.4f}s")
        if confirmed:
            for k in confirmed:
                print(f"    Key found: {k:#06x}  ({k:016b})")
        else:
            print("    No key found.")

    return confirmed


# ---------------------------------------------------------------------------
# Attack 4 — Decrypt a file from another group
# ---------------------------------------------------------------------------

def attack_encrypted_file(filepath: str,
                           known_header: bytes,
                           verbose: bool = True):
    """
    Attempt to crack an encrypted file produced by cfb_encrypt_file.

    Reads the IV and ciphertext from the file header, then runs a
    known-header brute-force attack.

    Args:
        filepath      : str   — path to the encrypted file
        known_header  : bytes — known first bytes of the original plaintext
        verbose       : bool  — print progress

    Returns:
        (key: int, plaintext: bytes) or (None, None) if not found
    """
    with open(filepath, 'rb') as f:
        header     = f.read(HEADER_SIZE)
        ciphertext = f.read()

    iv, original_length = struct.unpack(HEADER_FORMAT, header)

    if verbose:
        print(f"[*] Attacking file: {filepath}")
        print(f"    IV              : {iv:#06x}")
        print(f"    Original length : {original_length} bytes")
        print(f"    Ciphertext size : {len(ciphertext)} bytes")

    keys = brute_force_known_header(ciphertext, iv, known_header, verbose)

    if keys:
        key       = keys[0]
        plaintext = cfb_decrypt_bytes(ciphertext, key, iv, original_length)
        if verbose:
            print(f"\n[+] Decrypted successfully with key {key:#06x}")
            print(f"    First 100 bytes: {plaintext[:100]}")
        return key, plaintext
    else:
        if verbose:
            print("[-] Attack failed — key not found.")
        return None, None


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 55)
    print("Attack Module Self-Test")
    print("=" * 55)

    SECRET_KEY = 0x4AF5
    IV         = 0xBEEF
    MESSAGE    = b"TOP SECRET: launch codes are 1234-ABCD"

    # Simulate encryption by the victim
    ciphertext, used_iv = cfb_encrypt_bytes(MESSAGE, SECRET_KEY, iv=IV)

    print(f"\nSecret key  : {SECRET_KEY:#06x}")
    print(f"IV          : {used_iv:#06x}")
    print(f"Plaintext   : {MESSAGE}")
    print(f"Ciphertext  : {ciphertext.hex()}")

    # ── Attack 1: block-level known plaintext ────────────────────
    print("\n" + "─" * 45)
    p0 = (MESSAGE[0] << 8) | MESSAGE[1]
    c0 = (ciphertext[0] << 8) | ciphertext[1]
    found = brute_force_known_plaintext(p0, c0, IV)
    assert SECRET_KEY in found, "Attack 1 failed!"
    print(f"  Attack 1 result correct: {SECRET_KEY in found}")

    # ── Attack 2: full byte-level known plaintext ────────────────
    print("\n" + "─" * 45)
    found2 = brute_force_bytes(MESSAGE, ciphertext, used_iv)
    assert SECRET_KEY in found2, "Attack 2 failed!"
    print(f"  Attack 2 result correct: {SECRET_KEY in found2}")

    # ── Attack 3: known header only ──────────────────────────────
    print("\n" + "─" * 45)
    found3 = brute_force_known_header(ciphertext, used_iv, b"TOP ")
    assert SECRET_KEY in found3, "Attack 3 failed!"
    print(f"  Attack 3 result correct: {SECRET_KEY in found3}")

    # ── Demonstrate full decryption after attack ─────────────────
    print("\n" + "─" * 45)
    recovered_key = found3[0]
    recovered_msg = cfb_decrypt_bytes(ciphertext, recovered_key, used_iv, len(MESSAGE))
    print(f"[+] Full message recovered:")
    print(f"    {recovered_msg}")
    print(f"    Correct: {recovered_msg == MESSAGE}")

    print("\nAll attack tests passed.")
