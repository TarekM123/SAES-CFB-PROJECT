# =============================================================================
# cfb.py  —  CFB (Cipher Feedback) mode wrapper for S-AES
# =============================================================================
#
# CFB turns S-AES (a block cipher) into a stream cipher.
# The plaintext is NEVER fed into S-AES directly — only the feedback is.
#
# Encryption:
#   keystream[i] = S-AES_encrypt(feedback[i], key)
#   C[i]         = P[i] XOR keystream[i]
#   feedback[i+1] = C[i]          # ciphertext becomes next input
#   feedback[0]   = IV
#
# Decryption:
#   keystream[i] = S-AES_encrypt(feedback[i], key)   # SAME direction — always encrypt
#   P[i]         = C[i] XOR keystream[i]
#   feedback[i+1] = C[i]          # same feedback rule
#
# Key observations:
#   - S-AES is always called in ENCRYPT direction, even during decryption.
#   - No padding is needed: last block uses only as many keystream bits as needed.
#   - The IV is random, public, and must never be reused with the same key.
#   - Errors in C[i] corrupt decryption of P[i] and P[i+1], then self-correct.
#
# Data representation:
#   - Internally everything is integers.
#   - Public API works with bytes for easy file I/O.
# =============================================================================

import os
import struct
from saes import saes_encrypt

BLOCK_BITS  = 16          # S-AES block size in bits
BLOCK_BYTES = 2           # S-AES block size in bytes
BLOCK_MASK  = 0xFFFF      # mask for a 16-bit value


# ---------------------------------------------------------------------------
# Low-level integer API  (operates on lists of 16-bit ints)
# ---------------------------------------------------------------------------

def cfb_encrypt_blocks(plaintext_blocks, key, iv):
    """
    Encrypt a list of 16-bit integer blocks using CFB mode.

    The last block may be partial — pass its actual bit-length in a separate
    call if needed (see cfb_encrypt_bytes for the full byte-level API).

    Args:
        plaintext_blocks : list[int]  — list of 16-bit plaintext values
        key              : int        — 16-bit S-AES key
        iv               : int        — 16-bit initialisation vector

    Returns:
        list[int]  — list of 16-bit ciphertext values (same length as input)
    """
    ciphertext_blocks = []
    feedback = iv

    for block in plaintext_blocks:
        keystream = saes_encrypt(feedback, key)
        cipher    = (block ^ keystream) & BLOCK_MASK
        ciphertext_blocks.append(cipher)
        feedback  = cipher          # ciphertext feeds back as next input

    return ciphertext_blocks


def cfb_decrypt_blocks(ciphertext_blocks, key, iv):
    """
    Decrypt a list of 16-bit integer blocks using CFB mode.

    Uses S-AES encrypt (not decrypt) — CFB decryption only needs the
    forward cipher direction.

    Args:
        ciphertext_blocks : list[int]  — list of 16-bit ciphertext values
        key               : int        — 16-bit S-AES key
        iv                : int        — 16-bit initialisation vector (must
                                         match the one used during encryption)

    Returns:
        list[int]  — list of 16-bit plaintext values
    """
    plaintext_blocks = []
    feedback = iv

    for cipher in ciphertext_blocks:
        keystream = saes_encrypt(feedback, key)
        block     = (cipher ^ keystream) & BLOCK_MASK
        plaintext_blocks.append(block)
        feedback  = cipher          # ALWAYS feed back the ciphertext, not plaintext

    return plaintext_blocks


# ---------------------------------------------------------------------------
# Byte-level API  (handles arbitrary-length byte strings)
# ---------------------------------------------------------------------------

def cfb_encrypt_bytes(plaintext: bytes, key: int, iv: int = None):
    """
    Encrypt arbitrary-length bytes using S-AES in CFB mode.

    Handles non-block-aligned messages cleanly:
    the last partial block is XORed with only the needed bytes of keystream.

    Args:
        plaintext : bytes  — arbitrary-length plaintext
        key       : int    — 16-bit S-AES key  (0x0000 – 0xFFFF)
        iv        : int    — 16-bit IV; randomly generated if not provided

    Returns:
        (ciphertext: bytes, iv: int)
        The IV is prepended to ciphertext in cfb_encrypt_file but returned
        separately here so callers can handle it as they wish.
    """
    if iv is None:
        iv = int.from_bytes(os.urandom(BLOCK_BYTES), 'big')

    # Pad plaintext to a multiple of 2 bytes with a length prefix approach:
    # We store the original length so we can strip padding on decryption.
    # Simpler: just work byte-pair by byte-pair, handling odd last byte.

    ciphertext = bytearray()
    feedback   = iv
    i          = 0

    while i < len(plaintext):
        # Build a 16-bit plaintext block from up to 2 bytes
        remaining = len(plaintext) - i
        if remaining >= 2:
            p_block = (plaintext[i] << 8) | plaintext[i + 1]
            n_bytes = 2
        else:
            # Last byte: treat as high byte of a 16-bit word, low byte = 0
            p_block = plaintext[i] << 8
            n_bytes = 1

        keystream = saes_encrypt(feedback, key)
        c_block   = (p_block ^ keystream) & BLOCK_MASK

        # Write only as many output bytes as we consumed input bytes
        if n_bytes == 2:
            ciphertext.append((c_block >> 8) & 0xFF)
            ciphertext.append(c_block & 0xFF)
        else:
            ciphertext.append((c_block >> 8) & 0xFF)

        # Feedback: reconstruct the full 16-bit ciphertext block for the
        # register (pad with 0 for the short last block)
        feedback = c_block if n_bytes == 2 else (c_block & 0xFF00)
        i += n_bytes

    return bytes(ciphertext), iv


def cfb_decrypt_bytes(ciphertext: bytes, key: int, iv: int, original_length: int = None):
    """
    Decrypt arbitrary-length bytes using S-AES in CFB mode.

    Args:
        ciphertext      : bytes  — ciphertext produced by cfb_encrypt_bytes
        key             : int    — 16-bit S-AES key
        iv              : int    — 16-bit IV used during encryption
        original_length : int    — original plaintext length in bytes;
                                   if None, assumed equal to len(ciphertext)

    Returns:
        bytes  — decrypted plaintext
    """
    if original_length is None:
        original_length = len(ciphertext)

    plaintext = bytearray()
    feedback  = iv
    i         = 0

    while i < len(ciphertext):
        remaining = len(ciphertext) - i
        if remaining >= 2:
            c_block = (ciphertext[i] << 8) | ciphertext[i + 1]
            n_bytes = 2
        else:
            c_block = ciphertext[i] << 8
            n_bytes = 1

        keystream = saes_encrypt(feedback, key)
        p_block   = (c_block ^ keystream) & BLOCK_MASK

        if n_bytes == 2:
            plaintext.append((p_block >> 8) & 0xFF)
            plaintext.append(p_block & 0xFF)
        else:
            plaintext.append((p_block >> 8) & 0xFF)

        feedback = c_block if n_bytes == 2 else (c_block & 0xFF00)
        i += n_bytes

    return bytes(plaintext[:original_length])


# ---------------------------------------------------------------------------
# File-level API
# ---------------------------------------------------------------------------
# File format (encrypted):
#   [2 bytes: IV] [2 bytes: original length in bytes] [N bytes: ciphertext]

HEADER_FORMAT = '>HH'          # big-endian: uint16 IV, uint16 original length
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)


def cfb_encrypt_file(input_path: str, output_path: str, key: int):
    """
    Encrypt a file using S-AES-CFB and write to output_path.

    Output format: [IV (2 bytes)] [original length (2 bytes)] [ciphertext]

    Args:
        input_path  : str  — path to plaintext file
        output_path : str  — path to write encrypted file
        key         : int  — 16-bit S-AES key
    """
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    original_length = len(plaintext)
    ciphertext, iv  = cfb_encrypt_bytes(plaintext, key)

    with open(output_path, 'wb') as f:
        f.write(struct.pack(HEADER_FORMAT, iv, original_length))
        f.write(ciphertext)

    print(f"Encrypted: {input_path} -> {output_path}")
    print(f"  IV              : {iv:#06x}")
    print(f"  Key             : {key:#06x}")
    print(f"  Original size   : {original_length} bytes")
    print(f"  Encrypted size  : {len(ciphertext)} bytes")


def cfb_decrypt_file(input_path: str, output_path: str, key: int):
    """
    Decrypt a file produced by cfb_encrypt_file.

    Args:
        input_path  : str  — path to encrypted file
        output_path : str  — path to write decrypted file
        key         : int  — 16-bit S-AES key
    """
    with open(input_path, 'rb') as f:
        header     = f.read(HEADER_SIZE)
        ciphertext = f.read()

    iv, original_length = struct.unpack(HEADER_FORMAT, header)

    plaintext = cfb_decrypt_bytes(ciphertext, key, iv, original_length)

    with open(output_path, 'wb') as f:
        f.write(plaintext)

    print(f"Decrypted: {input_path} -> {output_path}")
    print(f"  IV              : {iv:#06x}")
    print(f"  Key             : {key:#06x}")
    print(f"  Recovered size  : {len(plaintext)} bytes")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 55)
    print("CFB Mode Self-Test")
    print("=" * 55)

    key = 0x4AF5
    iv  = 0x1234

    # ── Test 1: block-level round-trip ──────────────────────────
    print("\n--- Block-level round-trip ---")
    pt_blocks = [0xABCD, 0x1234, 0x0000, 0xFFFF]
    ct_blocks = cfb_encrypt_blocks(pt_blocks, key, iv)
    rc_blocks = cfb_decrypt_blocks(ct_blocks, key, iv)

    for pt, ct, rc in zip(pt_blocks, ct_blocks, rc_blocks):
        ok = rc == pt
        print(f"  PT={pt:#06x}  CT={ct:#06x}  Rec={rc:#06x}  [{'OK' if ok else 'FAIL'}]")

    # ── Test 2: byte-level round-trip (even length) ──────────────
    print("\n--- Byte-level round-trip (even length) ---")
    message = b"Hello, S-AES CFB!"
    ct, used_iv = cfb_encrypt_bytes(message, key, iv)
    rc = cfb_decrypt_bytes(ct, key, used_iv, len(message))
    print(f"  Original  : {message}")
    print(f"  Encrypted : {ct.hex()}")
    print(f"  Recovered : {rc}")
    print(f"  Match     : {rc == message}")

    # ── Test 3: byte-level round-trip (odd length) ───────────────
    print("\n--- Byte-level round-trip (odd length) ---")
    odd_msg = b"Hello!"     # 6 bytes — even
    odd_msg2 = b"Hello!!"   # 7 bytes — odd
    for msg in [odd_msg, odd_msg2]:
        ct2, iv2 = cfb_encrypt_bytes(msg, key, iv)
        rc2 = cfb_decrypt_bytes(ct2, key, iv2, len(msg))
        print(f"  '{msg.decode()}' -> ct={ct2.hex()} -> rec='{rc2.decode()}'  [{'OK' if rc2==msg else 'FAIL'}]")

    # ── Test 4: different IV produces different ciphertext ───────
    print("\n--- IV sensitivity ---")
    ct_a, _ = cfb_encrypt_bytes(b"same message", key, iv=0x0001)
    ct_b, _ = cfb_encrypt_bytes(b"same message", key, iv=0x0002)
    print(f"  IV=0x0001 CT: {ct_a.hex()}")
    print(f"  IV=0x0002 CT: {ct_b.hex()}")
    print(f"  Different  : {ct_a != ct_b}")

    # ── Test 5: error propagation ────────────────────────────────
    print("\n--- Error propagation (1 bit flip in C[0]) ---")
    msg     = b"ABCDEFGH"
    ct3, iv3 = cfb_encrypt_bytes(msg, key, iv)
    # Flip one bit in first byte of ciphertext
    ct_corrupt = bytearray(ct3)
    ct_corrupt[0] ^= 0x01
    rc3 = cfb_decrypt_bytes(bytes(ct_corrupt), key, iv3, len(msg))
    print(f"  Original  : {list(msg)}")
    print(f"  Recovered : {list(rc3)}")
    corrupted = [i for i, (a, b) in enumerate(zip(msg, rc3)) if a != b]
    print(f"  Corrupted byte positions: {corrupted}")
    print(f"  (Expect positions 0-1 wrong, rest correct)")

    print("\nAll CFB tests done.")
