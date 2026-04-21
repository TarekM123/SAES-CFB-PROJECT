# =============================================================================
# main.py  —  Demo: encrypt a text file with S-AES-CFB, then crack it
# =============================================================================
#
# Usage:
#   python main.py                        # runs the full demo
#   python main.py encrypt <key_hex> <infile> <outfile>
#   python main.py decrypt <key_hex> <infile> <outfile>
#   python main.py attack  <infile> <known_header_ascii>
#
# Example:
#   python main.py encrypt 0x4AF5 message.txt message.enc
#   python main.py decrypt 0x4AF5 message.enc message_dec.txt
#   python main.py attack  message.enc "Hello"
# =============================================================================

import sys
import os
import struct
from cfb    import (cfb_encrypt_bytes, cfb_decrypt_bytes,
                    cfb_encrypt_file,  cfb_decrypt_file,
                    HEADER_FORMAT, HEADER_SIZE)
from attack import (brute_force_known_plaintext,
                    brute_force_bytes,
                    brute_force_known_header,
                    attack_encrypted_file)


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def _parse_key(key_str: str) -> int:
    """Parse a key from hex string like '0x4AF5' or '4AF5' or '19189'."""
    key_str = key_str.strip()
    if key_str.startswith('0x') or key_str.startswith('0X'):
        k = int(key_str, 16)
    elif all(c in '0123456789abcdefABCDEF' for c in key_str):
        k = int(key_str, 16)
    else:
        k = int(key_str)
    if not 0 <= k <= 0xFFFF:
        raise ValueError(f"Key {k} out of 16-bit range")
    return k


# ---------------------------------------------------------------------------
# Full demo
# ---------------------------------------------------------------------------

def run_demo():
    """
    End-to-end demonstration:
      1. Create a sample plaintext file
      2. Encrypt it with a known key
      3. Display the encrypted bytes
      4. Attack it using brute-force (known plaintext scenario)
      5. Decrypt and verify
    """
    print("=" * 60)
    print("S-AES CFB — Full Demo")
    print("=" * 60)

    # ── Setup ────────────────────────────────────────────────────
    SECRET_KEY = 0x4AF5
    PLAIN_FILE = "demo_plain.txt"
    ENC_FILE   = "demo_encrypted.bin"
    DEC_FILE   = "demo_decrypted.txt"

    sample_text = (
        "Hello from S-AES CFB mode!\n"
        "This file was encrypted using Simplified AES\n"
        "in Cipher Feedback (CFB) operation mode.\n"
        "Key size: 16 bits | Block size: 16 bits | Rounds: 2\n"
    )

    with open(PLAIN_FILE, 'w') as f:
        f.write(sample_text)

    print(f"\n[1] Plaintext file created: {PLAIN_FILE}")
    print(f"    Content:\n")
    print(sample_text)

    # ── Step 2: Encrypt ──────────────────────────────────────────
    print("─" * 60)
    print(f"[2] Encrypting with key={SECRET_KEY:#06x} ...")
    cfb_encrypt_file(PLAIN_FILE, ENC_FILE, SECRET_KEY)

    # Show the raw encrypted bytes
    with open(ENC_FILE, 'rb') as f:
        raw = f.read()
    iv, orig_len = struct.unpack(HEADER_FORMAT, raw[:HEADER_SIZE])
    ct_bytes = raw[HEADER_SIZE:]
    print(f"\n    Raw encrypted file (hex):")
    print(f"    Header: IV={iv:#06x}  original_length={orig_len}")
    print(f"    Ciphertext: {ct_bytes.hex()}")

    # ── Step 3: Brute-force attack ───────────────────────────────
    print("\n" + "─" * 60)
    print("[3] Running brute-force known-plaintext attack ...")
    print(f"    Attacker knows the plaintext starts with: 'Hello'")

    known_header = b"Hello"
    found_keys   = brute_force_known_header(ct_bytes, iv, known_header)

    if not found_keys:
        print("    Attack failed (unexpected).")
        return

    cracked_key = found_keys[0]

    # ── Step 4: Decrypt using recovered key ─────────────────────
    print("\n" + "─" * 60)
    print(f"[4] Decrypting with recovered key {cracked_key:#06x} ...")
    cfb_decrypt_file(ENC_FILE, DEC_FILE, cracked_key)

    with open(DEC_FILE, 'r') as f:
        recovered_text = f.read()

    print(f"\n    Recovered content:\n")
    print(recovered_text)
    print(f"    Matches original: {recovered_text == sample_text}")

    # ── Step 5: Statistics ───────────────────────────────────────
    print("─" * 60)
    print("[5] Summary")
    print(f"    Secret key  : {SECRET_KEY:#06x}  ({SECRET_KEY:016b})")
    print(f"    Cracked key : {cracked_key:#06x}  ({cracked_key:016b})")
    print(f"    Key correct : {cracked_key == SECRET_KEY}")
    print(f"    Key space   : 65,536 (2^16) — exhaustive search feasible")

    # Cleanup
    for fname in [PLAIN_FILE, ENC_FILE, DEC_FILE]:
        if os.path.exists(fname):
            os.remove(fname)

    print("\nDemo complete.")


# ---------------------------------------------------------------------------
# CLI dispatch
# ---------------------------------------------------------------------------

def cli_encrypt(args):
    if len(args) < 3:
        print("Usage: python main.py encrypt <key_hex> <infile> <outfile>")
        sys.exit(1)
    key, infile, outfile = _parse_key(args[0]), args[1], args[2]
    cfb_encrypt_file(infile, outfile, key)


def cli_decrypt(args):
    if len(args) < 3:
        print("Usage: python main.py decrypt <key_hex> <infile> <outfile>")
        sys.exit(1)
    key, infile, outfile = _parse_key(args[0]), args[1], args[2]
    cfb_decrypt_file(infile, outfile, key)


def cli_attack(args):
    if len(args) < 2:
        print("Usage: python main.py attack <infile> <known_header_ascii>")
        sys.exit(1)
    infile       = args[0]
    known_header = args[1].encode('ascii')
    key, plaintext = attack_encrypted_file(infile, known_header)
    if key is not None:
        print(f"\n[+] Key cracked: {key:#06x}")
        print(f"[+] Plaintext preview: {plaintext[:200]}")
    else:
        print("[-] Attack failed.")


if __name__ == "__main__":
    argv = sys.argv[1:]

    if not argv:
        run_demo()
    elif argv[0] == 'encrypt':
        cli_encrypt(argv[1:])
    elif argv[0] == 'decrypt':
        cli_decrypt(argv[1:])
    elif argv[0] == 'attack':
        cli_attack(argv[1:])
    else:
        print("Commands: encrypt | decrypt | attack")
        print("Run with no arguments for a full demo.")
        sys.exit(1)
