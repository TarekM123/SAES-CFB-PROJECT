# S-AES CFB — Cryptography Project

Implementation of **Simplified AES (S-AES)** in **CFB (Cipher Feedback) mode**,
with brute-force and known-plaintext cryptanalysis attacks.

> Course: IN410 — Applied Cryptography  
> Algorithm: S-AES | Mode: CFB  
> Language: Python 3 (no external libraries, no built-in AES/DES)

---

## Project structure

```
saes_cfb/
├── saes.py      # S-AES core engine (S-Box, key expansion, encrypt, decrypt)
├── cfb.py       # CFB mode wrapper (byte-level and file-level API)
├── attack.py    # Brute-force and known-plaintext attack tools
├── main.py      # Demo script and command-line interface
└── README.md    # This file
```

---

## Quick start

```bash
# Run the full demo (encrypt → attack → decrypt)
python main.py

# Encrypt a file
python main.py encrypt 0x4AF5 plaintext.txt encrypted.bin

# Decrypt a file
python main.py decrypt 0x4AF5 encrypted.bin recovered.txt

# Attack an encrypted file (provide known header bytes)
python main.py attack encrypted.bin "Hello"
```

---

## Algorithm overview

### S-AES

S-AES is a pedagogical cipher with the same structure as full AES but
operating on 16-bit blocks with a 16-bit key and only 2 rounds.

| Property    | S-AES          | Full AES              |
|-------------|----------------|-----------------------|
| Block size  | 16 bits        | 128 bits              |
| Key size    | 16 bits        | 128 / 192 / 256 bits  |
| Rounds      | 2              | 10 / 12 / 14          |
| Word size   | 4 bits (nibble)| 8 bits (byte)         |

**Encryption structure:**

```
AddRoundKey(K0)
Round 1: SubNibbles → ShiftRow → MixColumns → AddRoundKey(K1)
Round 2: SubNibbles → ShiftRow → AddRoundKey(K2)   ← no MixColumns
```

**Key expansion:**  
The 16-bit key is split into two 8-bit words W0, W1. Three subkeys
K0, K1, K2 are derived using RotNib, SubNib (S-Box), and round constants.

```
K0 = W0 || W1
W2 = W0 XOR g(W1, RCON[1])    g(W) = SubNib(RotNib(W)) XOR RC
W3 = W1 XOR W2
K1 = W2 || W3
W4 = W2 XOR g(W3, RCON[2])
W5 = W3 XOR W4
K2 = W4 || W5
```

**GF(2⁴) arithmetic:**  
MixColumns multiplies each column by the matrix `[[1,4],[4,1]]` over
GF(2⁴) with irreducible polynomial `x⁴ + x + 1`. Addition = XOR;
multiplication uses the Russian peasant algorithm with reduction.

---

### CFB mode

CFB (Cipher Feedback) turns S-AES into a stream cipher. The plaintext
is never fed directly into S-AES — only the IV / feedback is.

```
Encryption:
  keystream[i] = S-AES_encrypt(feedback[i], key)
  C[i]         = P[i] XOR keystream[i]
  feedback[i+1] = C[i]          # ciphertext becomes next input

Decryption:
  keystream[i] = S-AES_encrypt(feedback[i], key)   # always encrypt!
  P[i]         = C[i] XOR keystream[i]
  feedback[i+1] = C[i]
```

Key properties:
- **S-AES is always called in encrypt direction**, even during decryption.
- **No padding needed**: the last partial block uses only the needed bytes.
- **IV is random and public**: prepended to the ciphertext file, never reused.
- **Error propagation**: a corrupted block Cᵢ damages Pᵢ and Pᵢ₊₁, then self-corrects.

**Encrypted file format:**

```
[2 bytes: IV] [2 bytes: original plaintext length] [N bytes: ciphertext]
```

---

## Cryptanalysis and brute-force attack

S-AES has a 16-bit key → only **65,536 possible keys**. Exhaustive search
is feasible in under 1 second.

### Attack 1 — Known-plaintext (one block)

Given one `(plaintext_block, ciphertext_block, IV)` triple:

```
target_keystream = P[0] XOR C[0]
for key in 0..65535:
    if S-AES_encrypt(IV, key) == target_keystream:
        candidate found
```

### Attack 2 — Known-plaintext (full message verification)

Same first step, but each candidate key is verified against the full
known plaintext to eliminate false positives (multiple keys can match
on one block alone).

### Attack 3 — Known-header (ciphertext-only)

If the attacker knows the plaintext begins with a fixed pattern
(file magic bytes, a greeting, a known word), they test each candidate
key by decrypting only the first block, comparing to the known header.

```python
# Under 1 second thanks to first-block pre-filter:
found_keys = brute_force_known_header(ciphertext, iv, b"Hello")
```

### Why brute-force works here

| Property          | Value            |
|-------------------|------------------|
| Key space         | 2¹⁶ = 65,536     |
| Keys/second       | ~100,000 in Python|
| Time to exhaust   | < 1 second        |

Real AES-128 has 2¹²⁸ keys — the same attack would take longer than
the age of the universe.

---

## Module reference

### `saes.py`

| Function | Description |
|---|---|
| `saes_encrypt(plaintext, key)` | Encrypt one 16-bit block |
| `saes_decrypt(ciphertext, key)` | Decrypt one 16-bit block |
| `key_expansion(key)` | Returns `[K0, K1, K2]` |
| `gf_mult(a, b)` | GF(2⁴) multiplication |

### `cfb.py`

| Function | Description |
|---|---|
| `cfb_encrypt_bytes(pt, key, iv)` | Encrypt bytes, returns `(ct, iv)` |
| `cfb_decrypt_bytes(ct, key, iv, length)` | Decrypt bytes |
| `cfb_encrypt_file(infile, outfile, key)` | Encrypt a file |
| `cfb_decrypt_file(infile, outfile, key)` | Decrypt a file |

### `attack.py`

| Function | Description |
|---|---|
| `brute_force_known_plaintext(p, c, iv)` | Block-level known-PT attack |
| `brute_force_bytes(pt, ct, iv)` | Full byte-level known-PT attack |
| `brute_force_known_header(ct, iv, header)` | Known-header attack |
| `attack_encrypted_file(path, header)` | Attack a file directly |

---

## Important implementation notes

1. **No standard AES/DES libraries are used anywhere.** All operations
   (S-Box, key schedule, GF arithmetic, CFB mode) are implemented from scratch.

2. **Decrypt order matters.** The inverse of  
   `SubN → ShiftR → MixC → ARK(K1)`  
   is **not** `InvARK → InvMixC → InvShiftR → InvSubN`.  
   It must be: `ARK(K1) → InvMixC → InvShiftR → InvSubN`  
   because ARK is its own inverse (XOR is self-inverse) and the order reversal
   places InvMixC after ARK(K1).

3. **CFB uses S-AES encrypt in both directions.** The keystream is
   generated by encrypting the feedback. XOR is applied to the
   plaintext/ciphertext, never to the S-AES engine's direction.

---

## References

- Stallings, W. — *Cryptography and Network Security* (5th ed.), Appendix C
- Musa, Schaefer, Wedig — *A Simplified AES Algorithm and Its Linear and Differential Cryptanalysis* (2003)
- NIST FIPS 197 — Advanced Encryption Standard
