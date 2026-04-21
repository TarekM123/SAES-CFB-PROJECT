# =============================================================================
# saes.py  —  Simplified AES (S-AES) core engine
# =============================================================================
# Block size : 16 bits
# Key size   : 16 bits
# Rounds     : 2
# Word size  : 4 bits (nibble)
#
# Reference: Stallings "Cryptography and Network Security", Appendix C
#            Musa, Schaefer, Wedig "A Simplified AES Algorithm" (2003)
# =============================================================================


# ---------------------------------------------------------------------------
# S-Box and Inverse S-Box
# ---------------------------------------------------------------------------
# Fixed 4-bit -> 4-bit substitution table.
# Index = input nibble (0-15), value = substituted nibble.

SBOX = [0x9, 0x4, 0xA, 0xB,
        0xD, 0x1, 0x8, 0x5,
        0x6, 0x2, 0x0, 0x3,
        0xC, 0xE, 0xF, 0x7]

INV_SBOX = [0] * 16
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

# Round constants (8-bit values applied during key expansion)
# RCON[1] = 1000 0000, RCON[2] = 0011 0000
RCON = {1: 0x80, 2: 0x30}


# ---------------------------------------------------------------------------
# GF(2^4) Multiplication
# ---------------------------------------------------------------------------
# Irreducible polynomial: x^4 + x + 1  (0x13 in binary: 10011)

def gf_mult(a, b):
    """
    Multiply two 4-bit values in GF(2^4).
    Uses the Russian peasant algorithm with reduction mod x^4+x+1.
    """
    result = 0
    for _ in range(4):
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x10:        # bit escaped 4-bit boundary
            a ^= 0x13       # reduce mod 10011
        a &= 0xF
        b >>= 1
    return result


# ---------------------------------------------------------------------------
# State matrix helpers
# ---------------------------------------------------------------------------
# S-AES organises 16 bits as a 2x2 nibble matrix filled column-major:
#
#   Bit layout:  [b15..b12 | b11..b8 | b7..b4 | b3..b0]
#                    n0         n1        n2       n3
#
#   State matrix (column-major):
#       [ n0  n2 ]    col 0 = [n0, n1]
#       [ n1  n3 ]    col 1 = [n2, n3]

def int_to_state(block):
    """Convert a 16-bit integer to a 2x2 nibble state matrix (column-major)."""
    n0 = (block >> 12) & 0xF
    n1 = (block >>  8) & 0xF
    n2 = (block >>  4) & 0xF
    n3 = (block >>  0) & 0xF
    return [[n0, n2],
            [n1, n3]]


def state_to_int(state):
    """Convert a 2x2 nibble state matrix back to a 16-bit integer."""
    return ((state[0][0] & 0xF) << 12 |
            (state[1][0] & 0xF) <<  8 |
            (state[0][1] & 0xF) <<  4 |
            (state[1][1] & 0xF))


# ---------------------------------------------------------------------------
# Key Expansion
# ---------------------------------------------------------------------------
# Expands a 16-bit key into three 16-bit subkeys K0, K1, K2.
#
# The key is split into two 8-bit words: W0 (high byte), W1 (low byte).
#
# Key schedule:
#   K0 = W0 || W1                (original key)
#   W2 = W0 XOR g(W1, RCON[1])
#   W3 = W1 XOR W2
#   K1 = W2 || W3
#   W4 = W2 XOR g(W3, RCON[2])
#   W5 = W3 XOR W4
#   K2 = W4 || W5
#
# g(W, RC):
#   1. RotNib(W)  — swap the two nibbles of the byte
#   2. SubNib(result) — apply SBOX to each nibble
#   3. XOR with round constant RC

def _rot_nib(byte):
    """Swap the high and low nibbles of an 8-bit value."""
    return ((byte & 0xF) << 4) | ((byte >> 4) & 0xF)


def _sub_nib_byte(byte):
    """Apply SBOX to both nibbles of an 8-bit value."""
    return (SBOX[(byte >> 4) & 0xF] << 4) | SBOX[byte & 0xF]


def _g(word, rcon):
    """Key schedule g function: SubNib(RotNib(word)) XOR rcon."""
    return _sub_nib_byte(_rot_nib(word)) ^ rcon


def key_expansion(key):
    """
    Expand a 16-bit key into three 16-bit subkeys.

    Args:
        key : int  — 16-bit key

    Returns:
        [K0, K1, K2]  — list of three 16-bit subkeys
    """
    W0 = (key >> 8) & 0xFF
    W1 =  key & 0xFF

    K0 = key

    W2 = W0 ^ _g(W1, RCON[1])
    W3 = W1 ^ W2
    K1 = (W2 << 8) | W3

    W4 = W2 ^ _g(W3, RCON[2])
    W5 = W3 ^ W4
    K2 = (W4 << 8) | W5

    return [K0, K1, K2]


# ---------------------------------------------------------------------------
# Round operations
# ---------------------------------------------------------------------------

def _add_round_key(state, subkey):
    """XOR every nibble in the state with the corresponding nibble of subkey."""
    ks = int_to_state(subkey)
    return [[state[r][c] ^ ks[r][c] for c in range(2)] for r in range(2)]


def _sub_nibbles(state, inverse=False):
    """Apply SBOX (or INV_SBOX) to every nibble in the state."""
    box = INV_SBOX if inverse else SBOX
    return [[box[state[r][c]] for c in range(2)] for r in range(2)]


def _shift_row(state):
    """
    ShiftRow: swap the two nibbles of row 1. Row 0 is unchanged.

    Before: [ s00  s01 ]    After: [ s00  s01 ]
            [ s10  s11 ]           [ s11  s10 ]

    Note: this operation is its own inverse (applying it twice = identity).
    """
    return [[state[0][0], state[0][1]],
            [state[1][1], state[1][0]]]


def _mix_columns(state):
    """
    MixColumns: multiply each column by [[1,4],[4,1]] in GF(2^4).

    For each column c:
        new[0][c] = 1*state[0][c] XOR 4*state[1][c]
        new[1][c] = 4*state[0][c] XOR 1*state[1][c]
    """
    result = [[0, 0], [0, 0]]
    for c in range(2):
        result[0][c] = gf_mult(1, state[0][c]) ^ gf_mult(4, state[1][c])
        result[1][c] = gf_mult(4, state[0][c]) ^ gf_mult(1, state[1][c])
    return result


def _inv_mix_columns(state):
    """
    Inverse MixColumns: multiply each column by [[9,2],[2,9]] in GF(2^4).

    The matrix [[9,2],[2,9]] is the inverse of [[1,4],[4,1]] in GF(2^4).
    """
    result = [[0, 0], [0, 0]]
    for c in range(2):
        result[0][c] = gf_mult(9, state[0][c]) ^ gf_mult(2, state[1][c])
        result[1][c] = gf_mult(2, state[0][c]) ^ gf_mult(9, state[1][c])
    return result


# ---------------------------------------------------------------------------
# S-AES Encrypt
# ---------------------------------------------------------------------------

def saes_encrypt(plaintext, key):
    """
    Encrypt a single 16-bit block with S-AES.

    Round structure:
        AddRoundKey(K0)
        Round 1:  SubNibbles -> ShiftRow -> MixColumns -> AddRoundKey(K1)
        Round 2:  SubNibbles -> ShiftRow -> AddRoundKey(K2)  [no MixColumns]

    Args:
        plaintext : int  — 16-bit plaintext block
        key       : int  — 16-bit key

    Returns:
        int  — 16-bit ciphertext block
    """
    K0, K1, K2 = key_expansion(key)
    state = int_to_state(plaintext)

    state = _add_round_key(state, K0)

    # Round 1
    state = _sub_nibbles(state)
    state = _shift_row(state)
    state = _mix_columns(state)
    state = _add_round_key(state, K1)

    # Round 2 (no MixColumns in final round)
    state = _sub_nibbles(state)
    state = _shift_row(state)
    state = _add_round_key(state, K2)

    return state_to_int(state)


# ---------------------------------------------------------------------------
# S-AES Decrypt
# ---------------------------------------------------------------------------

def saes_decrypt(ciphertext, key):
    """
    Decrypt a single 16-bit block with S-AES.

    Inverse round structure (operations undone in exact reverse order):
        AddRoundKey(K2)
        InvShiftRow -> InvSubNibbles
        AddRoundKey(K1) -> InvMixColumns
        InvShiftRow -> InvSubNibbles
        AddRoundKey(K0)

    IMPORTANT: InvMixColumns comes AFTER undoing ARK(K1) because during
    encryption, MixColumns ran BEFORE ARK(K1).

    Args:
        ciphertext : int  — 16-bit ciphertext block
        key        : int  — 16-bit key

    Returns:
        int  — 16-bit plaintext block
    """
    K0, K1, K2 = key_expansion(key)
    state = int_to_state(ciphertext)

    # Undo Round 2
    state = _add_round_key(state, K2)
    state = _shift_row(state)
    state = _sub_nibbles(state, inverse=True)

    # Undo ARK(K1) then MixColumns
    state = _add_round_key(state, K1)
    state = _inv_mix_columns(state)

    # Undo Round 1
    state = _shift_row(state)
    state = _sub_nibbles(state, inverse=True)

    # Undo initial AddRoundKey
    state = _add_round_key(state, K0)

    return state_to_int(state)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 50)
    print("S-AES Self-Test")
    print("=" * 50)

    test_key = 0x4AF5

    K0, K1, K2 = key_expansion(test_key)
    print(f"\nKey : {test_key:#06x}  ({test_key:016b})")
    print(f"K0  : {K0:#06x}  ({K0:016b})")
    print(f"K1  : {K1:#06x}  ({K1:016b})")
    print(f"K2  : {K2:#06x}  ({K2:016b})")

    print("\n--- Round-trip tests ---")
    all_ok = True
    for pt in [0x0000, 0xFFFF, 0x1234, 0xABCD, 0x6F6B, 0xD728]:
        ct  = saes_encrypt(pt, test_key)
        rec = saes_decrypt(ct, test_key)
        ok  = rec == pt
        all_ok = all_ok and ok
        status = "OK" if ok else "FAIL"
        print(f"  PT={pt:#06x}  CT={ct:#06x}  Recovered={rec:#06x}  [{status}]")

    print(f"\nAll round-trip tests passed: {all_ok}")

    print("\n--- Uniqueness check (key=0x4AF5) ---")
    cts = [saes_encrypt(pt, test_key) for pt in range(65536)]
    unique = len(set(cts)) == 65536
    print(f"  All 65536 ciphertexts are unique: {unique}")
