import itertools, math, secrets, sys
import requests
from Crypto.Util.Padding import pad
sys.path.insert(1, "challenge/")
from crypto import B as SBOX, IB, SnowCipher, _ek, b2m, m2b, compute_lrc, r_con
from utils import xtime, inv_shift_rows, inv_mix_columns, mix_columns, shift_rows, sub_bytes, add_round_key
from tqdm import tqdm

WIN_SCORE = 10_000_000
RUNE_XOR = 0xA7
WIN_RUNES = (0xC3, 0x7A, 0xB0, 0xAE)

def xor(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))

def differential(a, b):
    return xor(a, b)

def generate_sbox_ddt():
    table = [None] * 256
    for i in range(256):
        for j in range(256):
            diff_input = i ^ j
            diff_output = SBOX[i] ^ SBOX[j]
            if table[diff_input] is None:
                table[diff_input] = [set() for _ in range(256)]
            table[diff_input][diff_output].update((i, j))
    return table

DDT = generate_sbox_ddt()

def get_impossible_bytes_per_offset_by_alpha(alpha):
    # Generate list of impossible states given `alpha`
    # Stores all impossible states for each offset (0,...,15)
    impossible_bytes_per_offset = {i: set() for i in range(16)}
    # Before shift rows : [0, 1, 2, 3] =>
    # After shift rows  : [0, 3, 2, 1]
    ROW_MAPPING = {0: 0, 1: 3, 2: 2, 3: 1, 4: 1, 5: 0, 6: 3, 7: 2, 8: 2, 9: 1, 10: 0, 11: 3, 12: 3, 13: 2, 14: 1, 15: 0}
    # Iterate over each row for first column
    # TODO: Change bounds depending on target column ([0-4],[4-8],[8-12],[12-16])
    for row_id in range(8, 12):
        shifted_row_id = ROW_MAPPING[row_id]
        # Get impossible output differences
        impossible_diffs = [beta for beta in range(256) if DDT[alpha[row_id]][beta] == set()]
        for impossible_diff in impossible_diffs:
            impossible_state = bytearray(16)
            impossible_state[row_id] = impossible_diff
            # Apply ShiftRows -> MixColumns (Round 1) to alpha
            # AddRoundKey applies XOR key_byte which cancels out so alpha remains
            transformed_impossible_state = m2b(mix_columns(shift_rows(b2m(impossible_state))))
            for chunk_offset in range(shifted_row_id*4, shifted_row_id*4+4):
                impossible_bytes_per_offset[chunk_offset].add(transformed_impossible_state[chunk_offset])
    return impossible_bytes_per_offset

# https://github.com/Merricx/aes-attack/blob/main/utils.py#L134
def recover_master_key(key, current_round):
    key_schedule = [key]
    for r in range(current_round, 0, -1):
        target_key = key_schedule[0]
        prev_key_round = [b""] * 4
        prev_key_round[3] = xor(target_key[12:], target_key[8:12])
        prev_key_round[2] = xor(target_key[8:12], target_key[4:8])
        prev_key_round[1] = xor(target_key[4:8], target_key[:4])
        xored_rcon = xor(bytes([r_con[r], 0, 0, 0]), target_key[:4])
        prev_key_round[0] = xor(m2b(sub_bytes(b2m(prev_key_round[3][1:] + prev_key_round[3][:1]), SBOX)), xored_rcon)
        key_schedule.insert(0, prev_key_round[0] + prev_key_round[1] + prev_key_round[2] + prev_key_round[3])
    return key_schedule[0]

def track_seal(sector, x, y, score_lo):
    return (sector * 19 + x * 7 + y * 13 + score_lo) & 0xFF

def flags_seal(hp, sector, x, y, track):
    return (hp + sector + x + y + track) & 0xFF

def pack_state(*, hp=5, sector=3, x=7, y=6, score=12_345, runes, deaths=0):
    assert (runes[0] ^ runes[1] ^ runes[2] ^ runes[3]) == RUNE_XOR
    st = bytearray(16)
    st[0] = 0x4E
    st[1] = hp & 0xFF
    st[2] = sector & 0xFF
    st[3] = x & 0xFF
    st[4] = y & 0xFF
    st[5] = score & 0xFF
    st[6] = (score >> 8) & 0xFF
    st[7] = (score >> 16) & 0xFF
    st[8:12] = bytes(runes)
    st[12] = track_seal(st[2], st[3], st[4], st[5])
    st[13] = deaths & 0xFF
    st[14] = flags_seal(st[1], st[2], st[3], st[4], st[12])
    st[15] = compute_lrc(st[:15])
    return bytes(st)

def winning_state():
    return pack_state(hp=5, sector=9, x=18, y=13, score=WIN_SCORE, runes=WIN_RUNES, deaths=0)

def choose_plaintexts():
    while True:
        a, b, c = secrets.token_bytes(3)
        r1 = [a, b, c, RUNE_XOR ^ a ^ b ^ c]
        # Force the delta XOR to zero. This preserves the rune quartet balance
        # and, because only bytes 8..11 change, it also preserves the LRC byte.
        d = list(secrets.token_bytes(3))
        d.append(d[0] ^ d[1] ^ d[2])
        if 0 in d:
            continue
        r2 = tuple(r1[i] ^ d[i] for i in range(4))
        p1 = pack_state(runes=tuple(r1))
        p2 = pack_state(runes=r2)
        alpha = differential(p1, p2)
        if alpha[:8] == b"\x00" * 8 and alpha[12:] == b"\x00" * 4 and all(alpha[8:12]):
            assert p1[15] == p2[15]
            return p1, p2

def candidate_round_key_to_master(candidate_rk2):
    # Match the transform used by the attack core: candidate bytes are in the
    # inverse-MixColumns / inverse-ShiftRows coordinate system.
    rk2 = m2b(mix_columns(shift_rows(b2m(bytes(candidate_rk2)))))
    return recover_master_key(rk2, 2)

def product_size(candidates):
    return math.prod(len(candidates[i]) for i in range(16))

def oracle(plaintext):
    global URL, sess, sid
    # The attack surface is disguised as the arcade death-save routine.
    # Every call decrements a life and prints one encrypted save tape.
    r = sess.post(
        f"{URL}/api/death",
        json={"session_id": sid, "state_hex": plaintext.hex()},
        timeout=10,
    )
    return bytes.fromhex(r.json()["ciphertext"])[:16]

global URL, sess, sid
def main():
    global URL, sess, sid
    URL = f"http://{sys.argv[1]}"
    MAX_PAIR_NUM = 7

    sess = requests.Session()
    start = sess.post(f"{URL}/api/start", timeout=10).json()
    sid = start["session_id"]
    print(f"[+] session = {sid}")

    round_key_candidates = {o: list(range(256)) for o in range(16)}

    PT = []
    CT = []

    for pair_index in range(1, MAX_PAIR_NUM + 1):
        PT = choose_plaintexts()
        CT = [oracle(p) for p in PT]

        alpha = differential(*PT)
        impossible_bytes_per_offset = get_impossible_bytes_per_offset_by_alpha(alpha)

        for o in range(16):
            survivors = []
            for rk2_byte in round_key_candidates[o]:
                c_inv = [
                    m2b(
                        sub_bytes(
                            inv_shift_rows(
                                add_round_key(
                                    inv_mix_columns(b2m(c)),
                                    inv_mix_columns(b2m(bytes([rk2_byte]) * 16)),
                                )
                            ),
                            IB,
                        )
                    )
                    for c in CT
                ]
                beta = differential(*c_inv)
                if beta[o] not in impossible_bytes_per_offset[o]:
                    survivors.append(rk2_byte)
            round_key_candidates[o] = survivors

        counts = [len(round_key_candidates[i]) for i in range(16)]
        total = product_size(round_key_candidates)
        print(f"[+] {pair_index = } | candidates per offset = {counts} | {total = }")
    if total > 2**20:
        print("retrying")
        return

    for candidate in tqdm(itertools.product(*(round_key_candidates[i] for i in range(16))), total= total):
        test_key = candidate_round_key_to_master(candidate)
        cipher = SnowCipher(test_key)
        if any(cipher.encrypt_block(pt) != ct for pt, ct in zip(PT, CT)):
            continue
        print(f"[+] recovered key: {test_key.hex()}")
        forged = cipher.encrypt(winning_state())
        print(f"[+] {forged.hex() = }")
        res = sess.post(f"{URL}/api/load", json={"session_id": sid, "ciphertext": forged.hex()}, timeout=10).json()
        if "flag" in res:
            print(res["flag"])
            exit()

if __name__ == "__main__":
    while True:
        main()