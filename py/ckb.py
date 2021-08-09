from reference import *
import reference
import hashlib

SECP256K1_ORDER = reference.n


def ckb_tagged_hash(tag: str, msg: bytes) -> bytes:
    def blake2b(m):
        return hashlib.blake2b(m, digest_size=32, person="ckb_default_hash".encode()).digest()
    tag_hash = blake2b(tag.encode())
    return blake2b(tag_hash + tag_hash + msg)


tagged_hash = ckb_tagged_hash


class Script:
    def run(self):
        print("run script successfully")
        return True


def taproot_tweak_pubkey(pubkey: bytes, h: bytes) -> Tuple[int, bytes]:
    t = int_from_bytes(tagged_hash("TapTweak", pubkey + h))
    # if failed, must try another h value
    # bip-0341: If t ≥ (order of secp256k1), fail.
    if t >= SECP256K1_ORDER:
        raise ValueError
    # bip-0341: Let p = c[1:33] and let P = lift_x(int(p)) where lift_x and [:] are defined as in BIP340.
    # Fail if this point is not on the curve.
    P = lift_x(pubkey)
    if P is None:
        raise ValueError        
    # bip-0341: Let Q = P + int(t)G.
    Q = point_add(P, point_mul(G, t))
    return 0 if has_even_y(Q) else 1, bytes_from_int(x(Q))


def taproot_tweak_seckey(seckey0: bytes, h: bytes) -> bytes:
    s = int_from_bytes(seckey0)
    P = point_mul(G, s)
    seckey = s if has_even_y(P) else SECP256K1_ORDER - s
    t = int_from_bytes(tagged_hash("TapTweak", bytes_from_int(x(P)) + h))
    if t >= SECP256K1_ORDER:
        raise ValueError
    return bytes_from_int((seckey + t) % SECP256K1_ORDER)

# not implemented
def smt_verify(smt_root: bytes, proof: bytes, key: bytes, value: bytes) -> bool:
    return True


def load_script(script_identity: bytes) -> Script:
    return Script()


def taproot_sign(smt_root: bytes, internal_seckey: bytes, message: bytes) -> Tuple[bytes, bytes]:
    aux_rand = bytes_from_int(1)
    output_seckey = taproot_tweak_seckey(internal_seckey, smt_root)
    sig = schnorr_sign(message, output_seckey, aux_rand)

    internal_key = pubkey_gen(internal_seckey)
    (y_parity, output_key) = taproot_tweak_pubkey(internal_key, smt_root)
    return (sig, output_key, y_parity)


# provide output_key, sig in witness
def taproot_unlock_via_sig(message: bytes, output_key: bytes, sig: bytes) -> bool:
    return schnorr_verify(message, output_key, sig)

# provide internal_key, output_key, y_pairity, smt_root, proof, script_identity in witness
def taproot_unlock_via_script(internal_key: bytes, output_key: bytes, y_parity: int,
                            smt_root: bytes, proof: bytes, script_identity: bytes) -> bool:
    # bip-0341: Let t = hash.TapTweak(p || km).
    (out_y_pairty, key) = taproot_tweak_pubkey(internal_key, smt_root)
    # bip-0341: If q ≠ x(Q) or c[0] & 1 ≠ y(Q) mod 2, fail
    if key != output_key or y_parity != out_y_pairty:
        return False

    # Just an idea:
    # script_identity can be 64 bytes at most: move 32 bytes into key and 32 bytes into value.
    # the key part should be unique.
    # Here we use identity (21 bytes) as key
    if not smt_verify(smt_root, proof, script_identity[0:21], [1]):
        return False
    # should verify with taproot_preimage and signature in witness, omitted
    script = load_script(script_identity)
    # bip-0341: Execute the script, according to the applicable script rules
    return script.run()


if __name__ == "__main__":
    proof = bytes_from_int(0x4C001122)
    script_identity = bytes_from_int(0x11)*2
    smt_root = bytes_from_int(0x12)
    message = bytes_from_int(0x13)
    y_parity = 0xFF
    internal_seckey = bytes_from_int(
        0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF)
    internal_key = pubkey_gen(internal_seckey)

    # 1. as taproot
    (sig, output_key, y_parity) = taproot_sign(smt_root, internal_seckey, message)

    success = taproot_unlock_via_script(
        internal_key, output_key, y_parity, smt_root, proof, script_identity)
    assert success

    # 2. as normal schnorr signature
    # If the spending conditions do not require a script path, 
    # the output key should commit to an unspendable script path 
    # instead of having no script path. This can be achieved by 
    # computing the output key point as Q = P + int(hashTapTweak(bytes(P)))G. [22]
    unspendable_smt_root = tagged_hash("TapTweak", internal_key)
    (sig, output_key, _) = taproot_sign(unspendable_smt_root, internal_seckey, message)
    success = taproot_unlock_via_sig(message, output_key, sig)
    assert success

