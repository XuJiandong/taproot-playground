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
    # how to guarantee that?
    # if failed, try another h value
    if t >= SECP256K1_ORDER:
        raise ValueError
    Q = point_add(lift_x(pubkey), point_mul(G, t))
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


def load_script_by_hash(script_hash: bytes) -> Script:
    return Script()


def taproot_sign(smt_root: bytes, internal_seckey: bytes, message: bytes) -> Tuple[bytes, bytes]:
    aux_rand = bytes_from_int(1)
    output_seckey = taproot_tweak_seckey(internal_seckey, smt_root)
    sig = schnorr_sign(message, output_seckey, aux_rand)

    internal_pubkey = pubkey_gen(internal_seckey)
    (has_odd_y, output_pubkey) = taproot_tweak_pubkey(internal_pubkey, smt_root)
    return (sig, output_pubkey)


# provide output pubkey, sig in witness
def taproot_unlock_via_sig(message: bytes, pubkey: bytes, sig: bytes) -> bool:
    return schnorr_verify(message, pubkey, sig)

# provide internal pubkey, sig, smt_root, proof, script_hash in witness
def taproot_unlock_via_script(message: bytes, internal_pubkey: bytes, sig: bytes, 
                            smt_root: bytes, proof: bytes, script_identity: bytes) -> bool:
    (hash_odd_y, output_pubkey) = taproot_tweak_pubkey(internal_pubkey, smt_root)

    if not schnorr_verify(message, output_pubkey, sig):
        return False
    # script_identity can be 64 bytes at most: move 32 bytes into key and 32 bytes into value.
    # the key part should unique.
    if not smt_verify(smt_root, proof, script_identity[0:32], script_identity[32:64]):
        return False
    script = load_script_by_hash(script_identity)
    return script.run()


if __name__ == "__main__":
    proof = bytes_from_int(0x4C001122)
    script_identity = bytes_from_int(0x11)*2
    smt_root = bytes_from_int(0x12)
    message = bytes_from_int(0x13)
    internal_seckey = bytes_from_int(
        0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF)
    internal_pubkey = pubkey_gen(internal_seckey)

    (sig, output_pubkey) = taproot_sign(smt_root, internal_seckey, message)

    success = taproot_unlock_via_sig(message, output_pubkey, sig)
    assert success

    success = taproot_unlock_via_script(
        message, internal_pubkey, sig, smt_root, proof, script_identity)
    assert success
