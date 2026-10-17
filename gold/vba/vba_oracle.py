#!/usr/bin/env python3
# Independent MS-OVBA reference: Encryption (2.4.3.1), Password Hash (2.4.4.4 via
# hashlib), Hash Data Structure + Encode Nulls (2.4.4.1/2.4.4.2). Produces DPB
# hex blobs for known passwords so the Go decoder/verifier can be cross-checked.
import hashlib, json

def data_encrypt(data: bytes, seed: int, projkey: int, ignored: bytes) -> bytes:
    version = 2
    version_enc = seed ^ version
    projkey_enc = seed ^ projkey
    out = bytearray([seed, version_enc, projkey_enc])
    unenc1 = projkey
    enc1 = projkey_enc
    enc2 = version_enc
    def put(plain):
        nonlocal unenc1, enc1, enc2
        byte_enc = (plain ^ ((enc2 + unenc1) & 0xFF)) & 0xFF
        out.append(byte_enc)
        enc2 = enc1
        enc1 = byte_enc
        unenc1 = plain
    ignored_len = (seed & 6) // 2
    for i in range(ignored_len):
        put(ignored[i] if i < len(ignored) else 0)
    length = len(data)
    for b in length.to_bytes(4, "little"):
        put(b)
    for b in data:
        put(b)
    return bytes(out)

def encode_nulls(inp: bytes):
    # returns (grbit_bits as list of 0/1, encoded bytes)
    bits = []
    enc = bytearray()
    for b in inp:
        if b == 0x00:
            enc.append(0x01)
            bits.append(0)
        else:
            enc.append(b)
            bits.append(1)
    return bits, bytes(enc)

def hash_structure(key: bytes, pwhash: bytes) -> bytes:
    assert len(key) == 4 and len(pwhash) == 20
    kbits, kenc = encode_nulls(key)
    hbits, henc = encode_nulls(pwhash)
    # grbit: bits 0..3 = key, bits 4..23 = hash (LSB-first), 24-bit little-endian
    grbit = 0
    for i, bit in enumerate(kbits):
        grbit |= bit << i
    for j, bit in enumerate(hbits):
        grbit |= bit << (4 + j)
    out = bytearray()
    out.append(0xFF)  # Reserved
    out += grbit.to_bytes(3, "little")
    out += kenc
    out += henc
    out.append(0x00)  # Terminator
    assert len(out) == 29, len(out)
    return bytes(out)

def dpb_hashed(password: bytes, key: bytes, seed: int, projkey: int, ignored: bytes) -> str:
    pwhash = hashlib.sha1(password + key).digest()
    data = hash_structure(key, pwhash)
    enc = data_encrypt(data, seed, projkey, ignored)
    return enc.hex().upper(), pwhash.hex(), key.hex()

def dpb_plain(password: bytes, seed: int, projkey: int, ignored: bytes) -> str:
    data = password + b"\x00"
    return data_encrypt(data, seed, projkey, ignored).hex().upper()

def dpb_none(seed: int, projkey: int, ignored: bytes) -> str:
    return data_encrypt(b"\x00", seed, projkey, ignored).hex().upper()

# Find a password whose SHA1(pw+key) contains a 0x00 byte, to exercise the
# hash-null decode path.
def find_null_hash(key: bytes):
    i = 0
    while True:
        pw = ("nullseek%d" % i).encode()
        if 0x00 in hashlib.sha1(pw + key).digest():
            return pw
        i += 1

fixtures = {}
# Standard hashed case, no nulls likely.
fixtures["hashed_basic"] = {
    "password": "Welcome1",
    **dict(zip(["dpb", "hash", "key"], dpb_hashed(b"Welcome1", b"\x11\x22\x33\x44", 0xA7, 0x3C, b"\xde\xad\xbe")))
}
# Key with embedded NUL bytes (exercises GrbitKey decode).
fixtures["hashed_keynull"] = {
    "password": "s3cr3t!",
    **dict(zip(["dpb", "hash", "key"], dpb_hashed(b"s3cr3t!", b"\x00\x41\x00\x42", 0x10, 0x55, b"\x01\x02")))
}
# Hash with an embedded NUL byte (exercises GrbitHashNull decode).
_knull = b"\x37\x11\x00\x5a"
_pwnull = find_null_hash(_knull)
fixtures["hashed_hashnull"] = {
    "password": _pwnull.decode(),
    **dict(zip(["dpb", "hash", "key"], dpb_hashed(_pwnull, _knull, 0xFE, 0x01, b"\xaa\xbb\xcc")))
}
# Plaintext password case (recovered, not cracked).
fixtures["plaintext"] = {
    "password": "LetMeIn2024",
    "dpb": dpb_plain(b"LetMeIn2024", 0x42, 0x19, b"\x00"),
}
# No password.
fixtures["none"] = {"dpb": dpb_none(0x08, 0x20, b"\x11\x22\x33")}

print(json.dumps(fixtures, indent=2))
