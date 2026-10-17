// PDF Standard Security Handler 40-bit RC4 (V1/R2, and 40-bit R3/R4) file-key
// sweep. The file key is MD5(...)[:5] — 40 bits — and the /U verifier is a
// function of that 5-byte key alone, so sweeping 2^40 keys recovers it with no
// password. This kernel reproduces the CPU reference
// (xcrypto/scheme/pdf.Handler.computeU / RC4KeyAttack) using RC4 only; the one
// per-document MD5 the R3/R4 path needs — MD5(pad||ID) — is constant across keys
// and is precomputed on the host, passed in as `input`.
//
//   R2:     input = pad (32 bytes), rounds = 1,  cmpLen = 32
//   R3/R4:  input = MD5(pad||ID) (16 bytes), rounds = 20, cmpLen = 16
//
// For each candidate key5 the buffer is RC4'd `rounds` times, round r keyed by
// (key5 XOR r) — round 0 is the key itself — and the first cmpLen bytes are
// compared to /U. A hit is published via an atomic; the host re-checks it on the
// CPU (VerifyFileKey), so the device never decides correctness.

// rc4x5 XORs the RC4 keystream of the 5-byte key k over buf[0:blen] in place.
inline void rc4x5(const uchar k[5], uchar *buf, uint blen) {
    uchar s[256];
    for (uint i = 0; i < 256; i++) s[i] = (uchar)i;
    uint j = 0, ki = 0;
    for (uint i = 0; i < 256; i++) {
        j = (j + s[i] + k[ki]) & 0xffu;
        uchar t = s[i]; s[i] = s[j]; s[j] = t;
        if (++ki == 5u) ki = 0;
    }
    uint a = 0, b = 0;
    for (uint n = 0; n < blen; n++) {
        a = (a + 1u) & 0xffu;
        b = (b + s[a]) & 0xffu;
        uchar t = s[a]; s[a] = s[b]; s[b] = t;
        buf[n] ^= s[(s[a] + s[b]) & 0xffu];
    }
}

__kernel void pdf_rc4keysearch(__global const uchar *input,
                               const uint bufLen,
                               const uint rounds,
                               __global const uchar *u,
                               const uint cmpLen,
                               const ulong start,
                               const uint n,
                               __global volatile uint *out) {
    uint gid = get_global_id(0);
    if (gid >= n) return;
    ulong idx = start + (ulong)gid;

    uchar key[5];
    key[0] = (uchar)(idx & 0xffu);
    key[1] = (uchar)((idx >> 8) & 0xffu);
    key[2] = (uchar)((idx >> 16) & 0xffu);
    key[3] = (uchar)((idx >> 24) & 0xffu);
    key[4] = (uchar)((idx >> 32) & 0xffu);

    uchar buf[32];
    for (uint i = 0; i < bufLen; i++) buf[i] = input[i];
    for (uint r = 0; r < rounds; r++) {
        uchar kr[5];
        for (uint k = 0; k < 5; k++) kr[k] = key[k] ^ (uchar)r;
        rc4x5(kr, buf, bufLen);
    }
    uint match = 1u;
    for (uint i = 0; i < cmpLen; i++) if (buf[i] != u[i]) { match = 0u; break; }
    if (match) {
        if (atomic_xchg(&out[0], 1u) == 0u) {
            out[1] = (uint)(idx & 0xffffffffu);
            out[2] = (uint)(idx >> 32);
        }
    }
}
