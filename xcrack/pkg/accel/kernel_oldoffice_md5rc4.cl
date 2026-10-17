// Office 97/2000 RC4 (MS-OFFCRYPTO 2.3.6) 40-bit key-space sweep.
//
// The password enters the scheme only as trunc = MD5(UTF16LE(pw))[:5] — 40 bits
// — and the whole document (verifier included) is a function of (trunc, salt).
// This kernel sweeps a range of the 2^40 trunc values, reproducing the CPU
// reference (xcrypto/scheme/officebinary.RC4KeyAttack) byte-for-byte:
//
//   trunc2   = MD5( 16 × (trunc5 || salt) )[:5]
//   key      = MD5( trunc2 || LE32(0) )            // 16-byte RC4 key, block 0
//   dec      = RC4(key, encVerifier || encVerifierHash)   // 32 bytes
//   hit iff  MD5(dec[0:16]) == dec[16:32]
//
// Each work-item tests one trunc index i = start + gid; a hit is published via an
// atomic into out[0..2]. The host re-checks any hit on the CPU, so the device
// never decides correctness on its own.

// ---- MD5 (RFC 1321) ----

inline uint md5_lrot(uint x, uint c) { return (x << c) | (x >> (32u - c)); }

// md5 hashes msg[0:len] (len <= 336) and writes the 16-byte little-endian digest
// to out. It copies msg into a private, padded block buffer, so the caller need
// not pad. Only lengths that fit 6 512-bit blocks are used here.
inline void md5(const uchar *msg, uint len, uchar out[16]) {
    uchar buf[384];
    for (uint i = 0; i < len; i++) buf[i] = msg[i];
    uint total = len;
    buf[total++] = 0x80;
    // pad with zeros until total % 64 == 56
    while ((total & 63u) != 56u) buf[total++] = 0x00;
    ulong bits = (ulong)len * 8ul;
    for (uint i = 0; i < 8; i++) buf[total++] = (uchar)((bits >> (8u * i)) & 0xffu);

    const uint K[64] = {
        0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
        0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
        0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
        0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
        0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
        0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
        0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
        0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u };
    const uint S[64] = {
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };

    uint a0 = 0x67452301u, b0 = 0xefcdab89u, c0 = 0x98badcfeu, d0 = 0x10325476u;
    for (uint off = 0; off < total; off += 64) {
        uint M[16];
        for (uint i = 0; i < 16; i++) {
            uint j = off + i * 4u;
            M[i] = (uint)buf[j] | ((uint)buf[j+1] << 8) | ((uint)buf[j+2] << 16) | ((uint)buf[j+3] << 24);
        }
        uint A = a0, B = b0, C = c0, D = d0;
        for (uint i = 0; i < 64; i++) {
            uint F, g;
            if (i < 16)      { F = (B & C) | (~B & D);        g = i; }
            else if (i < 32) { F = (D & B) | (~D & C);        g = (5u*i + 1u) & 15u; }
            else if (i < 48) { F = B ^ C ^ D;                 g = (3u*i + 5u) & 15u; }
            else             { F = C ^ (B | ~D);              g = (7u*i) & 15u; }
            F = F + A + K[i] + M[g];
            A = D; D = C; C = B;
            B = B + md5_lrot(F, S[i]);
        }
        a0 += A; b0 += B; c0 += C; d0 += D;
    }
    uint words[4] = { a0, b0, c0, d0 };
    for (uint i = 0; i < 4; i++) {
        out[i*4+0] = (uchar)(words[i] & 0xffu);
        out[i*4+1] = (uchar)((words[i] >> 8) & 0xffu);
        out[i*4+2] = (uchar)((words[i] >> 16) & 0xffu);
        out[i*4+3] = (uchar)((words[i] >> 24) & 0xffu);
    }
}

// oldoffice_md5rc4 sweeps trunc indices [start, start+n) for the Office 97/2000
// verifier. salt is saltLen bytes; ev is encVerifier(16) || encVerifierHash(16).
// out[0] is the found flag (0/1), out[1]/out[2] the winning index low32/high.
__kernel void oldoffice_md5rc4(__global const uchar *salt,
                               const uint saltLen,
                               __global const uchar *ev,
                               const ulong start,
                               const uint n,
                               __global volatile uint *out) {
    uint gid = get_global_id(0);
    if (gid >= n) return;
    ulong idx = start + (ulong)gid;

    uchar t[5];
    t[0] = (uchar)(idx & 0xffu);
    t[1] = (uchar)((idx >> 8) & 0xffu);
    t[2] = (uchar)((idx >> 16) & 0xffu);
    t[3] = (uchar)((idx >> 24) & 0xffu);
    t[4] = (uchar)((idx >> 32) & 0xffu);

    // inter = 16 × (trunc5 || salt)
    uchar inter[352];
    uint slot = 5u + saltLen;
    for (uint s = 0; s < 16; s++) {
        uint b = s * slot;
        inter[b] = t[0]; inter[b+1] = t[1]; inter[b+2] = t[2]; inter[b+3] = t[3]; inter[b+4] = t[4];
        for (uint k = 0; k < saltLen; k++) inter[b + 5 + k] = salt[k];
    }
    uchar trunc2[16];
    md5(inter, 16u * slot, trunc2);

    uchar kb[9];
    kb[0] = trunc2[0]; kb[1] = trunc2[1]; kb[2] = trunc2[2]; kb[3] = trunc2[3]; kb[4] = trunc2[4];
    kb[5] = 0; kb[6] = 0; kb[7] = 0; kb[8] = 0;  // LE32(block 0)
    uchar key[16];
    md5(kb, 9u, key);

    // RC4: KSA (16-byte key) + PRGA over the 32-byte verifier.
    uchar sbox[256];
    for (uint i = 0; i < 256; i++) sbox[i] = (uchar)i;
    uint j = 0;
    for (uint i = 0; i < 256; i++) {
        j = (j + sbox[i] + key[i & 15u]) & 0xffu;
        uchar tmp = sbox[i]; sbox[i] = sbox[j]; sbox[j] = tmp;
    }
    uchar dec[32];
    uint a = 0, bb = 0;
    for (uint nn = 0; nn < 32; nn++) {
        a = (a + 1u) & 0xffu;
        bb = (bb + sbox[a]) & 0xffu;
        uchar tmp = sbox[a]; sbox[a] = sbox[bb]; sbox[bb] = tmp;
        dec[nn] = ev[nn] ^ sbox[(sbox[a] + sbox[bb]) & 0xffu];
    }

    uchar h2[16];
    md5(dec, 16u, h2);
    uint match = 1u;
    for (uint i = 0; i < 16; i++) if (h2[i] != dec[16 + i]) { match = 0u; break; }
    if (match) {
        if (atomic_xchg(&out[0], 1u) == 0u) {
            out[1] = (uint)(idx & 0xffffffffu);
            out[2] = (uint)(idx >> 32);
        }
    }
}
