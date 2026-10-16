// OpenCL PBKDF2-HMAC-SHA1 kernel for the xcrackd GPU tier.
//
// One work-item derives one password's key. The host guarantees key length
// <= 64 and salt length <= 51 (so salt||INT(i) and every intermediate U fit in
// a single SHA-1 message block after the HMAC pad block), which keeps the
// kernel branch-free over message blocks. Output is byte-for-byte identical to
// RFC 2898 PBKDF2-HMAC-SHA1, validated against the Go reference at startup.

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// sha1_block runs the SHA-1 compression function: 16 big-endian words `w` into
// state `s[5]`.
static void sha1_block(uint s[5], const uint w_in[16]) {
    uint a = s[0], b = s[1], c = s[2], d = s[3], e = s[4];
    uint w[80];
    for (int i = 0; i < 16; i++) w[i] = w_in[i];
    for (int i = 16; i < 80; i++) w[i] = ROTL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    for (int i = 0; i < 80; i++) {
        uint f, k;
        if (i < 20)      { f = (b & c) | ((~b) & d);        k = 0x5A827999u; }
        else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
        else             { f = b ^ c ^ d;                   k = 0xCA62C1D6u; }
        uint t = ROTL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = ROTL(b, 30); b = a; a = t;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e;
}

static void sha1_init(uint s[5]) {
    s[0] = 0x67452301u; s[1] = 0xEFCDAB89u; s[2] = 0x98BADCFEu;
    s[3] = 0x10325476u; s[4] = 0xC3D2E1F0u;
}

// prf computes HMAC-SHA1 resumed from the precomputed inner/outer pad states
// over a single-block message `msg` of `mlen` bytes (mlen <= 55), writing the
// 20-byte digest to out5[5].
static void prf(const uint inner[5], const uint outer[5],
                const uchar *msg, uint mlen, uint out5[5]) {
    uint blk[16];
    for (int i = 0; i < 16; i++) blk[i] = 0;
    for (uint i = 0; i < mlen; i++)
        blk[i >> 2] |= ((uint)msg[i]) << (24 - 8 * (i & 3));
    blk[mlen >> 2] |= ((uint)0x80u) << (24 - 8 * (mlen & 3));
    ulong bits = (ulong)(64 + mlen) * 8;
    blk[14] = (uint)(bits >> 32);
    blk[15] = (uint)bits;
    uint st[5];
    for (int i = 0; i < 5; i++) st[i] = inner[i];
    sha1_block(st, blk);            // inner hash = SHA1(ipad || msg)

    // outer: SHA1(opad || inner_digest(20 bytes))
    for (int i = 0; i < 16; i++) blk[i] = 0;
    for (int i = 0; i < 5; i++) blk[i] = st[i];
    blk[5] = 0x80000000u;           // 0x80 right after the 20-byte digest
    ulong bits2 = (ulong)(64 + 20) * 8;
    blk[14] = (uint)(bits2 >> 32);
    blk[15] = (uint)bits2;
    for (int i = 0; i < 5; i++) out5[i] = outer[i];
    sha1_block(out5, blk);
}

__kernel void pbkdf2_sha1(
    __global const uchar *keys,   // nkeys * 64, each zero-padded
    __global const uint  *keylens,// unused beyond padding; kept for clarity
    __global const uchar *salt,
    const uint saltlen,
    const uint iter,
    const uint dklen,
    __global uchar *out)          // nkeys * dklen
{
    uint gid = get_global_id(0);
    const __global uchar *key = keys + (ulong)gid * 64;

    // HMAC pad blocks from the (<=64-byte, zero-padded) key.
    uint ipad[16], opad[16];
    for (int i = 0; i < 16; i++) {
        uint kw = ((uint)key[i*4] << 24) | ((uint)key[i*4+1] << 16) |
                  ((uint)key[i*4+2] << 8) | ((uint)key[i*4+3]);
        ipad[i] = kw ^ 0x36363636u;
        opad[i] = kw ^ 0x5c5c5c5cu;
    }
    uint inner[5], outer[5];
    sha1_init(inner); sha1_block(inner, ipad);
    sha1_init(outer); sha1_block(outer, opad);

    uint nblocks = (dklen + 19) / 20;
    uchar msg[64];
    for (uint blk = 1; blk <= nblocks; blk++) {
        // U1 = PRF(salt || INT_BE(blk))
        for (uint i = 0; i < saltlen; i++) msg[i] = salt[i];
        msg[saltlen+0] = (uchar)(blk >> 24);
        msg[saltlen+1] = (uchar)(blk >> 16);
        msg[saltlen+2] = (uchar)(blk >> 8);
        msg[saltlen+3] = (uchar)(blk);
        uint u[5], t[5];
        prf(inner, outer, msg, saltlen + 4, u);
        for (int i = 0; i < 5; i++) t[i] = u[i];
        // U2..Uc over the previous 20-byte digest.
        uchar ubuf[20];
        for (uint it = 1; it < iter; it++) {
            for (int i = 0; i < 5; i++) {
                ubuf[i*4+0] = (uchar)(u[i] >> 24);
                ubuf[i*4+1] = (uchar)(u[i] >> 16);
                ubuf[i*4+2] = (uchar)(u[i] >> 8);
                ubuf[i*4+3] = (uchar)(u[i]);
            }
            prf(inner, outer, ubuf, 20, u);
            for (int i = 0; i < 5; i++) t[i] ^= u[i];
        }
        // Write T (big-endian) into the output, truncated to dklen.
        uint off = (blk - 1) * 20;
        for (int i = 0; i < 20 && off + i < dklen; i++) {
            uint word = t[i >> 2];
            out[(ulong)gid * dklen + off + i] = (uchar)(word >> (24 - 8 * (i & 3)));
        }
    }
}
