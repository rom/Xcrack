// OpenCL Office agile/standard iterated-hash spin, SHA-1 variant, for the
// xcrackd GPU tier. One work-item spins one candidate.
//
// The host computes the one variable-length first hash cur0 = SHA1(salt ||
// UTF16LE(password)) per candidate on the CPU and passes the 20-byte seed; this
// kernel runs the dominant spin loop:
//
//     for i in [0, spin):  cur = SHA1(LE32(i) || cur)
//
// Each message is LE32(i) || cur = 24 bytes, a single SHA-1 block. The output is
// byte-for-byte identical to prim.OfficeAgileHash(sha1.New, ...), validated
// against the Go reference at startup (GPUSelfTest).

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

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

#define DIGEST 20
#define MLEN   (4 + DIGEST)

__kernel void office_spin_sha1(
    __global const uchar *seeds,  // nseeds * 20
    const uint spin,
    __global uchar *out)          // nseeds * 20
{
    uint gid = get_global_id(0);
    uchar cur[DIGEST];
    for (int i = 0; i < DIGEST; i++) cur[i] = seeds[(ulong)gid * DIGEST + i];

    for (uint i = 0; i < spin; i++) {
        uchar msg[MLEN];
        msg[0] = (uchar)i; msg[1] = (uchar)(i >> 8);
        msg[2] = (uchar)(i >> 16); msg[3] = (uchar)(i >> 24);
        for (int k = 0; k < DIGEST; k++) msg[4 + k] = cur[k];

        uint blk[16];
        for (int k = 0; k < 16; k++) blk[k] = 0;
        for (uint k = 0; k < MLEN; k++)
            blk[k >> 2] |= ((uint)msg[k]) << (24 - 8 * (k & 3));
        blk[MLEN >> 2] |= ((uint)0x80u) << (24 - 8 * (MLEN & 3));
        blk[15] = MLEN * 8;

        uint st[5];
        st[0] = 0x67452301u; st[1] = 0xEFCDAB89u; st[2] = 0x98BADCFEu;
        st[3] = 0x10325476u; st[4] = 0xC3D2E1F0u;
        sha1_block(st, blk);
        for (int k = 0; k < DIGEST; k++)
            cur[k] = (uchar)(st[k >> 2] >> (24 - 8 * (k & 3)));
    }
    for (int i = 0; i < DIGEST; i++) out[(ulong)gid * DIGEST + i] = cur[i];
}
