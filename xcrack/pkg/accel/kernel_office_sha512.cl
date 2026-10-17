// OpenCL Office agile iterated-hash spin, SHA-512 and SHA-384 variants, for the
// xcrackd GPU tier. One work-item spins one candidate. The host passes the
// digest-length seed cur0 = SHA512|SHA384(salt || UTF16LE(password)); this
// kernel runs the spin loop
//
//     for i in [0, spin):  cur = H(LE32(i) || cur)
//
// Each message (LE32(i) || cur) is 68 bytes for SHA-512, 52 for SHA-384 — one
// SHA-512 block either way. Output is byte-for-byte identical to
// prim.OfficeAgileHash(sha512.New | sha512.New384, ...), validated against the
// Go reference at startup.

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

__constant ulong K512[80] = {
    0x428a2f98d728ae22UL,0x7137449123ef65cdUL,0xb5c0fbcfec4d3b2fUL,0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL,0x59f111f1b605d019UL,0x923f82a4af194f9bUL,0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL,0x12835b0145706fbeUL,0x243185be4ee4b28cUL,0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL,0x80deb1fe3b1696b1UL,0x9bdc06a725c71235UL,0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL,0xefbe4786384f25e3UL,0x0fc19dc68b8cd5b5UL,0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL,0x4a7484aa6ea6e483UL,0x5cb0a9dcbd41fbd4UL,0x76f988da831153b5UL,
    0x983e5152ee66dfabUL,0xa831c66d2db43210UL,0xb00327c898fb213fUL,0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL,0xd5a79147930aa725UL,0x06ca6351e003826fUL,0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL,0x2e1b21385c26c926UL,0x4d2c6dfc5ac42aedUL,0x53380d139d95b3dfUL,
    0x650a73548baf63deUL,0x766a0abb3c77b2a8UL,0x81c2c92e47edaee6UL,0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL,0xa81a664bbc423001UL,0xc24b8b70d0f89791UL,0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL,0xd69906245565a910UL,0xf40e35855771202aUL,0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL,0x1e376c085141ab53UL,0x2748774cdf8eeb99UL,0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL,0x4ed8aa4ae3418acbUL,0x5b9cca4f7763e373UL,0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL,0x78a5636f43172f60UL,0x84c87814a1f0ab72UL,0x8cc702081a6439ecUL,
    0x90befffa23631e28UL,0xa4506cebde82bde9UL,0xbef9a3f7b2c67915UL,0xc67178f2e372532bUL,
    0xca273eceea26619cUL,0xd186b8c721c0c207UL,0xeada7dd6cde0eb1eUL,0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL,0x0a637dc5a2c898a6UL,0x113f9804bef90daeUL,0x1b710b35131c471bUL,
    0x28db77f523047d84UL,0x32caab7b40c72493UL,0x3c9ebe0a15c9bebcUL,0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL,0x597f299cfc657e2aUL,0x5fcb6fab3ad6faecUL,0x6c44198c4a475817UL
};

static void sha512_block(ulong s[8], const ulong w_in[16]) {
    ulong w[80];
    for (int i = 0; i < 16; i++) w[i] = w_in[i];
    for (int i = 16; i < 80; i++) {
        ulong s0 = ROTR64(w[i-15],1) ^ ROTR64(w[i-15],8) ^ (w[i-15] >> 7);
        ulong s1 = ROTR64(w[i-2],19) ^ ROTR64(w[i-2],61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    ulong a=s[0],b=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
    for (int i = 0; i < 80; i++) {
        ulong S1 = ROTR64(e,14) ^ ROTR64(e,18) ^ ROTR64(e,41);
        ulong ch = (e & f) ^ ((~e) & g);
        ulong t1 = h + S1 + ch + K512[i] + w[i];
        ulong S0 = ROTR64(a,28) ^ ROTR64(a,34) ^ ROTR64(a,39);
        ulong maj = (a & b) ^ (a & c) ^ (b & c);
        ulong t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s[0]+=a; s[1]+=b; s[2]+=c; s[3]+=d; s[4]+=e; s[5]+=f; s[6]+=g; s[7]+=h;
}

// spin512 runs the Office spin over a digest-length (dlen) seed using the given
// 8-word init vector; one SHA-512 block per iteration (message = LE32(i)||cur,
// dlen+4 <= 68 bytes). Writes dlen big-endian bytes of the final state.
static void spin512(const __global uchar *seeds, uint gid, uint spin, uint dlen,
                    const ulong iv[8], __global uchar *out) {
    uchar cur[64];
    for (uint i = 0; i < dlen; i++) cur[i] = seeds[(ulong)gid * dlen + i];
    uint mlen = 4 + dlen;
    for (uint i = 0; i < spin; i++) {
        uchar msg[72];
        msg[0] = (uchar)i; msg[1] = (uchar)(i >> 8);
        msg[2] = (uchar)(i >> 16); msg[3] = (uchar)(i >> 24);
        for (uint k = 0; k < dlen; k++) msg[4 + k] = cur[k];

        ulong blk[16];
        for (int k = 0; k < 16; k++) blk[k] = 0;
        for (uint k = 0; k < mlen; k++)
            blk[k >> 3] |= ((ulong)msg[k]) << (56 - 8 * (k & 7));
        blk[mlen >> 3] |= ((ulong)0x80UL) << (56 - 8 * (mlen & 7));
        blk[15] = (ulong)mlen * 8;   // 128-bit length; high word (blk[14]) stays 0

        ulong st[8];
        for (int k = 0; k < 8; k++) st[k] = iv[k];
        sha512_block(st, blk);
        for (uint k = 0; k < dlen; k++)
            cur[k] = (uchar)(st[k >> 3] >> (56 - 8 * (k & 7)));
    }
    for (uint i = 0; i < dlen; i++) out[(ulong)gid * dlen + i] = cur[i];
}

__kernel void office_spin_sha512(
    __global const uchar *seeds,  // nseeds * 64
    const uint spin,
    __global uchar *out)          // nseeds * 64
{
    const ulong iv[8] = {
        0x6a09e667f3bcc908UL,0xbb67ae8584caa73bUL,0x3c6ef372fe94f82bUL,0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL,0x9b05688c2b3e6c1fUL,0x1f83d9abfb41bd6bUL,0x5be0cd19137e2179UL};
    spin512(seeds, get_global_id(0), spin, 64, iv, out);
}

__kernel void office_spin_sha384(
    __global const uchar *seeds,  // nseeds * 48
    const uint spin,
    __global uchar *out)          // nseeds * 48
{
    const ulong iv[8] = {
        0xcbbb9d5dc1059ed8UL,0x629a292a367cd507UL,0x9159015a3070dd17UL,0x152fecd8f70e5939UL,
        0x67332667ffc00b31UL,0x8eb44a8768581511UL,0xdb0c2e0d64f98fa7UL,0x47b5481dbefa4fa4UL};
    spin512(seeds, get_global_id(0), spin, 48, iv, out);
}
