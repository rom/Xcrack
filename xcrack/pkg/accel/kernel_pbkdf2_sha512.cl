// OpenCL PBKDF2-HMAC-SHA512 kernel for the xcrackd GPU tier (SQLCipher v4 and
// any standard PBKDF2-HMAC-SHA512 scheme). One work-item derives one password's
// key. The host guarantees HMAC key length <= 128 and salt length <= 107, so
// every PRF message (salt||INT and each 64-byte U) fits a single SHA-512 block
// after the pad block. Output is byte-for-byte identical to RFC 8018
// PBKDF2-HMAC-SHA512, validated against the Go reference (prim.PBKDF2 with
// sha512.New) at startup.

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

static void sha512_init(ulong s[8]) {
    s[0]=0x6a09e667f3bcc908UL; s[1]=0xbb67ae8584caa73bUL; s[2]=0x3c6ef372fe94f82bUL; s[3]=0xa54ff53a5f1d36f1UL;
    s[4]=0x510e527fade682d1UL; s[5]=0x9b05688c2b3e6c1fUL; s[6]=0x1f83d9abfb41bd6bUL; s[7]=0x5be0cd19137e2179UL;
}

// prf512 computes HMAC-SHA512 resumed from the inner/outer pad states over a
// single-block message of mlen bytes (mlen <= 111), writing the 64-byte digest.
static void prf512(const ulong inner[8], const ulong outer[8],
                   const uchar *msg, uint mlen, ulong out8[8]) {
    ulong blk[16];
    for (int i = 0; i < 16; i++) blk[i] = 0;
    for (uint i = 0; i < mlen; i++)
        blk[i >> 3] |= ((ulong)msg[i]) << (56 - 8 * (i & 7));
    blk[mlen >> 3] |= ((ulong)0x80UL) << (56 - 8 * (mlen & 7));
    ulong bits = (ulong)(128 + mlen) * 8;
    blk[14] = 0;        // 128-bit length, high word (always 0 for our sizes)
    blk[15] = bits;
    ulong st[8];
    for (int i = 0; i < 8; i++) st[i] = inner[i];
    sha512_block(st, blk);                       // inner = SHA512(ipad || msg)

    for (int i = 0; i < 16; i++) blk[i] = 0;
    for (int i = 0; i < 8; i++) blk[i] = st[i];
    blk[8] = 0x8000000000000000UL;                // 0x80 after the 64-byte digest
    ulong bits2 = (ulong)(128 + 64) * 8;
    blk[14] = 0;
    blk[15] = bits2;
    for (int i = 0; i < 8; i++) out8[i] = outer[i];
    sha512_block(out8, blk);                      // outer = SHA512(opad || inner)
}

__kernel void pbkdf2_sha512(
    __global const uchar *keys,    // nkeys * 128, each zero-padded
    __global const uint  *keylens, // vestigial; padding handled host-side
    __global const uchar *salt,
    const uint saltlen,
    const uint iter,
    const uint dklen,
    __global uchar *out)           // nkeys * dklen
{
    uint gid = get_global_id(0);
    const __global uchar *key = keys + (ulong)gid * 128;

    ulong ipad[16], opad[16];
    for (int i = 0; i < 16; i++) {
        ulong kw = 0;
        for (int j = 0; j < 8; j++) kw = (kw << 8) | (ulong)key[i*8 + j];
        ipad[i] = kw ^ 0x3636363636363636UL;
        opad[i] = kw ^ 0x5c5c5c5c5c5c5c5cUL;
    }
    ulong inner[8], outer[8];
    sha512_init(inner); sha512_block(inner, ipad);
    sha512_init(outer); sha512_block(outer, opad);

    uint nblocks = (dklen + 63) / 64;
    uchar msg[128];
    for (uint blk = 1; blk <= nblocks; blk++) {
        for (uint i = 0; i < saltlen; i++) msg[i] = salt[i];
        msg[saltlen+0] = (uchar)(blk >> 24);
        msg[saltlen+1] = (uchar)(blk >> 16);
        msg[saltlen+2] = (uchar)(blk >> 8);
        msg[saltlen+3] = (uchar)(blk);
        ulong u[8], t[8];
        prf512(inner, outer, msg, saltlen + 4, u);
        for (int i = 0; i < 8; i++) t[i] = u[i];
        uchar ubuf[64];
        for (uint it = 1; it < iter; it++) {
            for (int i = 0; i < 8; i++)
                for (int j = 0; j < 8; j++)
                    ubuf[i*8 + j] = (uchar)(u[i] >> (56 - 8*j));
            prf512(inner, outer, ubuf, 64, u);
            for (int i = 0; i < 8; i++) t[i] ^= u[i];
        }
        uint off = (blk - 1) * 64;
        for (int i = 0; i < 64 && off + i < dklen; i++) {
            ulong word = t[i >> 3];
            out[(ulong)gid * dklen + off + i] = (uchar)(word >> (56 - 8 * (i & 7)));
        }
    }
}
