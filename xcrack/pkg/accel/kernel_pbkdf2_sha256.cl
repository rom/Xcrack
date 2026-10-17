// OpenCL PBKDF2-HMAC-SHA256 kernel for the xcrackd GPU tier (RAR5-class and any
// standard PBKDF2-HMAC-SHA256 scheme). One work-item derives one password's key.
// The host guarantees HMAC key length <= 64 and salt length <= 51, so every PRF
// message (salt||INT and each 32-byte U) fits a single SHA-256 block after the
// pad block. Output is byte-for-byte identical to RFC 8018 PBKDF2-HMAC-SHA256,
// validated against the Go reference (prim.PBKDF2 with sha256.New) at startup.

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

__constant uint K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static void sha256_block(uint s[8], const uint w_in[16]) {
    uint w[64];
    for (int i = 0; i < 16; i++) w[i] = w_in[i];
    for (int i = 16; i < 64; i++) {
        uint s0 = ROTR32(w[i-15],7) ^ ROTR32(w[i-15],18) ^ (w[i-15] >> 3);
        uint s1 = ROTR32(w[i-2],17) ^ ROTR32(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint a=s[0],b=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
    for (int i = 0; i < 64; i++) {
        uint S1 = ROTR32(e,6) ^ ROTR32(e,11) ^ ROTR32(e,25);
        uint ch = (e & f) ^ ((~e) & g);
        uint t1 = h + S1 + ch + K256[i] + w[i];
        uint S0 = ROTR32(a,2) ^ ROTR32(a,13) ^ ROTR32(a,22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s[0]+=a; s[1]+=b; s[2]+=c; s[3]+=d; s[4]+=e; s[5]+=f; s[6]+=g; s[7]+=h;
}

static void sha256_init(uint s[8]) {
    s[0]=0x6a09e667u; s[1]=0xbb67ae85u; s[2]=0x3c6ef372u; s[3]=0xa54ff53au;
    s[4]=0x510e527fu; s[5]=0x9b05688cu; s[6]=0x1f83d9abu; s[7]=0x5be0cd19u;
}

// prf256 computes HMAC-SHA256 resumed from the inner/outer pad states over a
// single-block message of mlen bytes (mlen <= 55), writing the 32-byte digest.
static void prf256(const uint inner[8], const uint outer[8],
                   const uchar *msg, uint mlen, uint out8[8]) {
    uint blk[16];
    for (int i = 0; i < 16; i++) blk[i] = 0;
    for (uint i = 0; i < mlen; i++)
        blk[i >> 2] |= ((uint)msg[i]) << (24 - 8 * (i & 3));
    blk[mlen >> 2] |= ((uint)0x80u) << (24 - 8 * (mlen & 3));
    ulong bits = (ulong)(64 + mlen) * 8;
    blk[14] = (uint)(bits >> 32);
    blk[15] = (uint)bits;
    uint st[8];
    for (int i = 0; i < 8; i++) st[i] = inner[i];
    sha256_block(st, blk);                       // inner = SHA256(ipad || msg)

    for (int i = 0; i < 16; i++) blk[i] = 0;
    for (int i = 0; i < 8; i++) blk[i] = st[i];
    blk[8] = 0x80000000u;                         // 0x80 after the 32-byte digest
    ulong bits2 = (ulong)(64 + 32) * 8;
    blk[14] = (uint)(bits2 >> 32);
    blk[15] = (uint)bits2;
    for (int i = 0; i < 8; i++) out8[i] = outer[i];
    sha256_block(out8, blk);                      // outer = SHA256(opad || inner)
}

__kernel void pbkdf2_sha256(
    __global const uchar *keys,    // nkeys * 64, each zero-padded
    __global const uint  *keylens, // vestigial; padding handled host-side
    __global const uchar *salt,
    const uint saltlen,
    const uint iter,
    const uint dklen,
    __global uchar *out)           // nkeys * dklen
{
    uint gid = get_global_id(0);
    const __global uchar *key = keys + (ulong)gid * 64;

    uint ipad[16], opad[16];
    for (int i = 0; i < 16; i++) {
        uint kw = ((uint)key[i*4] << 24) | ((uint)key[i*4+1] << 16) |
                  ((uint)key[i*4+2] << 8) | ((uint)key[i*4+3]);
        ipad[i] = kw ^ 0x36363636u;
        opad[i] = kw ^ 0x5c5c5c5cu;
    }
    uint inner[8], outer[8];
    sha256_init(inner); sha256_block(inner, ipad);
    sha256_init(outer); sha256_block(outer, opad);

    uint nblocks = (dklen + 31) / 32;
    uchar msg[64];
    for (uint blk = 1; blk <= nblocks; blk++) {
        for (uint i = 0; i < saltlen; i++) msg[i] = salt[i];
        msg[saltlen+0] = (uchar)(blk >> 24);
        msg[saltlen+1] = (uchar)(blk >> 16);
        msg[saltlen+2] = (uchar)(blk >> 8);
        msg[saltlen+3] = (uchar)(blk);
        uint u[8], t[8];
        prf256(inner, outer, msg, saltlen + 4, u);
        for (int i = 0; i < 8; i++) t[i] = u[i];
        uchar ubuf[32];
        for (uint it = 1; it < iter; it++) {
            for (int i = 0; i < 8; i++) {
                ubuf[i*4+0] = (uchar)(u[i] >> 24);
                ubuf[i*4+1] = (uchar)(u[i] >> 16);
                ubuf[i*4+2] = (uchar)(u[i] >> 8);
                ubuf[i*4+3] = (uchar)(u[i]);
            }
            prf256(inner, outer, ubuf, 32, u);
            for (int i = 0; i < 8; i++) t[i] ^= u[i];
        }
        uint off = (blk - 1) * 32;
        for (int i = 0; i < 32 && off + i < dklen; i++) {
            uint word = t[i >> 2];
            out[(ulong)gid * dklen + off + i] = (uchar)(word >> (24 - 8 * (i & 3)));
        }
    }
}
