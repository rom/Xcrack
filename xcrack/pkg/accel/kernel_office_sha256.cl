// OpenCL Office agile iterated-hash spin, SHA-256 variant, for the xcrackd GPU
// tier. One work-item spins one candidate. The host passes the 32-byte seed
// cur0 = SHA256(salt || UTF16LE(password)); this kernel runs the spin loop
//
//     for i in [0, spin):  cur = SHA256(LE32(i) || cur)
//
// Each message is LE32(i) || cur = 36 bytes, a single SHA-256 block. Output is
// byte-for-byte identical to prim.OfficeAgileHash(sha256.New, ...), validated
// against the Go reference at startup.

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

#define DIGEST 32
#define MLEN   (4 + DIGEST)

__kernel void office_spin_sha256(
    __global const uchar *seeds,  // nseeds * 32
    const uint spin,
    __global uchar *out)          // nseeds * 32
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

        uint st[8];
        st[0]=0x6a09e667u; st[1]=0xbb67ae85u; st[2]=0x3c6ef372u; st[3]=0xa54ff53au;
        st[4]=0x510e527fu; st[5]=0x9b05688cu; st[6]=0x1f83d9abu; st[7]=0x5be0cd19u;
        sha256_block(st, blk);
        for (int k = 0; k < DIGEST; k++)
            cur[k] = (uchar)(st[k >> 2] >> (24 - 8 * (k & 3)));
    }
    for (int i = 0; i < DIGEST; i++) out[(ulong)gid * DIGEST + i] = cur[i];
}
