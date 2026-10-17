// Batch salted SHA-1 — SHA1(password || salt) — for the xcrackd GPU tier. This
// is hashcat's sha1($pass.$salt) shape (mode 110), used by the Microsoft VBA
// project-protection verifier (MS-OVBA 2.4.4.4: PasswordHash = SHA1(password ||
// 4-byte key)). One work-item hashes one candidate.
//
// Unlike the PBKDF2 kernels this is a single, un-iterated hash, so it is cheap
// per candidate: the device's job is to compute the whole batch at once and the
// host compares each 20-byte digest to the target, re-checking any apparent hit
// on the CPU (the device never decides correctness). The output is byte-for-byte
// identical to crypto/sha1 over (password || salt), validated against the Go
// reference at startup (GPUSelfTest).
//
// Each password occupies a fixed `pwStride`-byte slot in `pw`; `pwlens[gid]` is
// its true length. The host guarantees pwlens[gid] + saltLen + 9 <= MAXMSG, so
// the padded message always fits MSGBUF and the caller falls back to the CPU for
// anything longer (ErrUnsupported).

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
#define MSGBUF 256 // message + SHA-1 padding, a multiple of the 64-byte block

__kernel void vba_sha1(__global const uchar *pw,
                       const uint pwStride,
                       __global const uint *pwlens,
                       __global const uchar *salt,
                       const uint saltLen,
                       const uint n,
                       __global uchar *out) // n * 20
{
    uint gid = get_global_id(0);
    if (gid >= n) return;

    uint plen = pwlens[gid];
    uint mlen = plen + saltLen; // true message length, before padding

    uchar msg[MSGBUF];
    for (uint i = 0; i < plen; i++) msg[i] = pw[(ulong)gid * pwStride + i];
    for (uint i = 0; i < saltLen; i++) msg[plen + i] = salt[i];

    // SHA-1 padding: 0x80, then zeros to 56 mod 64, then the 64-bit big-endian
    // message bit length.
    ulong bits = (ulong)mlen * 8;
    uint p = mlen;
    msg[p++] = 0x80u;
    while ((p & 63u) != 56u) msg[p++] = 0u;
    for (int i = 0; i < 8; i++) msg[p++] = (uchar)(bits >> (56 - 8 * i));

    uint st[5];
    st[0] = 0x67452301u; st[1] = 0xEFCDAB89u; st[2] = 0x98BADCFEu;
    st[3] = 0x10325476u; st[4] = 0xC3D2E1F0u;
    for (uint off = 0; off < p; off += 64) {
        uint blk[16];
        for (int k = 0; k < 16; k++) {
            uint j = off + 4u * k;
            blk[k] = ((uint)msg[j] << 24) | ((uint)msg[j+1] << 16) |
                     ((uint)msg[j+2] << 8) | ((uint)msg[j+3]);
        }
        sha1_block(st, blk);
    }

    for (int k = 0; k < DIGEST; k++)
        out[(ulong)gid * DIGEST + k] = (uchar)(st[k >> 2] >> (24 - 8 * (k & 3)));
}
