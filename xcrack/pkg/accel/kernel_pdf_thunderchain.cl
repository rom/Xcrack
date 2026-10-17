// PDF V1/R2 "Thunder Table" rainbow-chain generator for the xcrackd GPU tier.
//
// Generating a precomputed table for the 2^40 R2 file-key space is the heavy,
// one-time cost of the TMTO. Each rainbow chain is an independent sequential walk
// of `chainLen` columns, so the work parallelises perfectly across chains: one
// work-item per chain. Each step computes the R2 image — the first 8 bytes of
// U = RC4(fileKey, pad) as a little-endian u64 — and the column-indexed reduction
// k = (image + seed + col) mod n. n is a power of two, so the modulo is a mask
// (n-1), passed in as nMask.
//
// This is byte-for-byte identical to the pure-Go walk in
// xcrypto/scheme/pdf/thundertable.go (r2Image + reduce), so a table generated
// here is inverted by the same CPU Lookup; validated against the Go reference at
// startup (GPUSelfTest) and GPU-vs-CPU in the cmd tests.

// The fixed 32-byte PDF Standard Security Handler padding string (PDF spec
// Algorithm 2) — the universal constant R2 encrypts to form /U.
__constant uchar PDFPAD[32] = {
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A
};

// r2Image8 returns the first 8 bytes of RC4(key5, pad) for the 40-bit key index,
// as a little-endian u64. key byte ki cycles 0..4 (5-byte RC4 key), matching the
// Go r2Image hot loop.
inline ulong r2Image8(ulong idx) {
    uchar key[5];
    key[0] = (uchar)(idx & 0xffu);
    key[1] = (uchar)((idx >> 8) & 0xffu);
    key[2] = (uchar)((idx >> 16) & 0xffu);
    key[3] = (uchar)((idx >> 24) & 0xffu);
    key[4] = (uchar)((idx >> 32) & 0xffu);

    uchar s[256];
    for (uint i = 0; i < 256; i++) s[i] = (uchar)i;
    uint j = 0, ki = 0;
    for (uint i = 0; i < 256; i++) {
        j = (j + s[i] + key[ki]) & 0xffu;
        uchar t = s[i]; s[i] = s[j]; s[j] = t;
        if (++ki == 5u) ki = 0;
    }
    uint a = 0, b = 0;
    ulong v = 0;
    for (uint n = 0; n < 8; n++) {
        a = (a + 1u) & 0xffu;
        b = (b + s[a]) & 0xffu;
        uchar t = s[a]; s[a] = s[b]; s[b] = t;
        uchar ks = s[(s[a] + s[b]) & 0xffu];
        v |= (ulong)(PDFPAD[n] ^ ks) << (8u * n);
    }
    return v;
}

__kernel void pdf_thunderchain(const ulong nMask,    // n-1 (n is a power of two)
                               const uint chainLen,
                               const ulong seed,
                               const ulong startIdx,
                               const uint count,
                               __global ulong *out)   // count endpoints
{
    uint gid = get_global_id(0);
    if (gid >= count) return;
    ulong k = startIdx + (ulong)gid; // chain start index (matches the Go start = i)
    for (uint col = 0; col < chainLen; col++) {
        k = (r2Image8(k) + seed + (ulong)col) & nMask;
    }
    out[gid] = k;
}
