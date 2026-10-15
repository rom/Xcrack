# Legacy MS Office test fixtures — provenance & license

These encrypted sample documents and their decrypted counterparts are the
cross-validation oracle for the `msoffice` format. They are vendored verbatim
from the test corpus of **msoffcrypto-tool** (https://github.com/nolze/msoffcrypto-tool),
which is MIT-licensed. They let Xcrack prove its legacy-Office decryption is
byte-for-byte correct without depending on a reference tool at test time.

| encrypted input | decrypted gold output | scheme | password |
| --------------- | --------------------- | ------ | -------- |
| `rc4cryptoapi_password.doc` | `rc4cryptoapi_password_plain.doc` | RC4 CryptoAPI | `Password1234_` |
| `rc4cryptoapi_password.xls` | `rc4cryptoapi_password_plain.xls` | RC4 CryptoAPI | `Password1234_` |
| `rc4cryptoapi_password.ppt` | `rc4cryptoapi_password_plain.ppt` | RC4 CryptoAPI | `Password1234_` |
| `xor_password_123456789012345.xls` | *(none — see note)* | XOR obfuscation | `123456789012345` |

The decrypted `rc4cryptoapi_*_plain.*` files were produced by msoffcrypto-tool;
Xcrack's tests decrypt the inputs independently and compare the resulting OLE
streams against the streams of these gold outputs byte-for-byte.

**XOR note:** the reference tool's decrypted XOR output is a differently-sized
re-save, so it is not a byte-exact oracle (the reference's own test compares it
only fuzzily). It is omitted here. The XOR input is still used to validate
detection, password verification, and a structurally-sound decrypt; the XOR
cryptography itself is round-trip tested in
`xcrypto/scheme/officebinary`.

## MIT License (msoffcrypto-tool)

```
MIT License

Copyright (c) 2015 nolze

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
