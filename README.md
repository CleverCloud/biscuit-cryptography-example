# example implementation for Biscuit token cryptography

To aid in the implementation of [Biscuit tokens](https://github.com/CleverCloud/biscuit)
in various languages, this repository contains an example implementation
of its cryptographic algorithms using [libsodium](https://doc.libsodium.org/).

Biscuit uses [Aggregated Gamma Signatures](https://eprint.iacr.org/2018/414.pdf)
("Aggregation of Gamma-Signatures and Applications to Bitcoin, Yunlei Zhao")
for its attenuation scheme, and this algorithm is implemented over the
[Ristretto group](https://ristretto.group) ("Ristretto: prime order elliptic
curve groups with non-malleable encodings"), of which libsodium proposes
an implementation.

The libsodium implementation is available in `src/sodium.rs`.
