# XMSS / XMSS^MT (RFC 8391) Test Certificate

`xmss_root_cert.der` is a self-signed **XMSS-SHA2_10_256** X.509 root cert,
used only by the wolfJCE WKS KeyStore round-trip test. wolfJCE provides
verify-only XMSS, so wolfJCE only includes this cert, no signing key.

XMSS uses stateful hash-based signatures, so this certificate cannot be
regenerated with `openssl` / `renewcerts.sh` the way the RSA/ECC certs are.

This certificate is generated with a 10-year validity and is not chain
validated by the test, only stored as a trusted entry and round tripped through
the KeyStore.

Produced with native wolfSSL built with XMSS and cert generation enabled:

```
./configure --enable-xmss --enable-certgen --enable-keygen
make && sudo make install
```

Generation used `wc_MakeCert_ex` / `wc_SignCert_ex` with `XMSS_TYPE` /
`CTC_XMSS` to generate and output the .der cert.

