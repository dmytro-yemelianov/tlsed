# Public test fixtures

Generated once with OpenSSL3.6.5 on2026-10-14 and committed as fixed DER.
These keys are intentionally public test material, never production credentials.
Self-signed non-CA certificates are explicitly trusted only inside tests.
Baseline CA-signed P256 chain/key comes from ../../tls-bench/fixtures.
New fixtures: ip(P256/IP SAN127.0.0.1), cn_only(P256/no SAN),
ed25519(DNSlocalhost), rsa(RSA2048/DNSlocalhost), client-only(P256/clientAuth EKU).
All have critical CA:false and digitalSignature; others have serverAuth EKU.
Validity uses 3650 days from generation; tests use2026-10-15 UTC, not wallclock.
IP/CN/client-only generation private keys discarded; RSA/Ed private keys retained
for native CertificateVerify signing tests. No system trust store is modified.

SHA256 hashes of exact committed DER files:

f57a6a9783c8f5f7c8df5cfac75c7549735e0c53f7557acee074f6981dca1804  client-only.der
4489e1c25efe179af9bd67eafe51ca035a027cf419926909b462c164f8c0afb6  cn_only.der
b7df083cedd30265363dc0e02d35a569334286324afb66379e3c7baa9e570457  ed25519-key.der
146a4d17c423000b1754ddc5deee93f302fedda1b63fc5ebc44a0914e131d1ff  ed25519.der
9c2fa412803dfe2cd67753ededbb916e2aaae06b322d4a15a86651936bd94efb  ip.der
e1a9f5aad519371e7645fb8e2ee080fdcab3c02d1986d2994e4d89abe3a77ca1  rsa-key.der
bc47272a0b8d9b9660c7fb57ca51d8a382feae0c8bf6fd5013c20cb19e413f99  rsa.der


Strict KU fixtures were generated with the same OpenSSL3.6.5 on2026-10-14.
ku-root is an explicit CA trust anchor with digitalSignature but no keyCertSign;
this intentionally demonstrates anchor separation. Three root-signed issuer
certificates share a subject/key: good(keyCertSign), bad(digitalSignature only),
and absent(no KU). Leaf variants have digitalSignature, keyEncipherment only,
absent KU, or a raw OpenSSL DER KU value with an extra trailing byte. All signing
keys were discarded. Expectations come from declared extensions and policy,
not custom X.509 cryptography. SHA256 of added exact DER fixtures:

2fa24f23a93d631ee5c8b8e95a7a0ea7eb348333dbb66ace0f6f8fdb92fcfcaf  ku-intermediate-absent.der
cb1d17ddf61560a752d8008c08d99bd1dcaee3098b5f82e18f5a9d9e7db7d30c  ku-intermediate-bad.der
44eeeddd3a369a4215485213c7b8a0a42bbd5b2a8db5dd90337cecf2081be1aa  ku-intermediate-good.der
1fac3363012a77aab7c8be6088db7d362f69505109896dae7b74c5446851a8cc  ku-leaf-absent.der
8e97e671bec736e59f7302e1157779366522c781f98d2f909e6ec27d0277e569  ku-leaf-bad.der
dbbacc97d0f3fc1fd5aa2aa494ec1a9675ba89fb26c22deee5fd7651de7bd88e  ku-leaf-good.der
8c464d97c46dbfba96b92959f4acc35c9adb631d20bf450a1f18de993698b2dd  ku-leaf-trailing.der
f56edaaee51e0750db2b4a9cce59c55196080512c0e780b12583340f4f82d12d  ku-root.der

Canonical KU negative fixtures are fixed self-signed non-CA test credentials.
Their raw KU DER encodes noncanonical zero padding (03:02:00:80), unknown
bit9 (03:03:06:80:40), or discarded high bit16 (03:04:07:80:00:80). They
are explicit fixed test anchors only to reach the separately checked leaf
role after signature validation; no arbitrary peer input is trusted. All keys
were discarded. SHA256 added DER:

2c6e933c72c08b426aa7590cadd5680a579eeeb690d278b7865dea37f64ae53a  ku-noncanonical.der
350c73e25b19365bc30b4a766ad585a828e7b9b971c11b561887bb40de019c29  ku-unknown-bit.der
46d35dd1b5ecbcaba3ae5036db44b766b9d5b146b7f73910b84f9cd1b2177a09  ku-truncated-high-bits.der
