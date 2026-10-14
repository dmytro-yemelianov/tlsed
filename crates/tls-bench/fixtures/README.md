# Fixed public benchmark fixtures

Local test CA and ECDSA P256/SHA256 leaf with SAN DNS:localhost, digitalSignature,
serverAuth. Leaf serial2; validity2026-10-14 06:52:07 UTC through2036-10-11
06:52:07 UTC. The committed DER and PEM encode identical certificates/key.
The fixtures are fixed/reproducible inputs; handshakes still use secure fresh
randomness and ephemeral keys. They are not production credentials. The leaf
private key is intentionally public for this local benchmark, and the CA
private key was discarded. No trust store outside the benchmark is modified.
After expiration, replace fixtures deliberately and record the change; never
bypass certificate/time verification to keep a benchmark running.
