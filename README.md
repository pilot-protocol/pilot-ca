# pilot-ca

Offline root-CA tooling for the Pilot Protocol. Generates and manages the Ed25519 root certificate that signs beacon WSS leaf certs in compat mode (TLS over port 443).

The root **private key is the trust anchor for every compat-mode daemon**. It must never leave the operator's secure machine (Yubikey-backed or air-gapped). This binary is the only production code that touches it.

## Install

```bash
go install github.com/pilot-protocol/pilot-ca@latest
```

## Subcommands

```
pilot-ca init-root <out-dir>
   Generate a fresh Ed25519 root CA keypair + self-signed root cert.
   Writes <out-dir>/root.key (mode 0600) and <out-dir>/root.crt.
   The .key file must be moved to offline storage immediately.

pilot-ca issue-beacon <root-dir> <hostname> <out-dir>
   Sign a leaf cert for a beacon hostname using the root in <root-dir>.
   Writes <out-dir>/<hostname>.key and <out-dir>/<hostname>.crt.
```

## Operational notes

See `docs/RUNBOOK-pilot-ca.md` in the `pilot-protocol/docs` repo for the full procedure: airgap setup, root rotation cadence, key-ceremony witnesses.

The CA tooling has a deliberately small surface and rare invocation cadence — every commit here is material to the trust anchor and should be reviewable in isolation.
