# Interop Notes

## Oracle Model

`ex_openid4vc` uses a split interoperability model:

- `oid4vc-ts` is the primary oracle for issuer-side OpenID4VCI protocol shapes.
- `spruceid/ssi` is the secondary oracle for overlapping JOSE, VC-JWT, JWK, DID, and holder-binding semantics.

## Current Evidence

- released upstream parity corpus under `test/fixtures/upstream/released/`
- contractual spec/semantic fixtures under `test/fixtures/spec/`
- maintainer-only live property checks against the pinned `oid4vc-ts` oracle
- fixture/manual semantic comparison guidance for `spruceid/ssi`

## Intentional Limits

- notification transport is not yet cross-implementation tested because the current oracle value is mainly schema-level, not a stable issuer helper surface
- issuer metadata and credential configuration remain manual parity rows because the current JS
  oracle consumes them but does not expose stable public builder APIs for direct contractual
  comparison
- holder binding is routed through `ex_did`, and the current contractual subset
  is defined by whatever DID methods `ex_did` can normalize into
  proof-compatible public JWKs under the chosen validation mode
- parity claims should always name the oracle and surface, not just say "upstream-compatible"
