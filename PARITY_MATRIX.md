# ExOpenid4vc Parity Matrix

Primary protocol oracle:

- package: `@openid4vc/openid4vci`
- version: `0.4.5`
- source repository: `openwallet-foundation-labs/oid4vc-ts`
- pinned upstream commit inspected while building the harness: `83c6c31a336f422cf09d2b52dbecb1ff8878ea6c`

Secondary semantic oracle:

- repository: `spruceid/ssi`
- role: cross-check JOSE, VC-JWT, JWK, DID, and holder-binding semantics that overlap with
  `ex_openid4vc`
- scope boundary: do not treat `ssi` as an issuer-side OpenID4VCI envelope oracle
- current test mode: fixture/manual until a stable, scriptable comparison harness is added

## Current Matrix

| Feature | Spec Status | `ex_openid4vc` | JS Oracle | Test Mode | Notes |
| --- | --- | --- | --- | --- | --- |
| Metadata URL derivation | Required helper in practice | Supported | No stable public helper | Manual | `oid4vc-ts` does not expose a stable public builder/helper for this URL mapping |
| Credential issuer metadata construction | Core issuer surface | Supported | Validation-oriented API | Manual | `oid4vc-ts` consumes issuer metadata shapes but does not expose a stable public metadata-construction API |
| Credential configuration construction | Core issuer surface | Supported | Validation-oriented API | Manual | `oid4vc-ts` validates/consumes these objects but does not expose a direct public configuration builder |
| Credential offer construction | Core issuer surface | Supported | Supported | Property + released fixture | First contractual parity surface |
| Nonce response construction | Core issuer surface | Supported | Supported | Property + released fixture | First contractual parity surface |
| Credential response construction | Core issuer surface | Supported | Supported | Property + released fixture | Live oracle property tests now cover deterministic response construction |
| Credential request parsing | Core issuer surface | Supported | Supported | Released fixture | App now consumes the library parser for wallet-facing requests |
| Deferred issuance | Core issuer surface | Supported | Supported | Released fixture | Deferred request parsing and deferred response construction are library-owned |
| Notification handling | Core issuer surface | Supported | Supported | Fixture | Contractual spec fixtures cover request and error shapes; no stable upstream transport helper is exposed |
| JWT proof validation | Core issuer surface | Supported | Supported | Fixture + secondary semantic oracle | Covered by pinned proof fixtures plus JOSE/DID overlap checks informed by `spruceid/ssi` |
| Holder binding via DIDs normalized through `ex_did` | App-critical extension | Supported | Partial/indirect | Fixture + secondary semantic oracle | Covered by pinned `did:jwk`, `did:key`, and `did:web` fixtures under the current `ex_did` normalization contract |

## Oracle Split

- `oid4vc-ts` is the primary oracle for issuer-side OpenID4VCI protocol shapes and deterministic
  builder behavior.
- `spruceid/ssi` is the secondary oracle for overlapping JOSE, VC-JWT, JWK, DID, and proof
  semantics.
- When the two cover different layers, parity claims must name which oracle backs the claim instead
  of collapsing them into a single generic "upstream" status.
- `Manual` rows are allowed only where the upstream library does not expose a stable public surface
  suitable for contractual comparison.

## Release Gate

Do not claim parity unless:

- released fixture corpus is current,
- contractual parity tests pass,
- live oracle property tests pass for all `Property` surfaces,
- any remaining `Manual` or `Deferred` entries are explicitly documented in README.
