# Supported Features

## Core Surfaces

| Surface | Status | Notes |
| --- | --- | --- |
| Metadata URL derivation | Supported | `https` issuers only |
| Credential issuer metadata | Supported | Builder-oriented |
| Credential configuration | Supported | Generic issuer-side helper |
| Credential offer | Supported | Authorization code and pre-authorized code grants |
| Nonce response | Supported | Deterministic parity-tested surface |
| Credential request builder | Supported | Wallet-facing request shaping |
| Credential request parser | Supported | Includes unsupported-format and unsupported-configuration errors |
| Credential response | Supported | Released fixture and live-oracle property covered |
| Deferred credential request parser | Supported | Transaction-id based deferred polling |
| Deferred credential response | Supported | Pending and issued paths |
| Notification request | Supported | Contractual spec fixture covered; request shape only, no transport |
| Notification error response | Supported | Contractual spec fixture covered; error shape only, no transport |

## Proof And Binding

| Surface | Status | Notes |
| --- | --- | --- |
| JWT proof inspection | Supported | Compact JWT parsing |
| JWT proof claim validation | Supported | `typ`, `alg`, `aud`, `nonce`, `iat` |
| JWT proof signature verification | Supported | Embedded or caller-supplied JWK |
| Holder binding via `did:jwk` | Supported | Uses `ex_did`; fixture-covered |
| Holder binding via `did:web` | Supported | Uses caller-supplied `fetch_json` through `ex_did`; fixture-covered |
| Holder binding via `did:key` | Supported | Uses `ex_did` multikey normalization; fixture-covered |
| DID methods that `ex_did` cannot normalize into public JWKs | Unsupported | Explicitly deferred |

## Deferred

Not yet supported:

- full OAuth/OpenID authorization flows
- notification transport behavior
- interactive authorization
- OpenID4VP
- holder DID method coverage beyond the current `ex_did`-normalized proof-key subset
