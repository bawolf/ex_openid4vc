# ExOpenid4vc

Quick links: [Hex package](https://hex.pm/packages/ex_openid4vc) | [Hex docs](https://hexdocs.pm/ex_openid4vc) | [Parity matrix](https://github.com/bawolf/ex_openid4vc/blob/main/PARITY_MATRIX.md) | [Interop notes](https://github.com/bawolf/ex_openid4vc/blob/main/INTEROP_NOTES.md) | [Fixture policy](https://github.com/bawolf/ex_openid4vc/blob/main/FIXTURE_POLICY.md)

## What Standard Is This?

[OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
and [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
define how apps, wallets, issuers, and verifiers exchange credentials over
normal web and mobile protocols.

In plain terms: if `ex_vc` is about what a credential is, `ex_openid4vc` is
about how that credential gets offered, requested, and delivered between
systems.

## Why You Might Use It

Use `ex_openid4vc` when you need to:

- publish issuer metadata and credential offers
- parse credential request envelopes from wallets
- validate proof claims on incoming issuance requests
- keep OpenID4VC protocol concerns separate from VC and DID internals

`ExOpenid4vc` provides an Elixir-native boundary for the OpenID4VCI metadata and offer
objects Delegate will need as the issuance surface becomes more standards-complete.

Current scope:

- derive Credential Issuer metadata URLs
- build Credential Issuer metadata documents
- build credential configuration objects
- build Credential Offer payloads
- build authorization code and pre-authorized code grant objects
- build and parse credential request/response envelopes
- inspect JWT proofs
- validate JWT proof claims
- verify JWT proof signatures against explicit key material
- bind JWT proof keys to holder DIDs through `ex_did` when the resolved
  verification methods can be normalized into proof-compatible public JWKs

This package does not yet implement full issuance or presentation protocol handlers.

## Status

Current support:

- issuer metadata URL derivation
- credential issuer metadata construction
- credential configuration construction
- credential offer construction
- nonce response construction
- credential request and response shaping
- credential request parsing with stable error atoms for unsupported format, unsupported
  configuration, malformed proofs, and malformed response-encryption input
- deferred credential request parsing and deferred response construction
- notification request and notification error response construction
- JWT proof parsing and validation
- JWS proof verification
- holder binding through `ex_did` for DID methods whose verification material
  can be normalized into proof-compatible public JWKs

Current proof verification boundary:

- compact JWT proof parsing
- `typ`, `alg`, `aud`, `nonce`, and `iat` validation
- JWS signature verification
- embedded public JWKs in the protected header, or an explicit JWK supplied by the caller
- optional holder binding by resolving `holder_did` through `ex_did` and
  matching the proof key to normalized verification-method JWK material

Supported holder-binding methods:

- `did:jwk`: supported and tested
- `did:web`: supported when `ex_did` can normalize the resolved verification methods into public JWKs
- `did:key`: supported when `ex_did` can normalize the multikey verification material into public JWKs
- embedded public JWK in the proof header: supported and tested
- explicit caller-supplied verification JWK: supported and tested
- DID methods that `ex_did` cannot normalize into proof-compatible public JWKs:
  intentionally unsupported today

Intentionally deferred:

- broader holder DID method support beyond the current `ex_did`-normalized
  proof-key subset
- full OpenID4VCI authorization flows
- OpenID4VP presentation handling
- broader parity coverage for notification transport behavior

## Installation

```elixir
def deps do
  [
    {:ex_openid4vc, "~> 0.1.0"}
  ]
end
```

## Example

```elixir
configuration =
  ExOpenid4vc.credential_configuration("jwt_vc_json",
    scope: "agent_delegation",
    cryptographic_binding_methods_supported: ["did:web"],
    credential_signing_alg_values_supported: ["ES256"],
    proof_types_supported: %{
      "jwt" => %{
        "proof_signing_alg_values_supported" => ["ES256"]
      }
    },
    credential_definition: %{
      "type" => ["VerifiableCredential", "AgentDelegationCredential"]
    }
  )

metadata =
  ExOpenid4vc.issuer_metadata("https://issuer.delegate.local",
    credential_configurations_supported: %{
      "agent_delegation_jwt" => configuration
    }
  )
```

## Testing And Parity

The library is tested with:

- direct unit coverage for current protocol helpers
- committed upstream parity fixtures under `test/fixtures/upstream/`
- committed spec/semantic fixtures under `test/fixtures/spec/`
- maintainer-only live property tests against the pinned JS oracle
- secondary fixture/manual checks against relevant `spruceid/ssi` JOSE, VC-JWT, JWK, and DID
  semantics

Refresh upstream parity fixtures with the maintainer-only recorder:

```bash
cd libs/ex_openid4vc/scripts/upstream_parity
pnpm install
pnpm run record:released
```

When developing in this workspace before `ex_did` is published on Hex, use the
local sibling dependency override:

```bash
cd libs/ex_openid4vc
EX_OPENID4VC_USE_LOCAL_DEPS=1 mix deps.get
EX_OPENID4VC_USE_LOCAL_DEPS=1 mix test
```

Run live cross-implementation property checks after installing the maintainer
dependencies:

```bash
cd libs/ex_openid4vc
EX_OPENID4VC_LIVE_ORACLE=1 mix test test/upstream_live_property_test.exs
```

The parity model is intentionally split:

- `oid4vc-ts` is the primary protocol oracle for issuer metadata, credential offers, nonce
  responses, credential responses, and later deferred issuance and notifications.
- `spruceid/ssi` is the secondary semantic oracle for JOSE, VC-JWT, JWK, DID, and holder-binding
  overlap. It is not treated as a full issuer-side OpenID4VCI oracle.

The current intentionally manual parity surfaces are:

- metadata URL derivation
- issuer metadata construction
- credential configuration construction

Those remain manual because `oid4vc-ts` currently does not expose stable public
builder APIs for them. They are still documented and covered by direct Elixir
tests, but they are not claimed as cross-implementation contractual parity.

Normal `mix test` and normal `ex_openid4vc` usage do not require Node, pnpm, or
network access. The committed fixtures are the contract.

Run the package release gate locally with:

```bash
mix ex_openid4vc.release.gate
```

Maintainers should include the live oracle checks before cutting a release:

```bash
EX_OPENID4VC_LIVE_ORACLE=1 mix ex_openid4vc.release.gate --include-live-oracle
```

## Open Source Notes

- Fixture policy: `FIXTURE_POLICY.md`
- Parity matrix: `PARITY_MATRIX.md`
- License: MIT
- Changelog: `CHANGELOG.md`
- Canonical package repository: [github.com/bawolf/ex_openid4vc](https://github.com/bawolf/ex_openid4vc)
- The current stable public facade is `ExOpenid4vc`; the release-gate task and oracle tooling are maintainer tooling, not the runtime API.

## Maintainer Workflow

`ex_openid4vc` is developed in the `delegate` monorepo. The public
`github.com/bawolf/ex_openid4vc` repository is the mirrored OSS surface for
issues, discussions, releases, and Hex publishing.

The monorepo copy is authoritative for:

- code
- tests and fixtures
- docs
- GitHub workflows
- release tooling

Direct standalone-repo edits are temporary hotfixes only and must be
backported to the monorepo immediately.

The intended workflow is:

1. make library changes in `libs/ex_openid4vc`
2. run `scripts/release_preflight.sh`
3. run `EX_OPENID4VC_LIVE_ORACLE=1 mix ex_openid4vc.release.gate --include-live-oracle` before a release when the live oracle corpus is part of the current contract
4. publish the corresponding `ex_did` dependency release first when `ex_openid4vc` depends on a newer `ex_did` version
5. sync the package into a clean checkout of `github.com/bawolf/ex_openid4vc`
6. verify the mirrored required file set with `scripts/verify_standalone_repo.sh`
7. review and push from the standalone repo
8. trigger the standalone publish workflow with the release version

A helper to sync all public package repos from the monorepo lives at
`/Users/bryantwolf/workspace/delegate/scripts/sync_public_libs.sh`.

The mirrored standalone repository carries GitHub Actions workflows for:

- CI on push and pull request
- manual publish through `workflow_dispatch`

The publish workflow expects a `HEX_API_KEY` repository secret in the standalone
`ex_openid4vc` repository. Once triggered, it publishes to Hex and then creates
the matching Git tag and GitHub release automatically.

## Releasing From GitHub

Releases are cut from the public `github.com/bawolf/ex_openid4vc` repository,
not from the private monorepo checkout.

The shortest safe path is:

1. finish the change in `libs/ex_openid4vc`
2. run `scripts/release_preflight.sh`
3. if the current contract requires it, run `EX_OPENID4VC_LIVE_ORACLE=1 mix ex_openid4vc.release.gate --include-live-oracle`
4. if `mix.exs` points at a newer `ex_did`, publish `ex_did` first
5. sync and verify the standalone repo with `scripts/sync_standalone_repo.sh` and `scripts/verify_standalone_repo.sh`
6. push the mirrored release commit to `main` in `github.com/bawolf/ex_openid4vc`
7. in GitHub, go to `Actions`, choose `Publish`, and run it with the version from `mix.exs`

The GitHub workflow is responsible for:

- rerunning the release gate
- publishing to Hex
- creating the matching git tag
- creating the matching GitHub release
