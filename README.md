# ExOpenid4vc

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
mix release.gate
```

Maintainers should include the live oracle checks before cutting a release:

```bash
EX_OPENID4VC_LIVE_ORACLE=1 mix release.gate --include-live-oracle
```

## Open Source Notes

- Fixture policy: `FIXTURE_POLICY.md`
- Parity matrix: `PARITY_MATRIX.md`
- License: MIT
- Changelog: `CHANGELOG.md`
- Canonical package repository: [github.com/bawolf/ex_openid4vc](https://github.com/bawolf/ex_openid4vc)
- The current stable public facade is `ExOpenid4vc`; the release-gate task and oracle tooling are maintainer tooling, not the runtime API.

## Maintainer Workflow

`ex_openid4vc` currently lives in the `delegate` monorepo and is mirrored into
the standalone `ex_openid4vc` repository for publishing and external
consumption.

The intended workflow is:

1. make library changes in `libs/ex_openid4vc`
2. run `mix release.gate`
3. run `EX_OPENID4VC_LIVE_ORACLE=1 mix release.gate --include-live-oracle`
4. sync the package into a clean checkout of `github.com/bawolf/ex_openid4vc`
5. review and push from the standalone repo
6. trigger the standalone publish workflow with the release version

A helper script for the sync step lives at `scripts/sync_standalone_repo.sh`.

The standalone repository also carries GitHub Actions workflows for:

- CI on push and pull request
- manual publish through `workflow_dispatch`

The publish workflow expects a `HEX_API_KEY` repository secret in the standalone
`ex_openid4vc` repository. Once triggered, it publishes to Hex and then creates
the matching Git tag and GitHub release automatically.
