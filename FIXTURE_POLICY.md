# Fixture Policy

`ex_openid4vc` ships its interoperability corpus in-repo.

## Contract Levels

- `test/fixtures/upstream/released/` is contractual.
- `test/fixtures/spec/` is contractual for spec- and semantic-fixture surfaces
  that do not rely on the JS protocol oracle.
- Live oracle checks are maintainer-only and advisory until committed into the released corpus.

Released fixtures are the parity contract used by tests. Live property checks
exist to refresh confidence against the pinned JS oracle before the corpus is
updated.

The package release gate should treat the released corpus as mandatory:

- `mix ex_openid4vc.release.gate` must pass against committed fixtures alone
- `EX_OPENID4VC_LIVE_ORACLE=1 mix ex_openid4vc.release.gate --include-live-oracle` is the
  maintainer pre-release check before refreshing or publishing

## Runtime Boundary

Using `ex_openid4vc` does not require JavaScript, `pnpm`, or network access.
Normal Elixir tests should only consume committed fixtures.

JavaScript tooling is maintainer-only and exists solely to refresh upstream
fixtures under `libs/ex_openid4vc/scripts/upstream_parity/`.

The oracle model is split:

- `oid4vc-ts` backs the issuer-side OpenID4VCI protocol fixture corpus.
- `spruceid/ssi` backs selected semantic fixtures for overlapping JOSE, VC-JWT, JWK, DID, and
  holder-binding behavior.
- local spec fixtures back notification, proof, and holder-binding contract
  surfaces that are intentionally not claimed as JS-oracle envelope parity.
- Do not use `spruceid/ssi` fixtures to claim parity for issuer-specific OpenID4VCI envelope
  behavior it does not implement.

## What Gets Committed

Commit:

- normalized JSON fixtures
- corpus manifests with oracle provenance
- recorder and oracle adapter source code
- package manager manifest and lockfile for the recorder

Do not commit:

- scratch captures
- temporary upstream checkouts
- debug dumps
- machine-specific cache files

## Compat Rules

When `ex_openid4vc` intentionally diverges from the JS oracle:

1. the divergence must be documented in `PARITY_MATRIX.md`,
2. the released fixture corpus must show the current expected behavior,
3. README status text must reflect the deferral or incompatibility.
