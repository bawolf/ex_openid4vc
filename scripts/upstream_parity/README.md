# Upstream Parity Recorder

This maintainer-only tool records deterministic outputs from the pinned
JavaScript OpenID4VCI oracle into committed fixtures under
`test/fixtures/upstream/`.

## Usage

Install the pinned recorder dependencies:

```bash
pnpm install
```

Refresh the contractual released corpus:

```bash
pnpm run record:released
```

After refreshing fixtures, rerun the package release gate from the library root:

```bash
mix ex_openid4vc.release.gate
EX_OPENID4VC_LIVE_ORACLE=1 mix ex_openid4vc.release.gate --include-live-oracle
```

Normal `mix test` and normal `ex_openid4vc` usage do not require Node, pnpm,
or network access. The JavaScript toolchain is only for maintainers refreshing
committed upstream parity fixtures.

This harness only records surfaces that `oid4vc-ts` exposes through stable
issuer-side APIs and that can be normalized contractually. Metadata URL
derivation, issuer metadata construction, and credential configuration
construction remain documented manual parity rows until the upstream library
exposes stable public builder surfaces for them.

## Policy

- `released/` is contractual and should back CI.
- Live property checks are advisory and should be used before refreshing fixtures.
- Only deterministic normalized JSON outputs and manifests should be committed.
- Scratch captures, debug dumps, and temporary installs should stay untracked.
