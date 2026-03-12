# Release Checklist

Before publishing a Hex release:

1. `mix release.gate` passes.
2. `EX_OPENID4VC_LIVE_ORACLE=1 mix release.gate --include-live-oracle` passes before cutting or refreshing a release.
3. The released parity corpus is current for every non-live contractual surface.
4. README, parity matrix, and supported-features docs agree on supported vs deferred surfaces.
5. Any intentional divergence from `oid4vc-ts` or `spruceid/ssi` is documented.
6. The changelog includes the release.
7. Sync `libs/ex_openid4vc` into a clean checkout of `github.com/bawolf/ex_openid4vc` with `scripts/sync_standalone_repo.sh /path/to/ex_openid4vc_repo`.
8. Push the release commit to the standalone repository.
9. Trigger the standalone repo publish workflow with the same version; it should publish to Hex and create the matching tag and GitHub release automatically.
