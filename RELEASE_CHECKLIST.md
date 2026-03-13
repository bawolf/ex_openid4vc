# Release Checklist

Before publishing a Hex release:

1. `scripts/release_preflight.sh` passes.
2. `EX_OPENID4VC_LIVE_ORACLE=1 mix ex_openid4vc.release.gate --include-live-oracle` passes before cutting or refreshing a release when the live oracle corpus is part of the current contract.
3. The released parity corpus is current for every non-live contractual surface.
4. README, parity matrix, and supported-features docs agree on supported vs deferred surfaces.
5. Any intentional divergence from `oid4vc-ts` or `spruceid/ssi` is documented.
6. The changelog includes the release.
7. If `mix.exs` depends on a newer `ex_did` release, publish `ex_did` first so the standalone `ex_openid4vc` repo can resolve the Hex dependency.
8. Sync `libs/ex_openid4vc` into a clean checkout of `github.com/bawolf/ex_openid4vc` with `scripts/sync_standalone_repo.sh /path/to/ex_openid4vc_repo`.
9. Verify the mirrored required file set with `scripts/verify_standalone_repo.sh /path/to/ex_openid4vc_repo`.
10. Direct standalone-repo edits are temporary hotfixes only and must be backported to `libs/ex_openid4vc` immediately.
11. Push the release commit to the standalone repository.
12. Trigger the standalone repo publish workflow with the same version; it should publish to Hex and create the matching tag and GitHub release automatically.
