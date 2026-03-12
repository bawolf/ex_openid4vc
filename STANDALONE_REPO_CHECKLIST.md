# Standalone Repo Bootstrap

Use this when preparing or refreshing the standalone `ex_openid4vc` repository
before triggering the automated publish workflow.

## `v0.1.0` Bootstrap

1. Sync the library into the standalone `ex_openid4vc` repository:

   ```bash
   /Users/bryantwolf/workspace/delegate/libs/ex_openid4vc/scripts/sync_standalone_repo.sh /path/to/ex_openid4vc_repo
   ```

2. In the standalone repo, review the diff:

   ```bash
   git status
   git diff --stat
   ```

3. Verify the package state from the standalone repo:

   ```bash
   mix deps.get
   mix release.gate
   ```

4. Commit the release state:

   ```bash
   git add .
   git commit -m "Release v0.1.0"
   ```

5. Push the commit:

   ```bash
   git push origin main
   ```

6. Trigger the standalone repository publish workflow with version `0.1.0`.

The publish workflow is responsible for:

- publishing to Hex
- creating the matching `v0.1.0` git tag
- creating the matching GitHub release
