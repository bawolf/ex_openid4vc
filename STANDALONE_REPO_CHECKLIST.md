# Standalone Repo Mirror Checklist

Use this when preparing or refreshing the mirrored `ex_openid4vc` repository
before triggering the automated publish workflow.

The monorepo copy in `libs/ex_openid4vc` is authoritative for code, tests,
docs, workflows, and release tooling. Direct standalone-repo edits are
temporary hotfixes only and must be backported immediately.

1. Run the maintainer preflight from the monorepo:

   ```bash
   /Users/bryantwolf/workspace/delegate/libs/ex_openid4vc/scripts/release_preflight.sh
   ```

2. Sync the library into the standalone `ex_openid4vc` repository:

   ```bash
   /Users/bryantwolf/workspace/delegate/libs/ex_openid4vc/scripts/sync_standalone_repo.sh /path/to/ex_openid4vc_repo
   ```

3. Verify that the required mirrored files match:

   ```bash
   /Users/bryantwolf/workspace/delegate/libs/ex_openid4vc/scripts/verify_standalone_repo.sh /path/to/ex_openid4vc_repo
   ```

4. In the standalone repo, review the diff:

   ```bash
   git status
   git diff --stat
   ```

5. Verify the package state from the standalone repo:

   ```bash
   mix deps.get
   mix ex_openid4vc.release.gate
   ```

6. Commit the release state:

   ```bash
   git add .
   git commit -m "Prepare release"
   ```

7. Push the commit:

   ```bash
   git push origin main
   ```

8. Trigger the standalone repository publish workflow with the release version.

The publish workflow is responsible for:

- publishing to Hex
- creating the matching git tag
- creating the matching GitHub release
