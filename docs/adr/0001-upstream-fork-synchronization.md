# Preserve upstream ancestry when synchronizing the Accelerate Obot fork

The Accelerate fork treats `obot-platform/obot` as the canonical implementation. Each synchronization starts from the current upstream `main`, retains only the net Accelerate-specific behavior that upstream does not already provide, and groups that behavior into reviewable commits. The sync reaches the fork's protected `main` through a reviewed merge commit so the exact upstream commit remains an ancestor; prior sync commits, metadata-only commits, obsolete intermediate fixes, and duplicate implementations are not replayed.

Providers synchronizes and publishes first because the Obot release consumes the Accelerate providers images. The release version matches the highest stable upstream tag, while sync metadata records both that tag and the exact upstream commit. Publication advances `latest` and `<upstream-version>-vibedata` together for the providers and Obot images. Completion requires required PR checks, merge, successful post-merge image publication, and verification that the published tags resolve to the synchronized sources. Publication remains fail-closed, and failures are repaired forward without reverting the synchronized history. The scheduled sync workflow must create the labels, metadata, conflict-resolution branch, and draft PR needed to enforce this process.

## Operating flow

1. Fetch both remotes and record the exact fork `main`, upstream `main`, recorded upstream checkpoint, and highest stable upstream tag.
2. Synchronize providers first. Start from upstream `main`, apply the net fork delta since the recorded checkpoint, and omit prior sync commits, metadata-only commits, obsolete intermediate fixes, and behavior that upstream now provides.
3. Classify overlapping behavior as required fork behavior, upstream-equivalent behavior, or unique but unproven behavior. Preserve required behavior; use upstream for equivalent behavior; preserve and flag unproven behavior until evidence shows it is obsolete.
4. Require a focused automated test or an explicit CI/release assertion for every retained fork behavior. Keep build and sync-automation repairs as separate commits in the sync PR.
5. Update the existing draft sync PR by force-with-lease on its temporary branch. Never rewrite fork `main`. Mark the PR ready only after local gates pass, then use a merge commit after all required GitHub checks pass.
6. Verify the providers post-merge publication and versioned image before reconciling Obot with the same rules.
7. Merge Obot only after its local and GitHub gates pass. Verify post-merge publication, the `latest` digest, the stable version tag, and their source commits.
8. Repair publication failures forward. The fail-closed workflows leave the previous published tags intact while repairs are reviewed.

## Default decision rules

- Upstream is canonical when it provides equivalent behavior.
- Preserve the final fork behavior, not its historical commit sequence.
- Use the highest stable upstream tag as the release version and record the exact upstream commit separately.
- Reuse the current sync PR and temporary branch when they exist.
- Use merge commits; do not squash, rebase-merge, or force-push `main`.
- Preserve and flag undocumented unique behavior rather than silently dropping it.
- Proceed through ready-for-review, merge, and publication verification without another approval after all gates pass.
- Ask for human input only when two incompatible product behaviors remain after applying these rules.
