# Quinn fork of iroh

Quinn is a pure-rust, async-compatible implementation of the IETF
[QUIC][quic] transport protocol.

This is a fork incorporating some changes for use in iroh.  The aim is
to contribute back any generally useful changes into upstream Quinn,
so it is strongly discouraged to use this fork directly.


## Git branches

The upstream branches are kept unmodified and get occasionally synced.
The iroh-specific branches are:

- `iroh-0.10.x` is the branch for quinn@0.10 series.
- `iroh-0.11.x` is the branch for quinn@0.11 series.

The default branch should be set the currently actively used branch by
iroh.

### Updating a branch

To update a branch to include the upstream changes, merge the upstream
branch.  E.g. when upstream is `main` and the current iroh branch is
`iroh-0.11.x`:

- Check which commits are new in main.

  Using *magit*: `magit-cherry` (Y), from `main` to `iroh-0.11.x`

- Find the commit to merge.

  You probably want to find the last released commit on the `main`
  branch, which might not be the last commit on main.  So you need to
  find the commit hash as you can't use "main" in this case.

- Merge this commit: `git merge abc123`

- You can check the log and cherries again to see if the right commits
  are left in main.

### Upstream versions

We only try to merge tagged upstream versions.  To check the current
matching upstream version run:

`git tag --merged`

This will show all the tags which are in the ancestors of HEAD.  Look
for the highest `quinn`, `quinn-proto` and `quinn-udp` tags which are
found in all the ancestor commits.
