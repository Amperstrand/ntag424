# Release process

Releases are driven from the local `just release` task and published by Woodpecker.

## Maintainer flow

1. Review the working copy and make sure the current `jj` change is empty.
2. Run `just release patch`, `just release minor`, `just release major`, or `just release 0.1.0`.
3. The task regenerates `CHANGELOG.md`, opens it in `$VISUAL` or `$EDITOR`, and aborts if you close it without saving. After saving, it shows the selected release section and the `cargo package --list` file list for confirmation.
4. The task updates `CHANGELOG.md`, writes the same notes into the `jj` commit message and annotated Git tag, then pushes the bookmark and tag.
5. The tag-triggered `release` workflow waits for the `test` workflow, verifies the tag matches `ntag424/Cargo.toml`, publishes to crates.io, and creates the Codeberg release from the annotated tag body via `fj release create`.

## Required tools

- `cargo set-version` from `cargo-edit`
- `jq`
- `uvx`
- `jj`
- `git`

## Woodpecker secrets

- `codeberg_token`
- `crates_io_token`
