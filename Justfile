ensure-no-std:
  cargo test -p ntag424 2>&1 | tail -12 && cargo build -p ntag424 --no-default-features --target thumbv7em-none-eabihf

changelog tag="":
  #!/usr/bin/env bash
  set -euo pipefail
  if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required" >&2
    exit 1
  fi
  raw_tag="{{tag}}"
  if [ -n "$raw_tag" ]; then
    tag="${raw_tag#v}"
  else
    tag="$(cargo metadata --format-version 1 --no-deps | jq -r '.packages[] | select(.name == "ntag424") | .version')"
    if [ -z "$tag" ]; then
      echo "error: could not determine current crate version" >&2
      exit 1
    fi
  fi
  uvx git-cliff --tag "v${tag}" --output CHANGELOG.md

doc:
  RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --all-features --workspace --no-deps

license:
  uvx reuse annotate -c 'Jannik Schürg' -l Apache-2.0 -l MIT --merge-copyrights ntag424/**/*.rs

lint:
  cargo fmt --all --check
  cargo clippy --workspace --locked --all-targets --all-features -- -D warnings

release value:
  #!/usr/bin/env bash
  set -euo pipefail

  manifest="ntag424/Cargo.toml"
  changelog="CHANGELOG.md"
  requested="{{value}}"

  if ! cargo --list | grep -q '^    set-version$'; then
    echo "error: cargo set-version is required (install cargo-edit)" >&2
    exit 1
  fi
  if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required" >&2
    exit 1
  fi

  if [ "$(jj log -r @ --no-graph -T 'if(empty, "true", "false")')" != "true" ]; then
    echo "error: current jj change (@) is not empty" >&2
    exit 1
  fi

  branch="$(jj log -r @- --no-graph -T 'bookmarks.map(|b| b.name()).join(",")')"
  if [[ "$branch" == *","* ]]; then
    echo "error: @- has multiple bookmarks ($branch), expected at most one" >&2
    exit 1
  fi

  current_version="$(cargo metadata --format-version 1 --no-deps | jq -r '.packages[] | select(.name == "ntag424") | .version')"
  if [ -z "$current_version" ]; then
    echo "error: could not determine current crate version" >&2
    exit 1
  fi

  if [[ "$requested" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
    next_version="${requested#v}"
  else
    base_version="${current_version%%[-+]*}"
    IFS=. read -r major minor patch <<<"$base_version"
    if [[ -z "${major:-}" || -z "${minor:-}" || -z "${patch:-}" ]]; then
      echo "error: bump keywords require a current version matching X.Y.Z or X.Y.Z-suffix" >&2
      exit 1
    fi
    case "$requested" in
      major)
        next_version="$((major + 1)).0.0"
        ;;
      minor)
        next_version="${major}.$((minor + 1)).0"
        ;;
      patch)
        next_version="${major}.${minor}.$((patch + 1))"
        ;;
      *)
        echo "error: release expects major, minor, patch, or an explicit version" >&2
        exit 1
        ;;
    esac
  fi
  tag="v${next_version}"

  if git rev-parse -q --verify "refs/tags/$tag" >/dev/null 2>&1; then
    echo "error: tag $tag already exists" >&2
    exit 1
  fi

  restore_release_files() {
    jj restore "$manifest" "$changelog"
  }

  extract_release_notes() {
    awk -v heading="## [$tag]" '
      index($0, heading) == 1 { printing = 1 }
      printing {
        if ($0 ~ /^## / && index($0, heading) != 1) {
          exit
        }
        print
      }
    ' "$changelog"
  }

  restore_on_exit=1
  trap 'if [ "${restore_on_exit:-0}" = 1 ]; then restore_release_files; fi' EXIT

  cargo set-version --manifest-path "$manifest" "$next_version"
  if [ "$(cargo metadata --format-version 1 --no-deps | jq -r '.packages[] | select(.name == "ntag424") | .version')" != "$next_version" ]; then
    echo "error: failed to update crate version" >&2
    exit 1
  fi

  uvx git-cliff --tag "$tag" --output "$changelog"
  mtime_before_edit="$(python3 -c 'import os, sys; print(os.stat(sys.argv[1]).st_mtime_ns)' "$changelog")"
  editor_cmd="${VISUAL:-${EDITOR:-vi}}"
  echo "Opening $changelog in $editor_cmd"
  sh -c "$editor_cmd \"\$1\"" sh "$changelog"
  mtime_after_edit="$(python3 -c 'import os, sys; print(os.stat(sys.argv[1]).st_mtime_ns)' "$changelog")"
  if [ "$mtime_before_edit" = "$mtime_after_edit" ]; then
    echo "Aborted: $changelog was closed without saving."
    exit 1
  fi
  release_notes="$(extract_release_notes)"
  package_files="$(cargo package -p ntag424 --list --allow-dirty)"

  if [ -z "${release_notes//[$'\t\r\n ']}" ]; then
    echo "error: release notes for $tag are empty after editing $changelog" >&2
    restore_release_files
    exit 1
  fi
  if [ -z "${package_files//[$'\t\r\n ']}" ]; then
    echo "error: cargo package did not report any packaged files" >&2
    restore_release_files
    exit 1
  fi

  echo "Will release $tag from ${branch:-detached change}"
  echo
  echo "Release notes:"
  echo "$release_notes"
  echo
  echo "Crate contents:"
  echo "$package_files"
  echo
  read -rp "Proceed with commit, tag, push, and publish for these release notes and crate contents? [y/N] " confirm
  if [[ "$confirm" != [yY] ]]; then
    echo "Aborted."
    exit 1
  fi

  release_message="$(printf 'release: %s\n\n%s\n' "$tag" "$release_notes")"
  jj commit -m "$release_message"
  if [ -n "$branch" ]; then
    jj bookmark set "$branch" -r @-
  fi
  jj git export
  restore_on_exit=0

  tag_target="$(jj log -r @- --no-graph -T 'commit_id')"
  printf '%s' "$release_notes" | git tag -a "$tag" "$tag_target" --cleanup=verbatim -F -

  if [ -n "$branch" ]; then
    jj git push --bookmark "$branch"
  fi
  git push origin "$tag"

  echo "Released $tag"
