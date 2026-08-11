#!/usr/bin/env bash
# Create a GitHub Release (via tag → Actions) and deploy signed update manifests.
#
# Prerequisites:
#   - clean git working tree on the commit you want to ship
#   - package.json version already set (or pass VERSION / --bump)
#   - gh authenticated for this repo
#   - scripts/update-keys.sh present (from update-keys.sh.template)
#   - GitHub secret UPDATE_SIGNING_PRIVATE_KEY (CI signs) OR local keys/ + UPDATE_SIGNING_PRIVATE_KEY_FILE
#
# Single entry point — normally just:
#   npm run release
#
# That will: bump if needed → tag → wait for GitHub Actions → download signed
# manifests → deploy to codemacher.de (via scripts/update-keys.sh env).
#
# Options:
#   ./scripts/release.sh 1.0.18           # require package.json version == 1.0.18
#   ./scripts/release.sh --bump patch     # force version bump, then release
#   ./scripts/release.sh --dry-run
#   ./scripts/release.sh --no-deploy      # GitHub release only (no trust-host upload)
#   ./scripts/release.sh --deploy-only    # only fetch manifests + deploy (no new tag)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

KEYS_SH="$ROOT/scripts/update-keys.sh"
DIST_DIR="$ROOT/dist-release"
DRY_RUN=0
NO_DEPLOY=0
DEPLOY_ONLY=0
BUMP=""
VERSION_ARG=""

die() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

usage() {
  sed -n '2,/^set -euo pipefail$/p' "$0" | sed '$d' | sed 's/^# \?//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage 0 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --no-deploy) NO_DEPLOY=1; shift ;;
    --deploy-only) DEPLOY_ONLY=1; shift ;;
    --bump)
      BUMP="${2:-}"
      [[ -n "$BUMP" ]] || die "--bump needs patch|minor|major"
      shift 2
      ;;
    --dir)
      DIST_DIR="$(cd "${2:-}" && pwd)" || die "invalid --dir"
      shift 2
      ;;
    -*)
      die "unknown option: $1"
      ;;
    *)
      VERSION_ARG="$1"
      shift
      ;;
  esac
done

pkg_version() {
  node -p "require('./package.json').version"
}

require_keys_sh() {
  if [[ ! -f "$KEYS_SH" ]]; then
    die "Missing $KEYS_SH — copy scripts/update-keys.sh.template and fill in deploy settings."
  fi
  # shellcheck disable=SC1090
  source "$KEYS_SH"
}

ensure_clean_git() {
  if [[ -n "$(git status --porcelain)" ]]; then
    die "Working tree is not clean. Commit or stash first."
  fi
}

bump_version() {
  local kind="$1"
  info "Bumping version ($kind)"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: npm version $kind --no-git-tag-version && git commit"
    return
  fi
  # Do not let npm create the tag — release.sh owns annotated tags.
  npm version "$kind" --no-git-tag-version
  git add package.json package-lock.json
  git commit -m "release: $(pkg_version)"
}

# Peeled commit SHA for refs/tags/<tag> on origin, or empty if missing.
remote_tag_commit() {
  local tag="$1"
  local sha
  sha="$(git ls-remote origin "refs/tags/${tag}^{}" 2>/dev/null | awk '{print $1}' | head -n1)"
  if [[ -z "$sha" ]]; then
    sha="$(git ls-remote origin "refs/tags/${tag}" 2>/dev/null | awk '{print $1}' | head -n1)"
  fi
  printf '%s' "$sha"
}

# Sets REUSE_REMOTE_RELEASE=1 when tag is already on origin at HEAD (deploy only).
# Otherwise bumps patch when that version was already shipped from another commit.
ensure_releasable_version() {
  local ver tag remote_sha head
  ver="$(pkg_version)"
  tag="v${ver}"
  head="$(git rev-parse HEAD)"
  remote_sha="$(remote_tag_commit "$tag")"
  REUSE_REMOTE_RELEASE=0

  if [[ -z "$remote_sha" ]]; then
    return
  fi
  if [[ "$remote_sha" == "$head" ]]; then
    info "Tag $tag already on origin at HEAD — skip CI, only deploy manifests"
    REUSE_REMOTE_RELEASE=1
    return
  fi
  if [[ -n "$VERSION_ARG" ]]; then
    die "Tag $tag already on origin at ${remote_sha:0:8} (HEAD ${head:0:8}). Pass --bump or change package.json."
  fi
  if [[ -n "$BUMP" ]]; then
    return
  fi
  info "Tag $tag already on origin — auto --bump patch"
  bump_version patch
}

create_and_push_tag() {
  local ver="$1"
  local tag="v${ver}"
  local head local_sha remote_sha
  head="$(git rev-parse HEAD)"
  remote_sha="$(remote_tag_commit "$tag")"

  if git rev-parse "$tag" >/dev/null 2>&1; then
    local_sha="$(git rev-parse "${tag}^{}")"
    if [[ "$local_sha" == "$head" ]]; then
      info "Tag $tag already points at HEAD — reusing"
    elif [[ -n "$remote_sha" ]]; then
      die "Tag $tag exists locally and on origin, but not at HEAD. Use --bump."
    else
      info "Moving local tag $tag → HEAD (not on origin yet)"
      if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "dry-run: git tag -d $tag && git tag -a $tag …"
      else
        git tag -d "$tag" >/dev/null
        git tag -a "$tag" -m "DMARC Lighthouse $tag"
      fi
    fi
  else
    info "Creating tag $tag"
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "dry-run: git tag -a $tag -m 'DMARC Lighthouse $tag'"
    else
      git tag -a "$tag" -m "DMARC Lighthouse $tag"
    fi
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: git push origin HEAD $tag"
    return
  fi

  local branch
  branch="$(git rev-parse --abbrev-ref HEAD)"
  if [[ "$branch" != "HEAD" ]]; then
    git push -u origin "HEAD"
  fi

  remote_sha="$(remote_tag_commit "$tag")"
  if [[ -n "$remote_sha" ]]; then
    local_sha="$(git rev-parse "${tag}^{}")"
    if [[ "$remote_sha" == "$local_sha" ]]; then
      info "Tag $tag already on origin"
      return
    fi
    die "Tag $tag already on origin at different commit (${remote_sha:0:8}). Refusing to overwrite."
  fi
  git push origin "$tag"
}

# Sets RELEASE_RUN_ID for later artifact download.
wait_for_release_workflow() {
  local tag="$1"
  info "Waiting for GitHub Actions release workflow for $tag"
  RELEASE_RUN_ID=""
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: gh run watch …"
    return
  fi
  local sha
  sha="$(git rev-parse "${tag}^{}")"
  sleep 3
  local run_id=""
  for _ in $(seq 1 45); do
    run_id="$(
      gh run list --workflow=release.yml --limit=30 \
        --json databaseId,headSha,headBranch \
        --jq ".[] | select(.headSha == \"${sha}\" or .headBranch == \"${tag}\") | .databaseId" \
        | head -n1
    )"
    if [[ -n "$run_id" ]]; then
      break
    fi
    sleep 2
  done
  [[ -n "$run_id" ]] || die "Could not find release workflow run for $tag (sha $sha)"
  info "Watching run $run_id"
  gh run watch "$run_id" --exit-status
  RELEASE_RUN_ID="$run_id"
}

find_release_run_id() {
  local tag="$1"
  gh run list --workflow=release.yml --limit=40 \
    --json databaseId,headBranch,conclusion \
    --jq ".[] | select(.headBranch == \"${tag}\" and .conclusion == \"success\") | .databaseId" \
    | head -n1
}

# Manifests are workflow artifacts (not GitHub Release assets).
download_manifest_assets() {
  local tag="$1"
  local ver="${tag#v}"
  local run_id="${2:-${RELEASE_RUN_ID:-}}"
  info "Downloading signed manifests (workflow artifact) → $DIST_DIR"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: gh run download … -n update-manifests"
    return
  fi
  if [[ -z "$run_id" ]]; then
    run_id="$(find_release_run_id "$tag")"
  fi
  [[ -n "$run_id" ]] || die "No successful release workflow run found for $tag (need artifact update-manifests)"
  mkdir -p "$DIST_DIR"
  # Artifact may unpack into a subfolder — download into a temp dir and flatten.
  local tmp
  tmp="$(mktemp -d)"
  gh run download "$run_id" -n update-manifests -D "$tmp"
  local json sig
  json="$(find "$tmp" -type f -name "${ver}.json" | head -n1)"
  sig="$(find "$tmp" -type f -name "${ver}.json.sig" | head -n1)"
  [[ -n "$json" && -n "$sig" ]] || die "Artifact update-manifests from run $run_id missing ${ver}.json[.sig]"
  cp -f "$json" "$DIST_DIR/${ver}.json"
  cp -f "$sig" "$DIST_DIR/${ver}.json.sig"
  rm -rf "$tmp"
  ls -lah "$DIST_DIR/${ver}.json" "$DIST_DIR/${ver}.json.sig"
}

finish_deploy() {
  local ver="$1"
  local tag="v${ver}"
  if [[ ! -f "$DIST_DIR/${ver}.json" || ! -f "$DIST_DIR/${ver}.json.sig" ]]; then
    download_manifest_assets "$tag"
  fi
  ensure_signed_manifest "$ver"
  if [[ "$NO_DEPLOY" -eq 1 ]]; then
    info "Skipping deploy (--no-deploy). Manifests in $DIST_DIR"
    return
  fi
  deploy_manifest "$ver"
}

ensure_signed_manifest() {
  local ver="$1"
  local json="$DIST_DIR/${ver}.json"
  local sig="$DIST_DIR/${ver}.json.sig"
  if [[ -f "$json" && -f "$sig" ]]; then
    info "Signed manifest already present"
    return
  fi
  info "Signing manifest locally"
  local key_file="${UPDATE_SIGNING_PRIVATE_KEY_FILE:-$ROOT/keys/update-ed25519-private.pem}"
  if [[ -z "${UPDATE_SIGNING_PRIVATE_KEY:-}" && -f "$key_file" ]]; then
    export UPDATE_SIGNING_PRIVATE_KEY
    UPDATE_SIGNING_PRIVATE_KEY="$(cat "$key_file")"
  fi
  [[ -n "${UPDATE_SIGNING_PRIVATE_KEY:-}" ]] || die "No signed manifest in release and no UPDATE_SIGNING_PRIVATE_KEY / $key_file"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: npm run update:sign -- --dir $DIST_DIR --version $ver"
    return
  fi
  npm run update:sign -- --dir "$DIST_DIR" --version "$ver" --out "$DIST_DIR"
}

deploy_manifest() {
  local ver="$1"
  require_keys_sh
  info "Deploying manifest $ver to trust host"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: npm run update:deploy -- --dir $DIST_DIR --version $ver --verify"
    return
  fi
  npm run update:deploy -- --dir "$DIST_DIR" --version "$ver" --verify
}

# --- main ---

REUSE_REMOTE_RELEASE=0
RELEASE_RUN_ID=""

command -v gh >/dev/null || die "gh CLI is required (https://cli.github.com/)"
command -v git >/dev/null || die "git is required"

if [[ "$DEPLOY_ONLY" -eq 1 ]]; then
  [[ "$NO_DEPLOY" -eq 1 ]] && die "--deploy-only and --no-deploy cannot be combined"
  require_keys_sh
  VER="$(pkg_version)"
  [[ -z "$VERSION_ARG" ]] || VER="$VERSION_ARG"
  info "Deploy-only for v${VER}"
  finish_deploy "$VER"
  info "Done (deploy-only)."
  echo "  Manifest: https://codemacher.de/dmarc-lighthouse/updates/${VER}.json"
  exit 0
fi

ensure_clean_git
[[ "$NO_DEPLOY" -eq 1 ]] || require_keys_sh

if [[ -n "$BUMP" ]]; then
  bump_version "$BUMP"
else
  ensure_releasable_version
fi

VER="$(pkg_version)"
if [[ -n "$VERSION_ARG" && "$VERSION_ARG" != "$VER" ]]; then
  die "package.json version is $VER, but you passed $VERSION_ARG (bump first or pass --bump)"
fi

ensure_clean_git

TAG="v${VER}"
info "Releasing $TAG (package.json $VER)"

if [[ "$REUSE_REMOTE_RELEASE" -eq 1 ]]; then
  finish_deploy "$VER"
else
  create_and_push_tag "$VER"
  wait_for_release_workflow "$TAG"
  finish_deploy "$VER"
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  info "Dry-run complete."
  exit 0
fi

info "Release $TAG complete."
echo "  GitHub:  https://github.com/codemacherUG/dmarc-lighthouse/releases/tag/${TAG}"
echo "  Manifest: https://codemacher.de/dmarc-lighthouse/updates/${VER}.json"
