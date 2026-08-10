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
# Usage:
#   ./scripts/release.sh                  # tag v$(package.json version), wait, deploy
#   ./scripts/release.sh 1.0.17           # require package.json version == 1.0.17
#   ./scripts/release.sh --bump patch     # npm version patch, commit, then release
#   ./scripts/release.sh --dry-run
#   ./scripts/release.sh --no-deploy      # only GitHub release
#   ./scripts/release.sh --deploy-only    # skip tag/CI; deploy existing dist-release or download
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
    echo "dry-run: npm version $kind -m 'release: %s'"
    return
  fi
  npm version "$kind" -m "release: %s"
}

create_and_push_tag() {
  local ver="$1"
  local tag="v${ver}"
  if git rev-parse "$tag" >/dev/null 2>&1; then
    die "Tag $tag already exists"
  fi
  info "Creating tag $tag"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: git tag -a $tag -m 'DMARC Lighthouse $tag'"
    echo "dry-run: git push origin HEAD $tag"
    return
  fi
  git tag -a "$tag" -m "DMARC Lighthouse $tag"
  # Push branch (if bump commit) and tag — triggers .github/workflows/release.yml
  local branch
  branch="$(git rev-parse --abbrev-ref HEAD)"
  if [[ "$branch" != "HEAD" ]]; then
    git push -u origin "HEAD"
  fi
  git push origin "$tag"
}

wait_for_release_workflow() {
  local tag="$1"
  info "Waiting for GitHub Actions release workflow for $tag"
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
}

download_release_assets() {
  local tag="$1"
  info "Downloading release assets → $DIST_DIR"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: gh release download $tag --dir $DIST_DIR"
    return
  fi
  rm -rf "$DIST_DIR"
  mkdir -p "$DIST_DIR"
  gh release download "$tag" --dir "$DIST_DIR"
  ls -lah "$DIST_DIR"
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

if [[ "$DEPLOY_ONLY" -eq 1 ]]; then
  require_keys_sh
  VER="$(pkg_version)"
  [[ -z "$VERSION_ARG" ]] || VER="$VERSION_ARG"
  if [[ ! -f "$DIST_DIR/${VER}.json" ]]; then
    command -v gh >/dev/null || die "gh CLI required to download release"
    download_release_assets "v${VER}"
  fi
  ensure_signed_manifest "$VER"
  deploy_manifest "$VER"
  info "Done (deploy-only)."
  exit 0
fi

command -v gh >/dev/null || die "gh CLI is required (https://cli.github.com/)"
command -v git >/dev/null || die "git is required"

if [[ -n "$BUMP" ]]; then
  ensure_clean_git
  bump_version "$BUMP"
fi

VER="$(pkg_version)"
if [[ -n "$VERSION_ARG" && "$VERSION_ARG" != "$VER" ]]; then
  die "package.json version is $VER, but you passed $VERSION_ARG (bump first or pass --bump)"
fi

ensure_clean_git
[[ "$NO_DEPLOY" -eq 1 ]] || require_keys_sh

TAG="v${VER}"
info "Releasing $TAG (package.json $VER)"

if [[ "$DRY_RUN" -eq 1 ]]; then
  create_and_push_tag "$VER" >/dev/null || true
  wait_for_release_workflow "$TAG"
  download_release_assets "$TAG"
  ensure_signed_manifest "$VER"
  [[ "$NO_DEPLOY" -eq 1 ]] || deploy_manifest "$VER"
  info "Dry-run complete."
  exit 0
fi

create_and_push_tag "$VER"
wait_for_release_workflow "$TAG"
download_release_assets "$TAG"
ensure_signed_manifest "$VER"
if [[ "$NO_DEPLOY" -eq 1 ]]; then
  info "Skipping deploy (--no-deploy). Manifests in $DIST_DIR"
else
  deploy_manifest "$VER"
fi

info "Release $TAG complete."
echo "  GitHub:  https://github.com/codemacherUG/dmarc-lighthouse/releases/tag/${TAG}"
echo "  Manifest: https://codemacher.de/dmarc-lighthouse/updates/${VER}.json"
