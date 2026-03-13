#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./build-local-macos.sh [--basebin|--full] [--force] [--persist-env]

Options:
  --basebin   Build BaseBin only (default, same as non-tag CI build)
  --full      Build full project and generate Application/Dopamine.ipa
  --force     Force reinstall/rebuild of cached dependencies
  --persist-env  Persist THEOS/PATH to ~/.zshrc
EOF
}

MODE="basebin"
FORCE="0"
PERSIST_ENV="0"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --basebin)
      MODE="basebin"
      ;;
    --full)
      MODE="full"
      ;;
    --force)
      FORCE="1"
      ;;
    --persist-env)
      PERSIST_ENV="1"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
  shift
done

persist_theos_env() {
  local rc_file="${HOME}/.zshrc"
  local marker_begin="# >>> dopamine-theos >>>"

  mkdir -p "$(dirname "${rc_file}")"
  touch "${rc_file}"

  if grep -Fq "${marker_begin}" "${rc_file}"; then
    echo "THEOS env already persisted in ${rc_file}, skipping"
    return
  fi

  {
    echo ""
    echo "${marker_begin}"
    echo "export THEOS=\"${THEOS}\""
    echo "export PATH=\"\$THEOS/bin:/opt/procursus/bin:/opt/procursus/sbin:\$PATH\""
    echo "# <<< dopamine-theos <<<"
  } >> "${rc_file}"

  echo "Persisted THEOS env to ${rc_file}"
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This script must run on macOS."
  exit 1
fi

for cmd in git curl xcodebuild brew; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd"
    exit 1
  fi
done
if ! xcode-select -p >/dev/null 2>&1; then
  echo "Xcode is not configured. Run: sudo xcode-select --switch /Applications/Xcode.app"
  exit 1
fi

BASEDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASEDIR"

CPU_COUNT="$(sysctl -n hw.logicalcpu)"
HOST_ARCH="$(uname -m)"

echo "[1/8] Sync submodules"
git submodule update --init --recursive

echo "[2/8] Install Homebrew dependencies"
BREW_PACKAGES=(make gnu-sed findutils coreutils libarchive openssl ldid xz)
for pkg in "${BREW_PACKAGES[@]}"; do
  if ! brew list "$pkg" >/dev/null 2>&1; then
    brew install "$pkg"
  fi
done

export PATH="$(brew --prefix make)/libexec/gnubin:$(brew --prefix findutils)/libexec/gnubin:$(brew --prefix coreutils)/libexec/gnubin:$PATH"

echo "[3/8] Install THEOS + iPhoneOS16.5 SDK"
DEFAULT_THEOS_HOME="/Users/ssdsl/theos"
if [[ -n "${THEOS:-}" ]]; then
  export THEOS="${THEOS}"
else
  export THEOS="${THEOS_HOME:-${DEFAULT_THEOS_HOME}}"
fi
SDK_DIR="${THEOS}/sdks/iPhoneOS16.5.sdk"

if [[ "$PERSIST_ENV" == "1" ]]; then
  persist_theos_env
fi

if [[ "$FORCE" == "1" || ! -f "${THEOS}/makefiles/common.mk" ]]; then
  if [[ -d "$THEOS" && ! -x "${THEOS}/bin/update-theos" ]]; then
    echo "Found partial THEOS install at ${THEOS} (missing bin/update-theos), removing it"
    rm -rf "$THEOS"
  fi
  THEOS_INSTALL_SH="${BASEDIR}/install-theos.sh"
  curl -fsSL https://raw.githubusercontent.com/theos/theos/master/bin/install-theos -o "$THEOS_INSTALL_SH"
  gsed -E "/^[[:space:]]*get_theos[[:space:]]*$/,+1 s/^([[:space:]]*)(get_sdks)[[:space:]]*$/\1mkdir -p \\\${THEOS}\\/sdks\\n\1touch \\\${THEOS}\\/sdks\\/sdk\\n\1\2/g" -i "$THEOS_INSTALL_SH"
  bash "$THEOS_INSTALL_SH"
else
  echo "THEOS already installed at ${THEOS}, skipping install"
fi

mkdir -p "$THEOS/sdks"
if [[ "$FORCE" == "1" || ! -d "$SDK_DIR" ]]; then
  curl -L https://github.com/theos/sdks/releases/latest/download/iPhoneOS16.5.sdk.tar.xz --output "$THEOS/sdks/iPhoneOS16.5.sdk.tar.xz"
  xz -d -f "$THEOS/sdks/iPhoneOS16.5.sdk.tar.xz"
  tar -xf "$THEOS/sdks/iPhoneOS16.5.sdk.tar" -C "$THEOS/sdks"
  rm -f "$THEOS/sdks/iPhoneOS16.5.sdk.tar"
else
  echo "SDK already exists at ${SDK_DIR}, skipping download"
fi

echo "[4/8] Build trustcache"
TOOLS_DIR="${BASEDIR}/.build-tools"
TRUSTCACHE_DIR="${TOOLS_DIR}/trustcache"
mkdir -p "$TOOLS_DIR"
if [[ "$FORCE" == "1" || ! -x /opt/procursus/bin/trustcache ]]; then
  if [[ ! -d "$TRUSTCACHE_DIR/.git" ]]; then
    git clone https://github.com/CRKatri/trustcache "$TRUSTCACHE_DIR"
  fi
  (
    cd "$TRUSTCACHE_DIR"
    export CFLAGS="${CFLAGS:-} -I$(brew --prefix openssl)/include -arch ${HOST_ARCH}"
    export LDFLAGS="${LDFLAGS:-} -L$(brew --prefix openssl)/lib -arch ${HOST_ARCH}"
    gmake -j"${CPU_COUNT}" OPENSSL=1
  )
  sudo mkdir -p /opt/procursus/bin
  sudo cp "${TRUSTCACHE_DIR}/trustcache" /opt/procursus/bin/
else
  echo "trustcache already installed at /opt/procursus/bin/trustcache, skipping rebuild"
fi
export PATH="/opt/procursus/bin:/opt/procursus/sbin:$PATH"

echo "[5/8] Set CI-compatible environment variables"
T2="$(TZ=UTC-2 /bin/date +'%Y%m%d_%H%M%S')"
TS="$(/bin/date -j -f "%Y%m%d_%H%M%S" "${T2}" +%s)"
SHASH="$(git rev-parse --short HEAD)"
export ctime="${T2}"
export ctimestamp="${TS}"
export shorthash="${SHASH}"

echo "[6/8] Ensure libarchive (CI parity)"
if brew list libarchive >/dev/null 2>&1; then
  echo "libarchive already installed, skipping"
else
  brew install libarchive
fi

echo "[7/8] Handle bootstraps"
if [[ "$MODE" == "full" ]]; then
  BOOTSTRAP_DIR="${BASEDIR}/Application/Dopamine/Resources"
  (
    cd "$BOOTSTRAP_DIR"
    bash ./download_bootstraps.sh
  )
else
  echo "BaseBin build selected, skipping bootstrap download"
fi

echo "[8/8] Build (${MODE})"
if [[ "$MODE" == "full" ]]; then
  gmake -j"${CPU_COUNT}" NIGHTLY=1
  echo "Build complete: ${BASEDIR}/Application/Dopamine.ipa"
else
  gmake -C BaseBin -j"${CPU_COUNT}" NIGHTLY=1
  echo "Build complete: ${BASEDIR}/BaseBin/basebin.tar"
fi
