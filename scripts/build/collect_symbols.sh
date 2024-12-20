#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex
set -o pipefail

function find_rust_platform() {
  rustc -Vv | grep -E "^host" | perl -p -e 's/^host:\s*(\S*)/\1/'
}

function usage() {
  echo Usage:
  echo     "${0} -c <CRATE_NAME> [-t <PLATFORM>]"
  echo
}

CRATE_NAME=""
PLATFORM="$(find_rust_platform)"

while getopts "t:c:" option; do
  case ${option} in
  t)
    PLATFORM="${OPTARG}"
    ;;
  c)
    CRATE_NAME="${OPTARG}"
    ;;
  *)
    echo Invalid argument: -"${?}"
    usage
    exit 1
    ;;
  esac
done

if [[ -z "${PLATFORM}" ]]; then
  echo "MUST SPECIFY PLATFORM"
  usage
  exit 1
fi

if [[ -z "${CRATE_NAME}" ]]; then
  echo "MUST SPECIFY CRATE_NAME"
  usage
  exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
AWS_LC_DIR="${REPO_ROOT}/${CRATE_NAME}/aws-lc"
SYMBOLS_FILE="${REPO_ROOT}/${CRATE_NAME}/symbols/${PLATFORM}.txt"

if [[ ! -d "${AWS_LC_DIR}" ]]; then
  echo "INVALID DIRECTORY: ${AWS_LC_DIR}"
  usage
  exit 1
fi

function filter_symbols() {
  grep -E '^\w*$' | grep -v -E "^bignum_" | grep -v "curve25519_x25519" | grep -v "edwards25519_" | grep -v "p256_montj" | grep -v "p384_montj" | grep -v "p521_montj" | grep -v "p521_j"
}

function filter_nm_symbols() {
  grep -v -E '^_Z' | grep -v -E '^\?' | grep -v 'BORINGSSL_bcm_' | grep -v 'BORINGSSL_integrity_test'
}

function filter_windows_symbols() {
   grep -v -E '^_*v?f?s?n?printf' | grep -v -E '^_*v?s?f?scanf' | grep -v RtlSecureZeroMemory | grep -v gai_strerrorA
}

function remove_leading_underscore() {
  grep -E '^_' | sed -e 's/^_\(.*\)/\1/'
}

function find_libcrypto() {
  find "${REPO_ROOT}/target" -type f \( -name "*crypto.lib" -o -name "lib*crypto.a" -o -name "lib*crypto.so" -o -name "lib*crypto.dylib" \) | grep "${CRATE_NAME}"
}

LIBCRYPTO_PATH="$(find_libcrypto)"
if [[ "${?}" -ne 0 ]]; then
  echo "Unable to find libcrypto"
  exit 1
fi

mkdir -p "$(dirname "${SYMBOLS_FILE}")"
echo Writing symbols to: ${SYMBOLS_FILE}

if [[ "${PLATFORM}" = *-msvc ]]; then
  if [[ "${PLATFORM}" = aarch64-* ]]; then
    MSVC_ARCH=arm64
  elif [[ "${PLATFORM}" = i686-* ]]; then
    MSVC_ARCH=x86
  else
    MSVC_ARCH=x64
  fi
  PFx86=$(printenv "ProgramFiles(x86)")
  VS_INSTALL_PATH="$("$(echo "${PFx86//\\/\/}//Microsoft Visual Studio/Installer/vswhere.exe")" | grep 'resolvedInstallationPath:' | sed -e 's/[^:]*: \(.*\)$/\1/')"

  DUMPBIN="$(ls -1 "${VS_INSTALL_PATH//\\/\/}"/VC/Tools/MSVC/*/bin/Hostx64/${MSVC_ARCH}/dumpbin.exe | tail -n 1)"
  PATH="$(dirname "${DUMPBIN/C:/\/c}")":"${PATH}"
  if [[ "${MSVC_ARCH}" = x64 ]]; then
    dumpbin //EXPORTS //SYMBOLS  "${LIBCRYPTO_PATH}" | grep External | grep -v UNDEF | sed -e 's/.*External\s*|\s*\(.*\)$/\1/' | filter_windows_symbols | grep -E '^\w*$' | sort | uniq >"${SYMBOLS_FILE}"
  elif [[ "${MSVC_ARCH}" = x86 ]]; then
    dumpbin //EXPORTS //SYMBOLS  "${LIBCRYPTO_PATH}" | grep External | grep -v UNDEF | sed -e 's/.*External\s*|\s*\(.*\)$/\1/' | remove_leading_underscore | filter_windows_symbols | grep -E '^\w*$' | sort | uniq >"${SYMBOLS_FILE}"
  else
    dumpbin //EXPORTS //SYMBOLS  "${LIBCRYPTO_PATH}" | grep External | grep -v UNDEF | sed -e 's/.*External\s*|\s*\(.*\)$/\1/' | filter_windows_symbols | sort | uniq | filter_symbols>"${SYMBOLS_FILE}"
  fi
  echo "dumpbin pipes: ${PIPESTATUS[@]}"
elif [[ "${LIBCRYPTO_PATH}" = *.dylib ]]; then
  nm --extern-only --defined-only -j  "${LIBCRYPTO_PATH}" | grep -v "${REPO_ROOT}" | sort | uniq | remove_leading_underscore | filter_nm_symbols |  filter_symbols >"${SYMBOLS_FILE}"
elif [[ "${LIBCRYPTO_PATH}" = *.so || "${LIBCRYPTO_PATH}" = *.lib ]]; then
  nm --extern-only --defined-only --format=just-symbols  "${LIBCRYPTO_PATH}" | sort | uniq | filter_nm_symbols | filter_symbols >"${SYMBOLS_FILE}"
else
  pushd "${AWS_LC_DIR}"
  go run -mod readonly "${AWS_LC_DIR}"/util/read_symbols.go "${LIBCRYPTO_PATH}" | sort | uniq | filter_nm_symbols | filter_symbols >"${SYMBOLS_FILE}"
  popd
fi

echo SUCCESS
