#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -e

function usage {
  echo "Usage: $(basename "${0}"): -c CRATE_PATH [-f]"
  echo
  echo "-c CRATE_PATH The relative crate path from the repository root"
  echo "-f fips build"
}

function cmake_build_options() {
  if [[ "${GENERATE_FIPS}" -eq 0 ]]; then
    echo "-DDISABLE_GO=ON -DDISABLE_PERL=ON -DBUILD_LIBSSL=ON"
  else
    echo "-DFIPS=1 -DBUILD_LIBSSL=ON"
  fi
}

function filter_symbols() {
  grep -v "^_\?bignum_" | grep -v "_\?curve25519_x25519" | grep -v "_\?edwards25519_" | grep -v "_\?p256_montj" | grep -v "_\?p384_montj" | grep -v "_\?p521_montj" | grep -v "_\?p521_jdouble"
}

REPO_ROOT=$(git rev-parse --show-toplevel)
GENERATE_FIPS=0
RELATIVE_CRATE_PATH=""

while getopts c:f option; do
  case $option in
  c)
    RELATIVE_CRATE_PATH="${OPTARG}"
    ;;
  f)
    GENERATE_FIPS=1
    ;;
  ?)
    usage
    exit 1
    ;;
  esac
done

if [[ -z "${RELATIVE_CRATE_PATH}" ]]; then
  echo "Relative crate path must be provided"
  exit 1
fi

CRATE_DIR="${REPO_ROOT}/${RELATIVE_CRATE_PATH}"
AWS_LC_DIR="${CRATE_DIR}/aws-lc"
TARGET_PLATFORM_ARCH=$("${REPO_ROOT}"/scripts/tools/target-platform.rs)
TARGET_PLATFORM=$(echo "${TARGET_PLATFORM_ARCH}" | cut -d ' ' -f 1)
TARGET_ARCH=$(echo "${TARGET_PLATFORM_ARCH}" | cut -d ' ' -f 2)
SYMBOLS_DIR="${CRATE_DIR}/symbols"
SYMBOLS_FILE="${SYMBOLS_DIR}/${TARGET_PLATFORM}_${TARGET_ARCH}.txt"

TEMP_BUILD_DIR="$(mktemp -d)"

if [[ ! -d ${CRATE_DIR} || ! -d ${TEMP_BUILD_DIR} || -z "${TARGET_PLATFORM}" || -z "${TARGET_ARCH}" ]]; then
  echo "$(basename "$0")" Sanity Check Failed
  exit 1
fi

echo Building in: "${TEMP_BUILD_DIR}"
mkdir -p "${TEMP_BUILD_DIR}"
pushd "${TEMP_BUILD_DIR}" &>/dev/null

if [[ $(type -P "cmake3") ]]; then
  CMAKE=cmake3
else
  CMAKE=cmake
fi

go env -w GOPROXY=direct
${CMAKE} "${AWS_LC_DIR}" $(cmake_build_options)
${CMAKE} --build . --target clean
${CMAKE} --build . --target crypto ssl

pushd "${AWS_LC_DIR}" &>/dev/null
go run -mod readonly "${AWS_LC_DIR}"/util/read_symbols.go "${TEMP_BUILD_DIR}/crypto/libcrypto.a" | filter_symbols >"${SYMBOLS_FILE}"
popd &>/dev/null # ${AWS_LC_DIR}

popd &>/dev/null # ${TEMP_BUILD_DIR}

rm -rf "${TEMP_BUILD_DIR}"

echo DONE
