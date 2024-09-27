#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -e

function usage {
  echo "Usage: $(basename "${0}"): -c CRATE_PATH"
  echo
  echo "-c CRATE_PATH The relative crate path from the repository root"
}

REPO_ROOT=$(git rev-parse --show-toplevel)
RELATIVE_CRATE_PATH=""

while getopts c:f option; do
  case $option in
  c)
    RELATIVE_CRATE_PATH="${OPTARG}"
    ;;
  ?)
    usage
    exit 1
    ;;
  esac
done

if [[ -z "${RELATIVE_CRATE_PATH}" ]]; then
  echo "Relative crate path must not be empty"
  exit 1
fi

CRATE_DIR="${REPO_ROOT}/${RELATIVE_CRATE_PATH}"

TEMP_TARGET_DIR=$(mktemp -d)

pushd "${CRATE_DIR}" &>/dev/null

if [[ -z "${GOPROXY:+x}" ]]; then
  export GOPROXY=direct
fi

cargo clean --target-dir "${TEMP_TARGET_DIR}"
# Sets AWS_LC_SYS_PREGENERATING_BINDINGS=1 which will cause the generation bindings for a specific platform. This feature
# is only intended for internal use thus is not a cargo feature. Requires bindgen to be enabled. The internal_bindgen
# config is enabled so that the final crates doesn't expect to find the dynamically generated bindings.rs
env AWS_LC_SYS_PREGENERATING_BINDINGS=1 AWS_LC_FIPS_SYS_PREGENERATING_BINDINGS=1 cargo build --target-dir "${TEMP_TARGET_DIR}" --features bindgen
cargo clean --target-dir "${TEMP_TARGET_DIR}"

popd &>/dev/null # ${CRATE_DIR}

rm -rf "${TEMP_TARGET_DIR}" &>/dev/null || true
