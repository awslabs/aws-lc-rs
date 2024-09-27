#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -e

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

source "${SCRIPT_DIR}/_generation_tools.sh"

function usage {
  echo "Usage: $(basename "${0}"): -c CRATE_PATH [-f]"
  echo "Performs an API diff of the crate to the published version"
  echo
  echo "-c CRATE_PATH The relative crate path from the repository root"
}

REPO_ROOT=$(git rev-parse --show-toplevel)
RELATIVE_CRATE_PATH=""

while getopts c:fm option; do
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
  echo "Relative crate path must be provided"
  exit 1
fi

CRATE_DIR="${REPO_ROOT}/${RELATIVE_CRATE_PATH}"

pushd "${CRATE_DIR}" &>/dev/null

CRATE_NAME=$("${REPO_ROOT}"/scripts/tools/cargo-dig.rs -n)
CRATE_VERSION=$("${REPO_ROOT}"/scripts/tools/cargo-dig.rs -v)

PUBLISHED_CRATE_VERSION=$(cargo search "${CRATE_NAME}" | egrep "^${CRATE_NAME} " | sed -e 's/.*"\(.*\)".*/\1/')

if ! parse_version "${PUBLISHED_CRATE_VERSION}"; then
  echo Could not find current version of published crate.
  exit 1
fi

TEMP_TARGET_DIR=$(mktemp -d)

if [[ -z "${GOPROXY:+x}" ]]; then
  export GOPROXY=direct
fi

env AWS_LC_SYS_PREGENERATING_BINDINGS=1 AWS_LC_FIPS_SYS_PREGENERATING_BINDINGS=1 cargo build --target-dir "${TEMP_TARGET_DIR}" --features bindgen
if ! cargo +stable public-api --target-dir "${TEMP_TARGET_DIR}" diff --deny changed --deny removed "${PUBLISHED_CRATE_VERSION}"; then
  echo
  echo "Version changing from: ${PUBLISHED_CRATE_VERSION} to ${CRATE_VERSION}"
  if ! prompt_yes_no "API changes found.  Continue with crate generation?"; then
    rm -rf "${TEMP_TARGET_DIR}"
    popd &>/dev/null # ${CRATE_DIR}
    exit 1
  fi
fi

rm -rf "${TEMP_TARGET_DIR}"

popd &>/dev/null # ${CRATE_DIR}
