#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex -o pipefail

SRC_DIR="${SRC_DIR:-/aws_lc_rs}"

pushd "${SRC_DIR}"

cargo test -p aws-lc-rs
cargo clean

popd # ${SRC_DIR}
