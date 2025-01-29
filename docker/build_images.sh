#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex

REPO_ROOT=$(git rev-parse --show-toplevel)

#############################################
# Build images from aws-lc-rs GitHub repo #
#############################################

# Linux hosts might not have "jq" installed.

# Ubuntu:
# sudo apt-get install jq

# Amazon Linux:
# sudo yum install jq

# Log Docker hub limit https://docs.docker.com/docker-hub/download-rate-limit/#how-can-i-check-my-current-rate
TOKEN=$(curl "https://auth.docker.io/token?service=registry.docker.io&scope=repository:ratelimitpreview/test:pull" | jq -r .token)
curl --head -H "Authorization: Bearer $TOKEN" https://registry-1.docker.io/v2/ratelimitpreview/test/manifests/latest

EXTRA_ARGS=()
if [[ -n "${GOPROXY:+x}" ]]; then
    EXTRA_ARGS=("--build-arg" "GOPROXY=${GOPROXY}" "${EXTRA_ARGS[@]}")
fi

pushd "${REPO_ROOT}/docker" &>/dev/null
docker build -t rust:linux-386 linux-386 --load "${EXTRA_ARGS[@]}"
docker build -t rust:linux-arm64 linux-arm64 --load "${EXTRA_ARGS[@]}"
docker build -t rust:linux-x86_64 linux-x86_64 --load "${EXTRA_ARGS[@]}"
docker build -t ubuntu:18.04 ubuntu-18.04 --load "${EXTRA_ARGS[@]}"
docker build -t alpine:3.20 alpine-3.20 --build-arg UID=$(id -u) --load "${EXTRA_ARGS[@]}"
popd &>/dev/null
