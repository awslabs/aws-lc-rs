#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)

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

pushd "${SCRIPT_DIR}"
docker build -t alpine:3.20 . --build-arg UID=$(id -u) --load "${EXTRA_ARGS[@]}"
popd
