#!/bin/sh
# Builds for the runner, runs the smoke test, and only then builds every platform and pushes: publish.sh <version> <tag>...
# DOCKER_REGISTRY empty pushes to the GitLab registry only.
set -eu

version="$1"
shift
date=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
docker buildx build . --pull --no-cache --load --platform linux/amd64 \
  -t gatekeeper:ci \
  --build-arg IMAGE_TAG="$version" \
  --build-arg BUILD_DATE="$date"
sh scripts/smoke.sh gatekeeper:ci "$version"

tags=""
for tag in "$@"; do
  tags="$tags -t $CI_REGISTRY_IMAGE:$tag"
  if [ -n "${DOCKER_REGISTRY:-}" ]; then
    tags="$tags -t $DOCKER_REGISTRY:$tag"
  fi
done
# The amd64 layers come from the cache of the tested build.
docker buildx build . --push --pull --platform "$BUILD_PLATFORMS" $tags \
  --build-arg IMAGE_TAG="$version" \
  --build-arg BUILD_DATE="$date"
