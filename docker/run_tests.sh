#!/bin/bash
set -e

if [ x${1} != "x" ]; then
    Dockerfile=${1}
else
    echo "Must Select a Dockerfile"
    exit 1
fi

if [ ! -f ${Dockerfile} ]; then
    echo "${Dockerfile} not found"
    exit 1
fi

input_base_name=$(basename ${Dockerfile})
prefix=$(echo ${input_base_name}| awk '{split($0,a,"."); print a[1]}')
tag=$(echo ${input_base_name}| awk '{split($0,a,"."); print a[2]}')

if [ x${prefix} != "xDockerfile" ]; then
    echo "Must Select a valid Dockerfile"
    exit 1
fi

if [ x${tag} == "x" ]; then
    echo "Dockerfile has no tag"
    exit 1
fi

IMAGE_NAME=mpc-lib-tester-$tag

docker build -f ${Dockerfile} . -t $IMAGE_NAME

docker run \
    --rm \
    --network=host \
    -it \
    -v "$PWD:/usr/src/mpc-lib" \
    --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
    ${IMAGE_NAME} bash -c "make && make run-tests"

echo "Done"