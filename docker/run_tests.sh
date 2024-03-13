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
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
CURRENT_DIR=`pwd`

cd ${SCRIPT_DIR}/..

docker build -f ${CURRENT_DIR}/${Dockerfile} . -t $IMAGE_NAME

docker run \
    --rm \
    ${IMAGE_NAME} bash -c "mkdir build_${IMAGE_NAME};cd build_${IMAGE_NAME};cmake ..;make -j && make -j test"

cd -

echo "Done"