#!/bin/bash
#
# Copyright 2018 Authors of Cilium
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# Execute command in the network namespace of the named k8s POD

set -e

CONTAINER_ID=$(docker ps -q --filter "name=k8s_POD_$1")
if [ "$(echo ${CONTAINER_ID} | wc -w)" -ne "1" ] ; then
    echo "Argument must be a name of a single running k8s POD:"
    docker ps --filter "name=k8s_POD_$1"
    exit 1
fi

PID=$(docker inspect -f '{{.State.Pid}}' ${CONTAINER_ID})
[ -z "${PID}" ] && exit 1

[ ! -d "/var/run/netns" ] && sudo mkdir -p /var/run/netns

function cleanup {
    sudo rm /var/run/netns/${CONTAINER_ID}
}

# Create and remove netns link only if needed
if [ ! -L /var/run/netns/${CONTAINER_ID} ] ; then
    sudo ln -sfT /proc/${PID}/ns/net /var/run/netns/${CONTAINER_ID}
    trap cleanup EXIT
fi

shift
[ "$1" = "--" ] && shift
sudo ip netns exec ${CONTAINER_ID} $@

